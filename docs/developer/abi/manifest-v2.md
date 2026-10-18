# Workspace 清单（Manifest v2）

Manifest 是 Workspace 内模块、翻译变体和工件的索引与完整性契约，位置为 `artifacts/modules.tsv`。文本为 UTF-8，记录列以制表符分隔。下面用 `<TAB>` 展示列边界，实际文件写入制表符。

## 头部

文件前六行按顺序为：

```text
# chimera-workspace-manifest-v2
# runtime_abi=1
# target_os=linux
# target_arch=riscv64
# target_arch_extension=rvv
# runtime_scene=linux_riscv64_rvv_v1
```

第一行是格式标识。其余字段声明 Runtime ABI 和完整目标组合；示例值对应当前 RVV 场景。Manifest 格式版本和 Runtime ABI 分别管理。

后续空行与注释行可以跳过，未知记录类型或错误列数会被拒绝。写入器对记录排序并写出规范形式，读取器校验字段和引用关系。

## 模块

```text
module<TAB>module_id<TAB>role<TAB>runtime_name<TAB>selected_kind<TAB>delivery<TAB>sha256
```

| 字段 | 约定 |
|---|---|
| `module_id` | 模块唯一标识 |
| `role` | `main` 或 `dependency`，全表恰好一个 `main` |
| `runtime_name` | 唯一的文件 basename，无目录分隔符 |
| `selected_kind` | `original` 或 `scalar`，表示离线选用了哪种构建 |
| `delivery` | `package` 或 `target`，表示文件的交付来源 |
| `sha256` | 选定模块文件的 64 位小写十六进制内容摘要 |

主程序必须使用 `delivery=target`。随包模块位于 `scalar/<runtime_name>`；目标机模块留在应用安装位置，由启动时的依赖解析定位。`runtime_name` 用于定位，文件内容摘要用于确认身份。

`selected_kind` 与 `delivery` 是独立字段。通用编解码器不从所选构建名称推导交付来源；当前模块选择与场景规则负责决定组合。运行期不按本机库是否存在重新选择另一种模块。

## 翻译变体与属性

```text
variant<TAB>variant_id<TAB>module_id
variant-property<TAB>variant_id<TAB>side<TAB>name<TAB>value_kind<TAB>value
```

`variant_id` 唯一，引用已登记模块。属性使用 `(variant_id, side, name)` 作为唯一键，`side` 为 `input` 或 `output`。

| `value_kind` | 值的规范形式 |
|---|---|
| `u64` | 范围内无符号 64 位十进制整数 |
| `i64` | 范围内有符号 64 位十进制整数 |
| `bool` | `true` 或 `false` |
| `token` | 符合标识符规则的字符串 |

RVV 场景从输入/输出属性读取架构、扩展与 `vector_vlen_bits`。变体名称只表示身份，消费者不能通过拆解名称推导 VLEN 或方向。

变体指纹由变体记录及其规范排序属性计算 SHA-256。翻译代码导出的指纹符号用于核对变体身份；它与工件文件摘要承担不同职责。

## 工件

```text
artifact<TAB>artifact_id<TAB>owner_kind<TAB>owner_id<TAB>capability<TAB>representation<TAB>abi<TAB>required_by<TAB>path<TAB>sha256
```

| 字段 | 约定 |
|---|---|
| `artifact_id` | 唯一工件标识 |
| `owner_kind` / `owner_id` | `workspace/root`、已登记 `module` 或已登记 `variant` |
| `capability` | 能力名称，例如 `runtime`、`translated-code`、`offset-map`、`safety` |
| `representation` | 表示形式，例如 `elf` 或 `json` |
| `abi` | 此能力的正整数 ABI 版本 |
| `required_by` | 按字典序排序、逗号分隔的消费者集合；空集合写 `-` |
| `path` | Workspace 内唯一的安全相对 POSIX 路径 |
| `sha256` | 工件文件的内容摘要 |

路径不能是绝对路径，不能包含反斜杠、NUL、`.` 或 `..` 路径分量。带 Workspace 根目录校验时，实际工件必须存在、留在根目录内且摘要匹配。工件路径不能覆盖随包模块输入。

`required_by` 表示消费要求，例如 Runtime 或 launcher 所需能力。结构检查、场景拓扑检查与能力装载分别负责不同层次；未知的 Runtime 必需能力会使校验失败。

## 当前发布关系

| 工件 | 所有者 | 表示 / ABI | 主要消费者 |
|---|---|---|---|
| `runtime` | Workspace | `elf` / 1 | Runtime |
| `translated-code` | 变体 | `elf` / 1 | Runtime |
| `offset-map` | 变体 | `elf` / 1 | Runtime |
| `safety` | 模块 | `elf` / 1 | Runtime |
| `external-scalar-leaf-contracts` | 模块 | `json` / 1 | launch |

最后一项按实际闭合的外部调用证明发布。当前安全分析主要针对主程序；不能从通用模块所有者格式推导全部依赖都执行了同样的安全分析。

当前步骤生成的安全 JSON、继承诊断和映射 JSON 主要服务准备、诊断与开发回放，不因文件存在就自动成为 Manifest 工件。正式交付以 registry 中明确登记的记录为准。

安装和运行还要验证随包模块、安装记录以及目标机解析文件；单独解析 Manifest 不能绑定一条任意应用路径。完整流程见 [Workspace 架构](../architecture/workspace.md)。

## 实现与验证

- [Python 类型与规则](../../../runtime/artifacts/manifest/chimera/manifest/model.py)
- [文本编解码器](../../../runtime/artifacts/manifest/chimera/manifest/codec.py)
- [C 结构定义](../../../runtime/interfaces/abi/module_manifest.h)与 [C 解析器](../../../runtime/artifacts/manifest/linux_riscv64_rvv_v1/manifest_v1.c)
- [Manifest 回归](../../../tests/test_manifest_v1.py)与 [C Manifest 回归](../../../runtime/tests/runtime/test_module_manifest_v1.c)

部分源码文件名保留早期版本编号，实际支持的文本版本以格式标识和校验逻辑为准。
