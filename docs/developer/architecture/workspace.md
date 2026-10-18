# Workspace、内容绑定与交付

Workspace 是离线工件集合，也是在线端选择 Runtime、模块和翻译变体的入口。当前格式是 **Manifest v2**：应用保留在目标机原位置，scalar 底座随包，分析结果用内容指纹绑定到选中的模块。

## 文件布局

```text
<workspace>/
  workspace.json
  scalar/
  artifacts/
    modules.tsv
    runtime/
  generated/
  dump/
  log/
```

`scalar/` 存放真正随包交付的模块文件。`artifacts/` 包括 Runtime、翻译 DSO、安全分析结果、地址映射及其 Manifest；具体文件名由生产者和 target 的生产规范决定。`generated/`、`dump/`、`log/` 用于离线生产、replay 和诊断，不是应用副本。

`workspace.json` 保存 Workspace 标识、内容身份及准备输入指纹等管理信息；在线工件清单以 `artifacts/modules.tsv` 为准。`.workspace` 是交付归档扩展名，不能与已展开的 Workspace 目录混用。

## 模块选择

`prepare_workspace/selection.py` 集中定义规则，供 prepare 与复用判断共同使用：对平台解析出的依赖，主程序始终选原文件；其他模块如果 scalar 根目录中存在同 basename 文件，则选 scalar，否则选原文件。这个规则不会仅凭库名称证明两个构建在语义上可互换，scalar 底座的选取是集成配置的一部分。

| 选择结果 | `selected_kind` | `delivery` | 分析与运行来源 |
| --- | --- | --- | --- |
| 主程序 | `original` | `target` | 原位置的应用 ELF |
| 有 scalar 替代的依赖 | `scalar` | `package` | prepare 复制到 `scalar/`，分析该交付副本 |
| 无 scalar 替代的依赖 | `original` | `target` | 目标机应用安装中的原文件 |

`selected_kind` 说明选了哪个构建，`delivery` 说明文件如何抵达运行环境，两者分别记录。主模块必须为 `delivery=target`。模块 ID 和 runtime basename 在一个 Manifest 中分别唯一，不能用同 basename 的多个库表达不同模块。

prepare 不改写输入 ELF、`PT_INTERP`、RPATH 或应用自己的文件。启动时显式执行包内 loader，保持应用文件的位置与内容；选中的 scalar loader/libc 组合也因此可以一起交付。loader 重定向等无法由当前调用方式控制的输入会在准备阶段被检查，不能依赖发布后再猜测。

## 四种内容标识各自证明什么

| 标识 | 内容与用途 |
| --- | --- |
| ELF identity digest | 覆盖离线端消费的加载字节、加载基址、指定 ELF 头字段、分析 metadata 和 `PT_INTERP` basename，用于 Workspace 内容身份 |
| prepare 输入指纹 | 组合主 ELF、全部选中模块的 identity、交付类别与 target/scene/runtime ABI，检测依赖或 scalar 选择变化 |
| module `sha256` | 选中模块的整文件 SHA-256，供 launcher 核对实际运行文件 |
| artifact `sha256` | 工件整文件 SHA-256，供登记、发布、打包及在线装载校验 |

identity digest 有意排除未被分析消费的部分布局或描述性数据，例如调试节和特定 note 区域；它不是整文件 SHA-256 的别名。因此即使只改变了 identity 不覆盖的数据，也不能推断修改后的文件满足 Manifest 的整文件 hash。

`core/workspace/anchor.py` 从同一个打开的文件描述符计算 identity 和整文件 SHA-256，并记录 `st_dev`、`st_ino`、`st_size`、`st_mtime_ns`。finalizer 在提交前重新比较这些 stat 字段，检测分析期间的替换或写入。`st_ctime_ns` 只用于诊断。scalar 交付副本还会与选中源文件的 identity 比较。

这项发布前复核不锁住从 prepare 到未来运行之间的文件。在线端仍必须重新验证应用和依赖；内容 hash 也不是来源认证或签名机制。

## Manifest v2 的层次

TSV 的首行是 `# chimera-workspace-manifest-v2`，随后固定记录 `runtime_abi`、`target_os`、`target_arch`、`target_arch_extension`、`runtime_scene`。版本号属于文件格式；runtime ABI 和各 capability ABI 分别版本化，当前值为 1 不代表 Manifest 是 v1。

| 记录 | 字段 |
| --- | --- |
| `module` | `module_id role runtime_name selected_kind delivery sha256` |
| `variant` | `variant_id module_id` |
| `variant-property` | `variant_id side name value_kind value` |
| `artifact` | `artifact_id owner_kind owner_id capability representation abi required_by path sha256` |

字段在文件中用制表符分隔。property 的 `side` 为 `input` 或 `output`，类型为 `u64`、`i64`、`bool`、`token`；RVV 端点属性见 [RVV 目标](targets/rvv/README.md)。

artifact 以 `workspace/root`、`module/<module_id>`、`variant/<variant_id>` 为所有者。`capability` 描述用途，`representation` 描述表示，`abi` 描述该工件的接口版本，`required_by` 是排序后的消费者集合，空集合序列化为 `-`。

工件路径必须是安全、规范的 Workspace 相对 POSIX 路径，不能逃出根目录，也不能占用随包模块输入路径。Manifest 通用校验检查所有者引用、唯一性、值类型、文件存在和工件 hash；target/scene 再检查每个模块需要的变体、工件数量和受支持 ABI。没有注册、或只是碰巧放在 `artifacts/` 的文件不会自动成为在线能力。

## 从 Workspace 到交付包

```mermaid
flowchart LR
    W[完整离线 Workspace] --> P[pack 筛选运行文件]
    R[显式 resources] --> P
    P --> A[.workspace 归档与文件索引]
    A --> V[校验成员路径 / 类型 / 摘要 / 兼容性]
    V --> S[安装 staging]
    S --> I[发布安装目录与完整性标记]
    I --> L[运行时再次验证工件和实际模块]
```

`chimera-pkg workspace pack` 由 `cli/chimera/workspack.py` 实现，选择 `workspace.json`、`scalar/`、`artifacts/` 及显式声明的 `resources/`；离线 `generated/`、`dump/`、`log/`、`build/`、`cache/`、`toolchain/` 不随交付包发送。应用和 `delivery=target` 的依赖保持目标机交付属性，不应放入 scalar payload。包内 `workspack.json` 提供归档格式、兼容性信息与文件索引；Workspack 的格式版本独立于 Manifest v2。

打包检查归档输出位置、受管目录、符号链接、成员路径、Manifest 引用与 Runtime 场景契约，并检查随包 ELF 的依赖布局。资源需显式声明；它们的应用用途应在[应用样例入口](../../README.md#应用样例)链接的相应应用文档中说明。完整的操作参数见[应用集成者 CLI](../../deployment/cli.md)。

安装先验证归档，再在 Workspace 根目录下创建 staging，写入文件、模式、更新 Workspace ID，最后写 `.workspack-install.json` 后发布。相同归档重复安装仅在已有目录完整性仍通过时复用；同名不同包被拒绝。安装后复核失败会移除本次目录。安装标记记录归档 SHA-256 和已安装文件摘要，支持后续完整性核对。

安装完成说明归档按规则展开；目标机还需具备应用、匹配的 `delivery=target` 模块及运行环境。launcher 的 loader 解析和实际内容验证见[在线运行时](runtime.md)。

主要实现：`analysis/prepare_workspace/`、`analysis/core/workspace/{identity,fingerprint,anchor,registry,session,repository}.py`、`runtime/artifacts/manifest/chimera/manifest/{model,codec}.py`、`cli/chimera/{workspace,workspack}.py`。
