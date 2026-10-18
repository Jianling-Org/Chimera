# 应用 Profile

Profile 是集成阶段显式提供的完整 TOML，包含工具与路径配置、目标身份和有序 workflow。`chimera-pkg check-elf/prepare` 都要求 `--profile`；使用者运行已交付 Workspace 无需 Profile。

## section 与默认值

根级只接受 `[config]` 与 `[profile]`，未知字段会报错。一般路径中的 `~` 会展开，相对路径相对于 Profile 文件所在目录；工具名不含路径分隔符时按命令搜索，有分隔符时按 Profile 路径解析。

| section / 字段 | 默认值与作用 |
| --- | --- |
| `config.data_root` | `build/data`，数据根目录 |
| `config.scalar_root` | `build/scalar`，选择标量底座模块的来源，需预先准备 |
| `config.workspace_name` | `auto`，自动命名；可使用有效 Workspace 名称 |
| `config.workspace_root` | 解析层默认 `build/workspaces`，但公开 CLI 已忽略该字段；通过 `--workspace-root` 或环境变量选输出根 |
| `config.translators` | 默认空数组，逐 route 声明翻译器 |
| `config.tools.python/cc/objdump/nm/cmake` | 默认空字符串；完整 workflow 应显式配置所需工具 |
| `config.tools.cc_flags` | 默认 `[]`，构建生成工件时追加的目标编译选项 |
| `config.target_files.sysroot` | 默认未指定，目标文件系统根 |
| `config.target_files.library_roots` | 默认 `[]`，目标依赖的显式搜索根 |
| `config.target_files.cmake_toolchain_file` | 默认未指定，目标 CMake 工具链文件 |
| `config.runtime.bpf_map` | `/sys/fs/bpf/pid_uprobe_map` |
| `config.runtime.ai_thread_control` | `/proc/set_ai_thread` |

`[profile]` 必须显式给出非空的 `name`、`target_os`、`target_arch`、`target_arch_extension`、`runtime_scene`，以及整数 `runtime_abi`。当前后者只接受 1；这是运行时 ABI 号，与 Manifest v2 的格式版本不同。完整准备还必须声明非空 workflow。

当前组合是 `linux / riscv64 / rvv / linux_riscv64_rvv_v1`。注册目录提供扩展机制，但不等于其他目标已可用。

## workflow 步骤

每条 `[[profile.workflow.steps]]` 只含 `step` 和可选 `parameters`；参数未知或类型不符时拒绝。没有声明的步骤不会自动插入。下表按常用完整顺序列出：

| step | 参数 | 操作影响 |
| --- | --- | --- |
| `prepare-workspace` | 无 | 选择模块，创建准备会话 |
| `build-runtime` | 无 | 构建运行时工件 |
| `disassemble` | 无 | 生成所选模块的反汇编 |
| `build-program-model` | 无 | 从反汇编建立程序模型 |
| `safety` | 见下表 | 生成安全工件，并为 check-elf 声明二进制检查 |
| `translate` | 必填 `source`、`target` 字符串 | 按 route 生成翻译产物，可重复，但同一 source 不能重复声明 |
| `offset-map` | 无 | 为翻译产物生成映射 |
| `patch-safepoints` | 无 | 生成打补丁的工件副本，不改写输入 ELF |
| `finalize-workspace` | 无 | 校验产物并发布 Workspace |

除 `translate` 外，当前步骤不可重复。顺序必须满足前一步产物依赖；例如 `safety` 需要模块和程序模型，`patch-safepoints` 需要安全结果、翻译和 offset map。

| safety 参数 | 默认值与约束 |
| --- | --- |
| `min_vlen_bits` | 必填整数，声明分析所用最小 VLEN；当前样例使用 256 |
| `compiler_metadata` | 默认 `[]`，要求 ELF 携带的编译器元数据能力名序列；当前能力名为 `stack_access_ids`、`function_pointer`。缺少所声明能力会失败，ELF 携带更多能力可被接受 |
| `unknown_stack_size_policy` | 默认 `conservative`；也接受 `assume-scalar-independent`，后者改变检查的适用范围，交付必须记录该选择 |
| `external_scalar_leaf_contracts` | 默认 `[]`；每条严格含 `symbol`、`library`、`sha256`，符号不可重复，library 为文件基名，sha256 为 64 位小写十六进制摘要 |

更改这些参数会改变检查身份和准入条件，需要重新检查。外部标量叶契约会绑定实际库内容并影响启动校验，不能仅靠一个库名豁免检查。安全算法、策略含义、元数据和契约证明边界统一见 [安全点文档](../developer/architecture/safepoints/README.md)。

## 当前目标的完整例子

下面的例子保存为集成目录中的 `application.toml`。翻译器由用户单独提供，通过既有 `translator_path` 字段填写其绝对路径；发布 wheel 不包含翻译器源码，也不能通过 `importlib.resources(chimera.preprocess.translator)` 获取。scalar 底座需先放入 `~/.chimera/scalar`，工具应能生成或读取目标 RISC-V64 文件；根据集成环境调整工具名、目标库根和工具链文件。输入准备见[外部依赖说明](../external-dependencies.md#翻译器)。

```toml
[config]
data_root = "~/.chimera/data"
scalar_root = "~/.chimera/scalar"
workspace_name = "auto"

[[config.translators]]
source = "riscv64;rvv;vlen=1024"
target = "riscv64;rvv;vlen=256"
translator_path = "/absolute/path/to/rvv_sbt_rvv.py"

[config.tools]
python = "python3"
cc = "cc"
cc_flags = ["-march=rv64gcv", "-mabi=lp64d"]
objdump = "objdump"
nm = "nm"
cmake = "cmake"

[config.target_files]
sysroot = "/"
library_roots = ["/usr/lib/riscv64-linux-gnu", "/lib"]

[config.runtime]
bpf_map = "/sys/fs/bpf/pid_uprobe_map"
ai_thread_control = "/proc/set_ai_thread"

[profile]
name = "application"
target_os = "linux"
target_arch = "riscv64"
target_arch_extension = "rvv"
runtime_scene = "linux_riscv64_rvv_v1"
runtime_abi = 1

[[profile.workflow.steps]]
step = "prepare-workspace"
[[profile.workflow.steps]]
step = "build-runtime"
[[profile.workflow.steps]]
step = "disassemble"
[[profile.workflow.steps]]
step = "build-program-model"
[[profile.workflow.steps]]
step = "safety"
parameters = { min_vlen_bits = 256, compiler_metadata = [], unknown_stack_size_policy = "conservative" }
[[profile.workflow.steps]]
step = "translate"
parameters = { source = "riscv64;rvv;vlen=1024", target = "riscv64;rvv;vlen=256" }
[[profile.workflow.steps]]
step = "offset-map"
[[profile.workflow.steps]]
step = "patch-safepoints"
[[profile.workflow.steps]]
step = "finalize-workspace"
```

翻译器文件必须由集成环境单独准备，并在 Profile 中使用其绝对路径；准备边界与路由要求见[外部依赖说明](../external-dependencies.md#翻译器)。

端点格式必须是三个非空字段 `architecture;extension;specification`，不能含空白，source 与 target 必须不同；每条 workflow route 必须有且仅有对应的 `config.translators` 绑定，翻译器文件必须存在。当前 RVV route 为 1024→256 或 256→1024。需要双向时，增加反向绑定到同目录的 `rvv_sbt_rvv1024.py`，并在 `offset-map` 前增加反向 `translate` 步骤。

旧 `config.translator`、`config.tools.translator_command`、Profile 顶层 safety 参数和 `source_vlen_bits/target_vlen_bits` 形式不受支持。使用当前 section、step 参数和 route 端点。

[集成者首页](README.md) · [CLI](cli.md) · [Workspace](workspace.md)
