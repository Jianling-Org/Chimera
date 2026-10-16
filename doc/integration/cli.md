# 应用集成者 CLI

统一入口是 `chimera-pkg`。全局参数放在子命令之前：`--version` 显示版本，`--debug` 启用离线及运行时诊断，`-h/--help` 查看帮助。命令示例中的 `PROFILE`、`ELF`、`APP_SOURCE`、`WORKSPACE` 表示由操作者设置的路径或名称。

## 完整语法

```text
chimera-pkg [--debug] check-elf --profile PROFILE --input ELF [--input ELF ...]
  [--strategy {auto,gate,svf}] [--min-vlen-bits N] [--text-threshold BYTES]
  [--objdump COMMAND] [--json PATH] [--inheritance-report PATH] [--strict]
  [--rebuild-stage {metadata,gate} --rebuild-dir NEW_DIRECTORY]
chimera-pkg [--debug] status --input ELF [--profile PROFILE]
chimera-pkg [--debug] llvm [--cxx] [--list REPORT | --build-plan PLAN_DIRECTORY]
  [--no-gate] [--registry PATH] -- COMPILER_ARGUMENTS...
chimera-pkg [--debug] prepare --profile PROFILE --input ELF [--workspace ID]
  [--workspace-root DIRECTORY] [--allow-problematic]
chimera-pkg build-bundle pack --profile PROFILE --script SCRIPT
  --instructions INSTRUCTIONS [--require-env NAME[=DESCRIPTION] ...] --output ARCHIVE
chimera-pkg build-bundle unpack --input ARCHIVE --output-dir NEW_DIRECTORY
chimera-pkg workspace pack --workspace ID_OR_PATH --output FILE.workspace
  [--resource SOURCE=RELATIVE_PATH ...]
chimera-pkg workspace install --input FILE.workspace [--name ID] [--workspace-root DIRECTORY]
chimera-pkg workspace remove --workspace ID_OR_PATH
chimera-pkg workspace clean [--workspace-root DIRECTORY]
```

`llvm` 的 `--build-plan` 与 `--list`、`--no-gate` 不可组合。双横线后的参数原样交给编译器。Workspace 操作的详细内容与路径规则见 [Workspace](workspace.md)。

## 检查与状态

`check-elf` 根据 Profile 的 workflow 收集二进制检查请求。无二进制检查请求的 workflow 会报告通过，但不构成安全检查证据。算法及报告解释见 [安全点文档](../developer/architecture/safepoints/README.md)。

`--strategy` 默认 `auto`，可指定 `gate` 或 `svf`；`--text-threshold` 默认 1048576 字节，用于自动路线选择。`--min-vlen-bits` 默认沿用 safety 参数，显式值必须与 workflow 声明相符。`--objdump` 覆盖本次检查工具。显式选择 SVF 路线仍需对应工具与构建条件，不意味着 wheel 已含完整 SVF。

单输入时 `--json` 指定检查报告文件，`--inheritance-report` 指定额外的继承诊断输出文件；后者当前导出本次分析，不读取旧报告。多输入时二者均指目录，工具按输入生成报告；同次调用不能重复输入同一路径。不指定 `--json` 时，报告默认写到输入路径追加 `.check.json` 的文件，以输出的 `report:` 为准。

`status` 查询状态；加 `--profile` 可检查记录范围是否匹配。状态含义为：

| 状态 | 后续操作 |
| --- | --- |
| `UNCHECKED` | 尚无有效凭据或内容已变化，执行检查 |
| `PROBLEMATIC` | 存在需处理的发现，读取决策并修复 |
| `REMEDIATED` | 编译器已应用决策，执行复检 |
| `CHECKED` | 当前记录通过；prepare 仍核对内容、版本和 workflow 范围 |

检查凭据绑定 ELF 内容摘要及检查目标、版本、参数；复制 ELF、改变 workflow 或升级检查实现后，应对实际输入重新检查。`--strict` 让未通过检查返回 1；不加它时正常完成分析可返回 0，因此自动化不能仅凭默认退出码判断安全通过。

## 固定重编计划

需要重编时，使用 `check-elf` 生成拥有自身快照的计划。`metadata` 保留 StackObject 元数据插桩、关闭 gate；`gate` 保留插桩并合并本次报告的 gate 名单。每阶段使用新目录，且应用要重新配置为计划中的 `cc/cxx`，清洁构建相应对象，避免缓存复用。

```bash
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" \
  --rebuild-stage metadata --rebuild-dir "$METADATA_PLAN"
cmake -S "$APP_SOURCE" -B "$METADATA_BUILD" \
  -DCMAKE_C_COMPILER="$METADATA_PLAN/cc" \
  -DCMAKE_CXX_COMPILER="$METADATA_PLAN/cxx"
cmake --build "$METADATA_BUILD"
chimera-pkg check-elf --profile "$PROFILE" --input "$METADATA_ELF" \
  --rebuild-stage gate --rebuild-dir "$GATE_PLAN"
cmake -S "$APP_SOURCE" -B "$GATE_BUILD" \
  -DCMAKE_C_COMPILER="$GATE_PLAN/cc" \
  -DCMAKE_CXX_COMPILER="$GATE_PLAN/cxx"
cmake --build "$GATE_BUILD"
chimera-pkg check-elf --profile "$PROFILE" --input "$GATE_ELF" --strict
```

这是需要两阶段时的通用适配：项目自己的配置选项、链接参数及产物路径由构建脚本补齐。metadata 复检已经通过时可直接交付其 ELF；若首轮证据足够，也可直接生成 gate 计划。生成决策阶段有意不使用 `--strict` 中断后续人工判断；最终交付检查应使用 `--strict`。

多输入可重复 `--input`，在同一检查范围下合并应用的多个产物。计划只有在全部分析正常完成后才发布 `cc/cxx`，含 `build-plan.json`、`decision.json`、Profile 快照和报告副本。脚本使用该目录的绝对路径；搬动目录后应重新生成入口。消费时校验包内摘要及报告范围，固定计划不受全局最近决策变更影响；不要手工修改已生成文件。

gate 计划拒绝 SVF/function-pointer 决策。遇此情况应使用所需 SVF/FunctionPointer 工具链流程，不能强行把报告改成 gate。直接调用 `llvm --list REPORT`、`llvm --no-gate` 以及默认状态表/最近决策发现接口仍存在；交付自动化优先显式使用固定计划。`llvm` 返回底层编译器的退出码，成功编译不等于最终 ELF 已通过检查。

## 准备 Workspace

```bash
chimera-pkg prepare --profile "$PROFILE" --input "$ELF" \
  --workspace "$WORKSPACE" --workspace-root "$WORKSPACE_ROOT"
```

workflow 按声明顺序执行，依赖不满足即失败。未指定输出根时使用 `CHIMERA_WORKSPACE_ROOT`，再默认 `~/.chimera/workspaces`；Profile 的 `config.workspace_root` 已被 CLI 忽略并产生警告。显式 `--workspace` 指定名称，否则由配置和输入生成名称。

当输入与所选依赖、scalar 底座等指纹一致时，prepare 可复用已发布 Workspace；所选输入变化会重新准备。`--allow-problematic` 仅允许当前范围已检查且为 `PROBLEMATIC` 的输入进入对照准备，不补足缺失或过期的检查凭据，也不能当作正式安全验收。

## 交付构建说明包

`build-bundle` 适合把 Profile、应用构建脚本和说明交给另一台集成机；它与 `.workspace` 运行工件包用途不同。

```bash
chimera-pkg build-bundle pack --profile "$PROFILE" \
  --script build-application.sh --instructions BUILD.md \
  --require-env 'APP_SOURCE=应用源码目录' \
  --require-env 'APP_BUILD=独立构建目录' --output application-build.zip
chimera-pkg build-bundle unpack --input application-build.zip \
  --output-dir received-build
export APP_SOURCE=/path/to/application-source
export APP_BUILD=/path/to/new-build
bash received-build/build-application.sh
```

归档只含三个原文文件与 `build-bundle.json`；不会执行脚本、打包环境变量的值、递归收集源码或自动修正 Profile。三个文件名必须互异且为 UTF-8 文本，Profile 必须是合法 TOML，每文件不超过 16 MiB。解包校验内容摘要，目标必须不存在；解包后文件模式为 0644，使用 `bash` 显式执行。Profile 中相对路径按解包后的 Profile 所在目录解析，引用的翻译器、源码和其他资源必须由接收方准备。

## 失败与退出码

| 情况 | 退出码或结果 |
| --- | --- |
| 命令正常完成 | 通常 0 |
| `check-elf --strict` 的检查未通过 | 1，保留报告与状态供处理 |
| 参数错误、文件缺失、Profile/workflow 错误、准入不匹配、打包安装校验失败 | 2 |
| 键盘中断 | 130 |
| `llvm` 的编译器运行结果 | 透传编译器退出码 |

重编输出目录已存在、输出覆盖输入、报告路径冲突、检查过程中 ELF/Profile 变化都会拒绝发布计划。失败后查看保留的报告；更正输入后使用新计划目录重新检查。

[集成者首页](README.md) · [Profile](profiles.md) · [Workspace](workspace.md)
