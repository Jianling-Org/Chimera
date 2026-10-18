# Workspace 打包与安装

Workspace 是由最终应用内容和所选依赖生成的运行工件集合。Manifest v2 记录目标、模块内容身份、交付方式和能力工件。应用留在目标机安装位置，输入 ELF 不改写；scalar 底座随包提供，启动时显式调用包内 loader。目标机应用路径可以不同，但基名必须匹配 Manifest 的 `runtime_name`，内容摘要也必须一致。

## 交付内容

| 内容 | 位置或来源 |
| --- | --- |
| Workspace 身份及准备信息 | `workspace.json` |
| 模块与能力索引 | `artifacts/modules.tsv` |
| 安全、翻译、映射和 Runtime 工件 | `artifacts/` 下由 Manifest 指定 |
| 随包提供的 scalar 模块和 loader | `scalar/` |
| 显式声明的模型、输入等资源 | `resources/` |
| 应用及目标解析模块 | 目标机预安装，按 Manifest 内容摘要匹配 |

`.workspace` 是有文件清单、摘要和权限的交付归档。`dump/log/generated/build/cache/toolchain` 等开发中间目录不随运行包交付，安装包不能承担原始开发 Workspace 的增量重建职责。

## 打包

先完成最终 ELF 的严格检查与 prepare，再打包：

```bash
chimera-pkg workspace pack --workspace "$WORKSPACE" \
  --output application.workspace
```

单个路径分量按 Workspace ID 在配置根目录下查找；含路径分隔符或绝对路径按显式路径处理。输出扩展名必须为 `.workspace`，输出不得置于 Workspace 内。打包会核对 Manifest 引用、模块交付规则、文件形状和依赖；不要向 Workspace 顶层随意添加文件。

需要交付资源时，每个源文件显式声明目标相对路径：

```bash
chimera-pkg workspace pack --workspace "$WORKSPACE" \
  --resource "$MODEL=model/data.bin" \
  --resource "$INPUT=inputs/request.txt" \
  --output application.workspace
```

上例安装为 `resources/model/data.bin` 和 `resources/inputs/request.txt`。资源源路径必须是普通文件，不能是目录或符号链接；目录树要逐文件列出。目标路径不能为绝对路径、包含 `..` 或与其他声明冲突。已有 `resources/` 文件也必须在本次用 `--resource` 明确声明，不能依靠目录存在自动带入。

资源不会自动变成启动参数或工作目录。运行时用应用自己的参数显式传入安装后的资源路径。若交付资源是 ELF/动态库，打包器还会检查相关本地依赖与不可移植路径；复制一个库文件并不保证依赖闭合。不要把 `delivery=target` 的模块额外塞入 `scalar/`，破坏目标解析契约。

## 安装与校验

在接收端先安装目标匹配的 Chimera wheel 和同版本应用，再安装包：

```bash
python3 -m pip install "$CHIMERA_WHEEL"
chimera-pkg workspace install --input application.workspace --name application
chimera-user list
chimera-user verify --workspace application
```

`--workspace-root` 可指定安装根；未指定则使用运行设置根，默认 `~/.chimera/workspaces`，可由 `CHIMERA_WORKSPACE_ROOT` 覆盖。`--name` 覆盖安装目录名，未提供时沿用包内 ID。

安装先检查归档成员、清单、摘要和模式，再在暂存目录中写入和发布。路径逃逸、符号链接、重复成员、错误摘要或不兼容的既有安装会失败。同内容且校验一致的既有安装可复用。安装后 `.workspack-install.json` 保存交付清单，运行命令先核验安装记录，文件缺失或被修改应重新交付安装。

安装完成说明归档能正确落盘。`chimera-user verify` 还校验工件、目标场景和主机契约；`register/run --input` 才针对目标机的应用与实际依赖执行内容绑定。当前 `verify --workspace ID --input ELF` 与不带 `--input` 的校验范围相同，不能用作应用内容匹配证明。详见 [使用者 CLI](../user/cli.md)。

## 清理

```bash
chimera-pkg workspace remove --workspace "$WORKSPACE"
chimera-pkg workspace clean --workspace-root "$WORKSPACE_ROOT"
```

`remove` 删除一个 Workspace；`clean` 删除所选根目录的所有内容。只对明确不再需要的发布目录执行。工具会拒绝根目录、用户主目录、当前工作目录及含符号链接的危险清理树；它不会替读者判断其中的工件是否仍被使用。

[集成者首页](README.md) · [CLI](cli.md) · [应用使用者指南](../user/README.md)
