# 应用使用者 CLI

入口为 `chimera-user`；`--version` 查看版本，`--debug` 在子命令之前启用诊断，`-h/--help` 查看帮助。使用者命令不接受 `--profile`。

## 完整语法

```text
chimera-user [--debug] list
chimera-user [--debug] verify --workspace ID_OR_PATH [--input ELF]
chimera-user [--debug] register --input ELF [--workspace ID_OR_PATH]
chimera-user [--debug] run --input ELF [--workspace ID_OR_PATH] -- APPLICATION_ARGUMENTS...
chimera-user [--debug] migrate [--workspace ID_OR_PATH]
  --parent-thread TID --migration-count N --direction ROUTE
chimera-user [--debug] migrate [--workspace ID_OR_PATH]
  --threads TID [TID ...] --direction ROUTE
```

安装由 `chimera-pkg workspace install` 执行，见 [Workspace](../integration/workspace.md)。`register` 没有 `--verify` 参数；`register/run` 必须显式提供 `--input`。

## 运行设置

首次调用会尽可能创建 `~/.chimera/user.toml`，只保存运行设置。可用 `CHIMERA_USER_CONFIG` 指定文件。

```toml
[runtime]
workspace_root = "~/.chimera/workspaces"
bpf_map = "/sys/fs/bpf/pid_uprobe_map"
ai_thread_control = "/proc/set_ai_thread"
```

`CHIMERA_WORKSPACE_ROOT`、`CHIMERA_BPF_MAP`、`CHIMERA_AI_THREAD_CONTROL` 分别覆盖对应配置。默认值如上；路径需与管理员部署的接口一致。只读主目录下配置无法落盘时，命令可使用内存默认值，所需 Workspace 和内核接口仍须可访问。

## 列表与校验

`list` 列出配置根下的已发布 Workspace。`--workspace` 接受该根下 ID 或可解析的显式目录。

`verify` 校验安装清单、Manifest、必需工件、场景拓扑以及主机契约。包的安装完整性检查和全量运行环境检查是两层：前者由安装/安装记录验证完成，后者由 `verify_workspace` 连同主机校验完成。

**`verify` 始终按 `--workspace` 检查工件与主机环境；当前接受的 `--input` 不参与应用绑定。** 核对目标机主程序时使用 `register/run --input ELF`，依赖的启动校验范围见下节。应用结果与迁移完成还需由应用输出及 Runtime 事件确认。

## 注册与启动

```bash
chimera-user verify --workspace "$WORKSPACE"
chimera-user register --workspace "$WORKSPACE" --input "$ELF"
chimera-user run --workspace "$WORKSPACE" --input "$ELF" -- APPLICATION_ARGUMENTS
```

省略 `--workspace` 时，`register/run` 在配置根下根据输入 ELF 查找已有 Workspace。多个候选或无法解析时显式指定。

两者都验证 Workspace 与主机，并核对输入主模块的文件基名及内容摘要；安装路径可以不同，但基名必须与 Manifest 的 `runtime_name` 一致。依赖通过包内 loader 的实际解析结果确定。注册使用这些实际路径登记 inode；启动还对实际解析模块逐一校验摘要。当前注册路径没有执行启动路径的逐依赖摘要循环，因此仅有注册成功不能替代启动时的完整内容校验。

注册把这台机器实际文件的 inode 告知内核。即使文件内容相同，更换路径指向的文件、重新安装或重新链接应用后也应重新注册；不能把另一台机器或旧 inode 的注册当作仍然有效。保留应用和所需库的安装位置，待注册后再启动。

`run` 用 `os.execve` 显式执行包内 scalar loader，配置库搜索路径与 Runtime preload，以原位置应用路径和传入参数启动；输入 ELF 的 `PT_INTERP` 不被改写。包内 `resources/` 也不会自动成为应用参数，须提供安装后资源的实际路径。

## 迁移线程

当前 scene 接受的 route 是 `1024-to-256` 和 `256-to-1024`，其是否适用于进程还取决于 Workspace 准备的产物及线程当前状态。反向请求不能替代线程状态确认。

```bash
chimera-user migrate --workspace "$WORKSPACE" \
  --parent-thread "$PID" --migration-count 2 --direction 1024-to-256
chimera-user migrate --workspace "$WORKSPACE" \
  --threads "$WORKER_TID" --direction 256-to-1024
```

两种选择方式互斥：

- `--parent-thread` 接受目标线程组中一个现存 TID，配合正整数 `--migration-count`。实现优先选择非主线程中 TID 较大的 N 个；数量超过非主线程数量时纳入主线程，最多选择现存全组线程。它不识别哪些线程负责计算。
- `--threads` 显式提供现存线程，所有 TID 必须属于同一线程组。对 OpenMP 等程序应从应用日志识别真正的计算 worker，避免把后台或休眠辅助线程当作计算线程。

省略 `--workspace` 时，命令读取 **目标进程** `/proc/<tgid>/environ` 中唯一非空、绝对路径形式的 `CHIMERA_WORKSPACE`，不会使用迁移命令自身的同名环境变量或当前目录。进程环境不可读、缺失或含歧义时，显式传入该进程启动所用的 Workspace。

Runtime ready 检查发生在首次控制写入之前，针对全部所选线程核对线程组以及当前 scene 需要的信号处理器已安装、未忽略且未屏蔽。当前 scene 要求信号 5 和 41。未安装处理器时报 `migration not ready`；等待 Runtime 初始化完成后重试。应用 PID 或 `CHIMERA_WORKSPACE` 早于处理器安装出现，不能跳过这一条件。

通过检查后按所选线程写入迁移控制接口。多个请求没有完成 ACK，也不保证后续写入失败时前面的请求被撤回。输出中的 `migrated_tids[...]` 是提交信息；需结合 Runtime 事件、实际核位置、翻译状态和正确的应用结果判断完成。

## 失败与退出状态

正常列表、校验、注册和迁移提交返回 0；参数错误、内容/工件不匹配、依赖解析失败、内核接口缺失或权限不足、线程不属于同组、Runtime 未就绪通常返回 2；键盘中断返回 130。`run` 在成功启动后已替换为应用，因此最终退出状态来自 loader/应用。

校验失败先核对 wheel 目标和安装包完整性；内容失配重新确认应用/依赖版本并交付对应 Workspace；inode 变化重新注册。迁移失败查看具体线程、route、ready 状态与控制接口权限。不要仅重命名文件来绕过内容匹配。

[使用者首页](README.md) · [集成者指南](../integration/README.md)
