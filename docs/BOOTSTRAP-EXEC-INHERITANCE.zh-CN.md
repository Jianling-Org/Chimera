# 子进程自动迁移标记继承：实现、使用与验收

本文记录 `feature/chimera-bootstrap-exec-inheritance` 分支的实现方案和截至 2026 年 10 月 15 日的验收结果。内核与用户态使用同名开发分支，最终测试以重新编译、经过 Chimera 预处理的 GNU make 为入口，同时验证 make 自身及其启动的子程序。

## 1. 结果与适用范围

本次实现和完整验收已经完成。测试内核为 `6.18.3-chimera-bootstrap-exec`。

| 验证项目 | 结果 |
| --- | --- |
| 内核 exec 继承自测 | 通过 |
| 重编 GNU make 上游测试 | 1431 项、133 类通过，以非 root 用户执行 |
| make 自身迁移 | 实测 X100 → A100 成功 |
| make 启动 RVV 子程序的缩减测试 | 10 轮，每轮 9 个子程序；90 次退出与校验和全部正确 |
| 真实 llama-perplexity 线程矩阵 | 2、4、8、12、16、24、32 线程全部通过 |
| 16 线程重复测试 | 10/10 轮通过 |
| 两小时混合线程循环 | 49/49 例通过，实际运行 7295.72 秒，约 121.6 分钟 |
| 最终清理和内核检查 | 分配账本、待迁移计数、CPU 预留全部归零；无迁移超时及内核告警扫描命中 |

真实 llama 测试共 66 例，累计完成 X100 → A100 迁移 126 次、A100 → X100 迁移 2106 次。非迁移基准困惑度为 29.7254，迁移测试范围为 29.7239–29.7296，最大相对偏差约 0.01413%，低于预先设定的 0.1% 门限。

这里的 llama 基线采用**标量控制代码、显式 RVV 计算内核、启用 OpenMP、关闭 OpenSSL**的配置，用于本地模型和文本计算。该结果不表示任意未经预处理的程序都能迁移，也不表示任意调用者中保活的 VLEN 派生标量已经具备通用迁移安全性，详见第 7 节。

## 2. 为什么 exec 需要重新初始化

fork 和 exec 的处理不同：

- fork 不替换程序映像，子进程继承已有映射和信号处理配置；内核需要重置不能直接继承的迁移提案、计数和预留状态。
- exec 替换程序映像。即使迁移偏好被保留，旧程序的运行时、信号处理和模块地址也不能继续用于新程序。

因此，继承迁移偏好与允许实际迁移必须分开。新程序启动后，需要先确定属于哪个 Workspace，校验实际加载的模块，再注册迁移运行时，最后发布就绪状态。

本方案使用一个与具体 Workspace 无关的小型预加载库：

```text
libchimera-bootstrap.so
```

启动器设置 `LD_PRELOAD` 和 `CHIMERA_REGISTRY`。普通动态 ELF 的 exec 保留这些环境变量时，新映像的动态加载器会再次执行 bootstrap constructor。

```text
chimera-user run --automigrate
    → 设置内核继承策略与 bootstrap 环境
    → exec 重编 make
        → constructor 查询 make 自己的 Workspace
        → 校验、加载运行时、注册处理函数、发布 ready
        → make fork/exec 配方程序
            → 内核保留偏好，关闭新映像的 ready 门
            → constructor 查询配方程序自己的 Workspace
            → 完成注册后重新发布 ready
```

shell 和构建辅助程序可以继续传递环境变量。没有注册记录的程序保持未就绪，不会直接套用父程序的 Workspace。

## 3. 用户态实现

### 3.1 注册表与 Workspace 选择

bootstrap 通过 `/proc/self/exe` 确定当前可执行文件，按其规范化绝对路径匹配注册表。

注册表第一行为：

```text
chimera-registry-v1
```

后续每行包含五个以制表符分隔的字段：

| 字段 | 内容 |
| --- | --- |
| 1 | 可执行文件绝对路径 |
| 2 | 可执行文件 SHA-256 |
| 3 | Workspace 绝对路径 |
| 4 | 运行时动态库绝对路径 |
| 5 | 运行时动态库 SHA-256 |

发布过程使用文件锁、同步写入与原子替换。格式错误、重复匹配、哈希过期或初始化失败时，新映像保持未就绪。bootstrap 会清除继承环境中的旧 Workspace 信息，每个新映像只允许初始化一个运行时。

### 3.2 初始化与就绪发布

选定 Workspace 后，bootstrap 校验可执行文件和运行时哈希，加载显式版本为 ABI 1 的初始化入口。运行时再核对实际加载模块的哈希，注册模块地址和迁移信号处理函数。

只有初始化完成，且对应线程的**内核迁移偏好仍然开启**，才发布 `ready:TID`。该操作还覆盖此前其他 constructor 已创建的线程。环境变量不能重新开启已经被关闭的内核偏好。

`CHIMERA_BOOTSTRAP_TRACE=1` 可输出初始化成功的 PID、可执行文件与 Workspace，便于确认 make 和子程序分别完成了注册。单看程序退出码或校验和，不能替代这一检查。

### 3.3 原生依赖与 TLS

bootstrap 执行时，原生 ELF 加载器已经装载了解释器和依赖库，不能再把它们替换为 Workspace 内打包的另一套 libc。

因此，本路径使用原生依赖 Profile，`scalar_root` 指向空目录；Workspace 中记录的 libc、加载器和其他模块必须对应目标机实际文件。系统依赖变化后，应重新检查并生成 Workspace。

运行时需要 8384 字节 TLS，后加载的动态库使用 initial-exec TLS。启动器会保留其他 `GLIBC_TUNABLES` 配置，并将可选静态 TLS 预留至少设为 64 KiB：

```text
glibc.rtld.optional_static_tls=65536
```

直接绕过启动器运行时，也必须在 exec 之前设置该项。glibc 默认的 512 字节预留不足。

## 4. 内核实现及状态约束

| 接口或状态 | 作用 |
| --- | --- |
| `inherit:TID` | 开启迁移偏好，要求新映像严格执行就绪检查，并先保持未就绪 |
| `ready:TID` | 已完成运行时注册后发布就绪；仅允许当前线程组中已有偏好的线程 |
| `hmp_exec_requires_ready` | 标识该任务需要经过 exec 后重新注册 |
| 原有 `+TID` / `-TID` | 保留兼容行为 |

exec 越过不可返回点后，保留迁移偏好，但关闭旧映像的就绪状态，清理旧提案、排队迁移信号及相关预留。准备或提交失败时，不得改变原有 CPU、PC 和上下文；未越过不可返回点的失败 exec 保持旧映像。

fork 继承偏好与相应门控状态，但重置提案、预留和迁移记账字段。新子任务首次放置保持在实际来源 VLEN 组内，避免尚未注册就被放到另一种物理 VLEN 的 CPU 上。

运行时就绪检查和停止任务执行迁移的路径都检查严格门控，不能通过 BPF 绕过。运行时注册还检查退出状态与偏好；已关闭偏好的任务执行 ready 操作会被拒绝。

双向迁移继续遵循原有状态机：原生代码进入翻译体后，翻译体不得再次迁移；返回原生代码也必须满足既有上下文与重入约束。

主要内核文件为 `drivers/soc/spacemit/hmp.c`、`fs/exec.c`、`fs/proc/array.c`、`kernel/sched/core.c` 及相应头文件。独立的 GPU BSP 初始化内存修复单独交付，不混入调度器补丁。Windows 大小写碰撞涉及的 13 个文件已排除，板端文件核对保持基线内容。

## 5. 构建、注册和运行

以下命令中的 `/absolute/path/...` 是需要替换的路径。Workspace 必须先通过保守安全检查和双向预处理，再进行注册；不可用 `--allow-problematic` 绕过验收。

### 5.1 构建通用 bootstrap

在用户态仓库根目录执行：

```sh
cmake -S runtime -B build/bootstrap -DCHIMERA_BUILD_BOOTSTRAP=ON
cmake --build build/bootstrap -j8
```

### 5.2 注册 make 与配方程序

每个需要迁移的可执行文件分别注册到同一张表：

```sh
chimera-user bootstrap-register \
  --input /absolute/path/rebuilt/make \
  --workspace /absolute/path/make-workspace \
  --registry /run/chimera/workspaces.tsv

chimera-user bootstrap-register \
  --input /absolute/path/child \
  --workspace /absolute/path/child-workspace \
  --registry /run/chimera/workspaces.tsv
```

发布会验证完整 Workspace 和产物哈希，不依赖旧路径中的 pinned BPF map。bootstrap 路径通过运行时初始化和内核 ready 接口完成准入。

### 5.3 以 make 为入口运行

```sh
CHIMERA_BOOTSTRAP_TRACE=1 chimera-user run \
  --registry /run/chimera/workspaces.tsv \
  --bootstrap /absolute/path/libchimera-bootstrap.so \
  --automigrate \
  /absolute/path/rebuilt/make -j8 -C /absolute/path/project
```

使用重编 make 的绝对路径，使递归 `$(MAKE)` 继续执行相同程序。需要迁移的配方程序也应指向已经注册、经过预处理的文件。启动器会保留并去重原有 `LD_PRELOAD` 条目。

板端开发时应使用当前源码的 `tools/run_source_cli.py` 入口，避免误调用旧 editable 安装。具体工具参数可通过该入口的帮助查看。

### 5.4 本次板端产物

用户态开发目录：`/root/kaiwen/chimera-bootstrap-exec`。

| 产物 | 相对于该目录的路径 |
| --- | --- |
| make 可执行文件 | `build/make-source-no-autovec/make` |
| make Workspace | `build/workspaces/make-no-crt` |
| llama 可执行文件 | `build/llama-offline-scalar/bin/llama-perplexity` |
| llama Workspace | `build/workspaces/llama-offline-no-crt` |
| 缩减 RVV Workspace | `build/workspaces/hello-no-crt` |
| 最终注册表 | `build/offline-no-crt-registry.tsv` |
| 最终验收目录 | `build/bootstrap-evidence/acceptance-offline-no-crt-v2` |

本次 llama 可执行文件 SHA-256：

```text
5a383f0849675d64a07dfa63060aab70e30a752889ad25ed80e65cea020add46
```

## 6. 为使 make 本身可迁移所做的处理

系统 `/usr/bin/make` 未通过保守栈存活性检查，因此使用官方 GNU make 4.4.1 源码重编。应用补丁、强制包含头文件和构建说明位于 `examples/applications/gnu-make/`。

主要处理包括明确归档和加载名称缓冲区的所有权，启用 GNU 自带的堆式 alloca 回退，并为各线程维护独立回收链。使用修补后的 Clang 和 ChimeraStackObject 插件；关闭自动循环与 SLP 向量化的选项必须位于 `-O2` 之后，防止后续优化选项重新启用向量化。

重编 make 通过安全检查、双向预处理和 1431 项上游测试。上游测试以非 root 用户运行，避免 root 绕过临时目录权限影响权限测试。make 的独立迁移测试观察到一次 X100 → A100 成功提交，且无超时、最终账本和预留为零。

## 7. 验证中发现的问题与当前边界

### 7.1 原生重入时的 VLEN 派生标量

早期自动向量化 llama 在混合循环的 4 线程用例中发生输出计数断言失败。core 显示调用者保留了按 256 位 VLEN 计算的步长，但实际执行 CPU 已变为 1024 位 VLEN。返回原生代码不会自动重新计算这些通用寄存器中的标量。

这属于原生重入安全问题，不能归因于 exec 迁移标记丢失。最终基线对控制目标使用 `-march=rv64gc` 并关闭自动向量化，ggml 显式 RVV 内核仍启用。可复用配置见 `examples/applications/llama-cpp/scalar-control.cmake`。检查确认 decode 中没有 `vlenb` 读取，整个程序仍有显式 RVV 指令。

通用支持仍需要进一步的标量存活性分析或栈帧保护。本次验收不能推广为任意二进制的双向原生重入保证。

### 7.2 翻译产物与标签识别

生成的翻译动态库原先包含 CRT 自动析构回调，反向翻译加载器退出时触发跨变体回调拒绝。生成代码和来源信息动态库改用 `-nostartfiles`，不改变应用自身析构函数，也不放松跨变体检查。

反汇编中的 `dlclose@plt+0x17a2` 一类名称可能代表普通内部代码。PLT 识别改为精确匹配 `@plt` 后缀，并补充双向回归测试。该修复不代表完整支持 libcrypto；最终本地 llama 工作负载关闭 OpenSSL。

运行时还改为从实际信号帧读取源向量状态，避免采用排队期间的旧快照；失败 ACK 保持原 PC 和上下文。该协议修正没有被作为上述 llama 断言的已证实原因。

### 7.3 preload 的范围

静态 ELF、secure-exec 或主动清除相关环境变量的启动方式不具备普通 preload 继承条件。内核会保持继承策略对应的新映像未就绪。应用还必须保留运行时使用的信号处理配置。

fork 不执行 constructor；vfork 后也要等到 exec 才执行 bootstrap。应用或系统依赖发生变化后，应重新生成并注册 Workspace。

## 8. 验收证据、审查与回滚

最终验收目录中：

- `final-audit.json`：最终审计，验证测试数量、混合循环时长、数值误差、双向迁移、清理计数和告警扫描。
- `results.json`：逐例线程数、退出状态、困惑度、迁移增量与清理结果。
- `native-reference.json`：固定 A100 CPU、关闭迁移偏好的非迁移基准。
- `final-dmesg.log`：最终内核日志。
- `PASS`：测试运行器完成标记；应与最终审计共同查看。

其他回归包括 11 项 C 测试、27 项启动器和 bootstrap 相关 Python 测试，以及翻译器 1586 项通过、287 项跳过。实际板端构建核对了 7 个内核代码文件，另有 13 个大小写敏感文件与基线匹配。

内核可审查补丁位于本地 `build/bootstrap-evidence/kernel-review/`，分为 `scheduler-bootstrap.patch` 和独立的 `bsp-bootloader-init-memory.patch`。交付时不要将 Windows 大小写碰撞文件加入调度器提交。当前实现尚未提交或推送，本文记录的是已测试工作区状态。

原启动配置和旧镜像备份位于板端：

```text
/root/kaiwen/chimera-bootstrap-kernel-build/bootstrap-evidence/boot-backup-20261013-220601
```

其中 `rollback.sh` 用于恢复原 GCC 实验内核启动选择。更换启动内核前，应再次核对备份和目标配置，并完成 panic、锁、任务生命周期、预留泄漏、信号帧与翻译状态重入审查。

英文详细记录：[exec 继承实现](BOOTSTRAP-EXEC-INHERITANCE.md)、[原生验收基线及诊断过程](BOOTSTRAP-NATIVE-BASELINE.md)。
