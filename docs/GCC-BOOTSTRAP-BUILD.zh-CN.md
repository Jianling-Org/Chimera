# 板端空间清理与 GCC 重编准备

## 2026-10-21：cc1 正式 Workspace 发布

make 当前分支严格检查通过（31.21 秒），匹配 Workspace 预处理成功（496.72 秒）。首轮实际编译链预检失败：make 退出 2、64 个目标中仅完成 15 个，GCC 子进程等待报告 `Interrupted system call`；418 次 proposal 均 NACK，真实迁移数为零。采样 cc1 仅在 X100，退出账本/pending/reservation 归零。不得将本轮视作迁移或性能通过。

Linux 信号安装现增加 `SA_RESTART`，避免调度通知使原程序的阻塞子进程等待返回 EINTR；新增真实 fork/signal/waitpid 回归与原信号合同共 4 项通过。独立 debug runtime 与三份 Workspace 克隆用于复测，更新 manifest 和注册 SHA，原发布产物保留。日志 `restart-signal-diagnostic.log`；仍需定位 NACK、证明真实迁移并完成正确性验证。

当前 `dev/automigration-subprocess` 分支的 regex 堆分配候选已完成 cc1 正式预处理，最终控制器返回 0，耗时 9660.85 秒。Workspace 为独立 GCC 根目录下 `workspaces/gcc-cc1-regexmalloc-release-native-v2`。正式管线重新执行安全分析、安全点补丁和发布校验；已生成翻译及映射二进制按 SHA 核验复用，未放宽 conservative strict。`evidence/final-pipeline-status.json`、`evidence/cc1-final-pipeline/` 和新用户态根 `cc1-final-pipeline.log` 留存证据。交换已关闭。

现对重编 GNU make ELF 重新执行当前分支严格检查并生成匹配的 `make-release-native-v1`，日志 `make-release-prepare-runner.log`，证据 `evidence/make-release-native/`。随后仍需 bootstrap 注册、make/编译器真实迁移和同编译器的两组内核性能验证；Workspace 发布不等同这些步骤通过。下方为历史过程记录。

## 2026-10-20 regex 堆分配候选

release重新准入时，旧xgcc严格检查出现6项发现，均来自libiberty的byte_re_match_2_internal动态SP帧（分配0x8f008，大小来源未证明），包括5个外部调用和1个未解析间接调用，pending_proof=1。cc1未启动。保留失败报告，不豁免或放宽。

新增候选仅追加已有REGEX_MALLOC编译选项，选择regex内置堆分配/释放分支，保留entryframes的其他选项；独立目录build-heap-entryframes-regexmalloc，证据evidence/heap-entryframes-regexmalloc，日志新用户态根regex-heap-build-runner.log。构建后执行GMP/MPFR/libiberty、C冒烟和两项严格检查。成功构建也不等同迁移准入，必须重新prepare及实际验证。

> 2026-10-20最新：分支已改名dev/automigration-subprocess；板端经用户授权恢复6.18.3-chimera-bootstrap-exec，exec继承自测通过。翻译器1823项通过（943跳过），portable C 11项通过；完整Python对照在干净venv补齐pyelftools和子进程源码路径后重跑，证据build/clean-compare-v2-20261020。严格GCC重新准入尚未开始，旧报告不能替代新验收。下文仍运行child-freeze等属于历史记录。

## 当前基线：automigration-release（2026-10-20）

用户指定以 `feature/rvv256-performance-optimizations-automigration-release` 为基线，现固定344909c7d72bb99ca62c82b0fd5d93163b636f2a。独立分支 `feature/chimera-bootstrap-automigration-release` 已在本地 `chimera-user-bootstrap-release` 和板端 `/root/kaiwen/chimera-bootstrap-exec-release` 建立，本任务增量已三方同步；下方普通主线v32恢复记录只作过程记录。

保留release的分级NACK、vstart拒绝、no-link寄存器和状态机保护；安全图释放/地址压缩沿用release已有实现。翻译DSO合并无CRT构造器和内部符号绑定，保留精确PLT识别。关键集成测试324项、169子测试通过。完整Python、翻译器和portable C回归正在新板端checkout运行；全通过后才执行同一GCC在release基线的conservative strict重新准入，无排除/豁免，不将旧版本报告当新验收。

当前日志为新checkout根 `release-port-runner.log`、`release-readmission-runner.log`，回归阶段证据 `build/release-port-20261020/`，GCC报告 `evidence/release-readmission-20261020/`（相对独立GCC构建根）。板端托管Git SSH key过期，已通过本机fetch后的增量bundle同步同一提交；未改凭据或其他冻结目录。未安装或启动内核。

## 2026-10-20 恢复开发

用户已明确要求fetch最新分支并继续。用户态主线现为13713b081（v32），内核主线仍2838fbc3c。相关标量VLEN生命周期、外部调用边界和翻译修复已集成本任务本地/板端独立工作树，保留bootstrap与安全地址压缩。launcher冲突已保留两套逻辑，先验证leaf绑定再发布注册表。324项集成测试和169子测试通过。

板端当前运行冻结测试内核 `6.18.3-prefer-a100-chimera-child-freeze`，旧暂停进程已不存在。GCC ELF哈希仍匹配，已启动v32 conservative strict重新准入，无排除和条件豁免。日志位于用户态 `build/bootstrap-evidence/resume-20261020/gcc-readmission-runner.log`，报告位于GCC根 `evidence/v32-readmission-20261020`。旧8G交换文件已清理，首次入口断言停止后，已改用独立4GiB临时交换、12GiB物理上限和每检查4小时保护，退出时swapoff。旧报告和第一方向汇编不直接作为v32验收，后续需重新核对/生成Workspace并完成实际迁移及性能验证。未安装或启动新内核。

日期：2026-10-15。目标是为 make 内核编译性能实验准备可检查、可预处理的 GCC 工具链。这里只记录当前现场操作，历史 gate5 的检查通过记录不能替代新产物验收。

最新进度：首次 GCC 构建成功（1050.26 秒），简单 C 编译/运行通过。随后修正两处运行时长度的栈缓冲区，相关 `_Pragma`、specs 测试通过；xgcc 本地未证明项已归零，但仍有 241 项继承传播发现，尚未通过迁移准入。正在追踪来源并检查 cc1，详见[候选说明与补丁](../experiments/gcc-bootstrap/README.md)。

后续来源报告确认多处动态栈分配传播，已转入 GNU `USE_C_ALLOCA` 堆式回退候选的全新构建。分配器双线程及溢出测试通过；旧 cc1 诊断主动结束后释放内存，新构建在 `build-heap-scalar` 运行。检查策略保持保守，尚未准入迁移。

## 空间清理结果

共对六处内核构建/输出目录执行 Kbuild `make clean`，不执行 `mrproper`，不改源码、不安装或切换启动内核。

| 构建目录 | 清理内容 |
| --- | --- |
| `/root/kaiwen/chimera-bootstrap-kernel-build` | 当前测试内核的对象、模块及链接中间文件 |
| `/root/kaiwen/chimera-make-kernel-perf/output` | X100 8 核构建中间文件 |
| `/root/codex-kernel-review` | 旧审查内核构建中间文件 |
| `/root/kaiwen/chimera-mmview` | 旧 mmview 内核构建中间文件 |
| `/root/kaiwen/chimera-prefer-a100-789b3a2ff` | 旧 prefer_A100 内核构建中间文件 |
| `/root/kaiwen/chimera-gcc-openloop-kernel` | 原已接近干净的源码树，新增回收可忽略 |

清理前根文件系统可用 2,924,900,352 字节，清理后可用 46,331,326,464 字节，累计释放 43,406,426,112 字节，约 **40.4 GiB**。源码下载等后续操作会再次占用部分空间，以 `df` 为准。

保留并按 SHA-256 核对恢复的最终文件共 63 项，包括各树中实际存在的配置、Image、vmlinux、System.map、模块符号/清单及设备树产物。备份使用同一文件系统的硬链接，放在构建树外，避免再占用一份大文件空间。清理后中间对象需要重新构建；保留最终产物并不意味着可以继续直接增量链接。

当前 `/boot/env_k3.txt` 哈希保持不变。现有 `/boot` 镜像、已安装模块、回滚备份、用户态迁移 Workspace、验收结果及故障 core 均保留。

第一次操作发现：Kbuild 会递归删除嵌套备份中的 `modules.order`。已将备份移到树外，并按 `modules_install` 的逆转换从已安装清单恢复，恢复文件与清理前 SHA-256 完全一致。后续各目录直接采用树外备份，没有重复该问题。

证据位于板端用户态目录 `/root/kaiwen/chimera-bootstrap-exec/build/bootstrap-evidence/`：

- `space-cleanup-20261015T084822Z/cleanup-summary.json`：前两处目录，释放 16,031,215,616 字节。
- `space-cleanup-20261015T084822Z/preserved-manifest.json`：最终产物身份及原启动配置哈希。
- `kernel-space-cleanup-20261015T085213Z/cleanup-summary.json`：其余四处目录，释放 27,375,222,784 字节。
- 各子目录的 `preserved-manifest.json` 和 `make-clean.log`：保存清单及清理日志。

## 新 GCC 尝试的范围

独立工作目录为 `/root/kaiwen/chimera-gcc-bootstrap-build`，不替换 `/usr/bin/gcc`。选择与系统编译器同版本系列的 GCC 15.2.0 官方源码；下载后必须先核对官方 SHA-512，再解压和构建。

源码地址：[GCC 15.2.0 tar.xz](https://gcc.gnu.org/pub/gcc/releases/gcc-15.2.0/gcc-15.2.0.tar.xz)，校验依据为[官方 SHA-512 清单](https://gcc.gnu.org/pub/gcc/releases/gcc-15.2.0/sha512.sum)。预期 SHA-512：

```text
89047a2e07bd9da265b507b516ed3635adb17491c7f4f67cf090f0bd5b3fc7f2ee6e4cc4008beef7ca884b6b71dffe2bb652b21f01a702e17b468cca2d10b2de
```

板端已有修补后的 Clang 21.1.0 和 `ChimeraStackObject.so`、`ChimeraVectorGate.so`。初始候选计划为 C-only、独立输出目录、关闭 bootstrap/multilib，使用 StackObject 插桩，并以标量控制代码避免自动向量化导致的 VLEN 派生标量保活。是否需要进一步 gate 重编，由 xgcc/cc1 的实际检查结果决定。

源码已完成官方 SHA-512 校验及解压；gettext/GMP/MPFR/MPC 四个私有依赖全部通过 GCC 随附的 SHA-512 校验，configure 返回 0。首次候选已在 `build-stack-scalar` 中启动 `make -j8 all-gcc`。主机编译器使用修补后的 Clang/Clang++，并传入 `-O2 -g1 -march=rv64gc -mabi=lp64d -fno-vectorize -fno-slp-vectorize -fpass-plugin=.../ChimeraStackObject.so`；build-machine 辅助工具使用系统 GCC/G++。

构建控制器保留日志并监测剩余磁盘、MemAvailable 和最长运行时间；触发保护时停止本轮进程组并保留现场。构建成功后执行简单 C 编译/运行，再顺序执行 xgcc、cc1 的 strict gate 检查。未通过时停止，不自动使用 `--allow-problematic`，也不自动放宽未知标量尺寸策略。

主日志：用户态目录 `build/bootstrap-evidence/gcc-build/build-runner.log`。构建日志、配置、工具哈希和后续检查报告：`/root/kaiwen/chimera-gcc-bootstrap-build/evidence/`。编译启动时文件系统可用约 42 GiB；该值会随构建变化。

缺少 GMP/MPFR/MPC 开发头文件。系统包安装模拟会升级现有 MPFR/MPC 运行库，因此未执行安装；优先使用 GCC 官方源码提供的私有依赖下载与构建流程，避免改变既有原生依赖身份。

完成编译不等于通过迁移准入。后续依次核对编译器身份、简单 C 编译运行、xgcc/cc1 的实际安全报告、双向 prepare、模块哈希与运行时迁移。报告必须查看 `passed` 和 findings；非 strict 命令返回 0 不代表检查通过。

若最终使用新 GCC，X100 8 核和异构 16 核内核构建都要用同一工具链重新测试；系统 GCC 的 1123.56 秒仅保留为历史参考。

## 堆式分配候选的最新进展（2026-10-15）

`build-heap-scalar` 已完成完整构建（1055.31 秒）。在两个显式动态缓冲区修正、GNU C_alloca 线程局部状态修正基础上，第三个补丁让 demangler 在实验宏下使用上游已有的 alloca 分支，避免原生 VLA 绕过堆式分配。

增量构建与 C/pragma/specs 编译运行通过；libiberty 上游 858 项解码测试全部通过，其他测试日志 47 条 PASS，无 FAIL/ERROR。xgcc 已通过默认保守 strict gate：发现项与待证明项均为 0，没有排除或条件豁免，ELF 哈希已复核。

cc1 的同策略分析仍在运行，已超过一小时，尚无最终报告；资源上限为 12 GiB、无 swap。后续控制器仅在两个二进制都通过且身份匹配时顺序预处理、验证和注册。若检查失败或触发资源保护，保留证据并停止后续步骤。当前不能宣称编译器迁移通过，也没有新的 16 核性能结果。

补丁及细节见 `experiments/gcc-bootstrap/`。检查证据在板端 `evidence/demangler-heap/`，预处理证据在 `evidence/native-preparation/`，均相对于 GCC 独立构建根目录。

## cc1 结果与下一候选（2026-10-16）

上述 cc1 检查在 6056.71 秒后正常返回失败，并非 OOM：1205 项发现中有 36 项本地根因、1169 项继承传播，93 项待证明。条件控制器写入 `evidence/native-preparation/STOP.json`，没有预处理或注册旧 cc1。

本地根因聚合为 10 个函数。GCC 的 7 个函数包括 DWARF 类型处理、表达式展开、地址输出、OpenMP scan、二元操作展开和 postreload；GMP 的 3 个函数为 `__gmpz_mul`、`__gmpf_get_str`、`__gmpz_get_str`。机器码核验发现部分 GCC 项实际为固定立即数帧，尾递归恢复栈后跳回入口导致 `loop-carried-value` 证明缺口，不能把所有报告项都解释成源码 VLA。GMP 的 `TMP_ALLOC_LIMBS` 确实可使用动态栈。

独立候选 `build-heap-notail` 已开始完整构建。保留前三个源码补丁，主机编译器增加 `-fno-optimize-sibling-calls`，私有 GMP configure 缓存设置 `gmp_cv_option_alloca=malloc-reentrant`。已读取生成的 GMP `config.h`：`WANT_TMP_REENTRANT=1`，`WANT_TMP_ALLOCA` 未定义。该候选不修改检查器，也不使用排除项或弱化策略。禁用尾调用只用于减少已观察到的证明缺口，不保证所有未知来源均消失，仍需实际 strict 报告。

构建控制器随后核验 GMP 配置，运行 GMP 和 libiberty 上游测试、C smoke，再顺序运行 xgcc/cc1 conservative strict 检查。新旧输出目录独立，旧二进制与失败报告保留。日志为用户态目录 `build/bootstrap-evidence/gcc-build/heap-notail-runner.log`，阶段证据为 GCC 根目录 `evidence/heap-notail/`。

该候选完整构建已通过，耗时 1050.26 秒。GMP 上游测试汇总为 175 项通过、0 跳过、0 失败/错误；libiberty 858 项解码测试及 47 条 PASS 均通过。C smoke 编译运行通过。新的 xgcc strict 检查耗时 115.48 秒，返回 0，报告 ELF SHA-256 与当前二进制一致。cc1 strict 检查仍在运行，没有新的准入结论。

新候选的条件接续控制器已启动：检查完成后核验两个报告、策略和二进制身份，只有全部通过才顺序 prepare。预处理证据使用 `evidence/native-preparation-notail/`，工作区名为 `gcc-xgcc-heap-notail-native-v1` 与 `gcc-cc1-heap-notail-native-v1`，注册表为 `gcc-bootstrap-notail-registry.tsv`；不复用旧候选的 STOP 目录或注册表。接续日志为用户态 `build/bootstrap-evidence/gcc-build/notail-continuation.log`。

已部署下一步运行时预检，等待 `PREPARED.json` 后复核两个 ELF 哈希，再用同一 GCC 原生编译生成参考对象和程序。随后 make 自动迁移启动 64 个编译任务，比较全部对象 SHA-256 和程序输出，采样 make/xgcc/cc1 的 CPU、就绪状态及账本增量，并保存前后 dmesg。证据目录为 `evidence/notail-runtime-pilot/`，等待/运行日志为用户态 `build/bootstrap-evidence/gcc-build/notail-runtime-pilot-runner.log`。该预检尚未开始，脚本部署和语法检查不构成运行通过；完整内核计时仍须检查其迁移、清理和告警证据后再启动。

## 剩余继承项与入口建帧候选（2026-10-16）

`heap-notail` 的 cc1 检查最终耗时 5068.25 秒，返回 1。本地根因及本地未证明项均为 0，仍有 123 项继承传播、26 个待证明函数，因此预处理与运行时预检都已自动停止。旧报告保留，不能把本地项归零当作整体通过。

26 个待证明函数包括 23 个 MPFR 函数，以及 GCC 的 `tree_to_poly_int64`、`tree_to_poly_uint64` 和 `check_load_store_for_partial_vectors` 的一个 lambda。MPFR 的私有 `TMP_ALLOC` 不使用 GMP 配置，默认仍允许最多 16384 字节的 alloca；源码明确允许通过 `MPFR_ALLOCA_MAX=0` 禁用。两个 GCC 小函数机器码只在断言失败路径分配固定 16 字节帧，提示条件控制流中的延迟建帧仍有证明缺口，尚不能据此豁免第三个函数或整个调用链。

已启动新的独立目录 `build-heap-entryframes`，保留原补丁与 GMP 堆模式，主机 flags 追加 `-DMPFR_ALLOCA_MAX=0 -mllvm -enable-shrink-wrap=false`。已用安装的 Clang 实际编译验证后者可用；configure 已通过。除原测试外，加入私有 MPFR 上游 `make -j8 check`。不修改检查器，不排除函数，两个 ELF 仍须重新通过完整 conservative strict 检查。

主日志为用户态 `build/bootstrap-evidence/gcc-build/entryframes-runner.log`，阶段证据为 GCC 根目录 `evidence/heap-entryframes/`。条件接续和预检等待进程已启动，日志分别为 `entryframes-continuation.log` 和 `entryframes-runtime-pilot-runner.log`。只有新二进制全部通过并成功准备、注册才执行预检；本候选尚无构建、准入或迁移通过结论。

该候选已完整构建成功，耗时 1055.28 秒。首次 MPFR check 的 183 项中，179 通过、3 跳过、1 失败；唯一失败为 `tsprintf` 的旧千位分隔符/精度期望。板端 glibc 为 2.43，[MPFR 官方说明](https://www.mpfr.org/mpfr-4.2.0/)已记录旧测试依赖 glibc 2.36 及以前的不正确输出。已按[官方 patch01](https://www.mpfr.org/mpfr-4.2.0/patch01)移植对应测试用例，补丁仅修改 `mpfr/tests/tsprintf.c`，原失败日志和测试源码均保留，没有调整库实现或忽略测试。

重跑 MPFR 全部测试返回 0，两个 GCC ELF 的 SHA-256 在测试修正前后完全一致。随后 libiberty check 和 C smoke 通过，xgcc/cc1 strict 检查恢复。恢复日志为 `build/bootstrap-evidence/gcc-build/entryframes-resume.log`。测试移植补丁保存于 `experiments/gcc-bootstrap/patches/0004-mpfr-tsprintf-thousands-test.patch`，它不是对迁移准入规则的修改。

用户已明确要求无人值守持续推进直至最终性能实验完成。本聊天设置每小时跟进（ID `gcc-make`）；状态无变化时不发送通知，失败时先自行诊断修复，最终完成后暂停跟进。恢复工作时先读取真实进程和状态文件，不重复启动已有任务。

## 当前候选已通过严格准入

`heap-entryframes` 的 xgcc 和 cc1 均已通过 conservative strict 检查，分别耗时 115.54 秒、4682.89 秒。两份报告发现项、待证明项均为 0，无排除或条件豁免，proof budget 未耗尽。条件控制器复核身份后开始 native prepare；xgcc 已成功（1205.03 秒），cc1 正在预处理，尚未注册和运行迁移预检。

准入 ELF SHA-256：xgcc `47899daf51ea563d4c107019e1c6b019efefdfc08dc56e10421b6d4d2fc49bf1`，cc1 `fd6cc6047b55842b56400282944a1ab3d5c4234a84fee0fd14eca6091bc563b9`。严格报告和 xgcc prepare 状态已归档本地。该结果确认本轮静态准入，不能替代 cc1 完整 Workspace、实际迁移和最终性能验收。

cc1 v1 prepare 在 2210.05 秒后被 cgroup OOM 杀死，退出 -9。dmesg 明确记录12GiB内存上限，原 staging 和日志保留；这不是安全检查失败。原注册和预检控制器已停止。

已启动一次资源有界的恢复：保持12GiB物理内存上限，允许最多8GiB磁盘交换，使用 GCC 根目录专用 `prepare-only-8GiB.swap`，不修改 fstab 或启动配置；设置4小时及剩余磁盘8GiB保护。使用新 Workspace `gcc-cc1-heap-entryframes-native-v2-swap`，复用已成功的 xgcc v1。成功后必须先关闭交换，再注册和运行正确性预检。正式性能计时前再次确认交换已关闭；失败保留现场，不能在交换未核验时启动计时。

恢复日志为用户态 `build/bootstrap-evidence/gcc-build/cc1-swap-retry-runner.log`，证据目录为 GCC 根 `evidence/native-preparation-entryframes-swap/`。恢复并不放宽检查或更改二进制，入口再次核对两份严格报告及 ELF 哈希。

该次重试仍于7120.13秒被OOM终止，临时交换已安全关闭，原现场保留。源码诊断发现安全步骤虽将外层vector/stack中间结果置空，内层 `SafetyAnalysisResult.vector/stack` 仍保留完整工作图，导致它们跨阶段驻留。现新增 `without_intermediates()`，仅在SafetyStep保留工作流结果时清空内层中间对象；安全记录、策略、排除信息和已导出的产物保持原值。

安全分类、产物、告警和safepoint共27项回归通过，新增弱引用测试确认原工作图可回收，同时验证安全记录及准入元数据保持。修正已同步板端，GCC二进制未变。新恢复沿用12G物理+8G临时交换及4小时保护，在每阶段边界记录RSS/swap并回收已死循环对象，不跳过分析、翻译或发布验证。日志为用户态 `build/bootstrap-evidence/gcc-build/cc1-memoryfix-runner.log`，阶段证据为 GCC根 `evidence/native-preparation-entryframes-memoryfix/`，Workspace新名 `gcc-cc1-heap-entryframes-native-v3-memoryfix`。尚需观察完整预处理是否能完成，不能将内存回归通过当作大型cc1验收通过。

v3在6570.12秒仍OOM，阶段日志已证明安全分析完成且进入第一方向翻译；翻译前父进程仍有约9GiB RSS，完整逐指令安全记录与翻译子进程叠加。进一步修正为：完整诊断导出后，工作流只保留精确安全地址的uint64字节表，不再跨翻译阶段保存每条指令的SafetyRecord对象。safepoint补丁步骤通过统一迭代接口兼容完整记录和压缩地址；原诊断文件、准入规则、补丁集合保持不变。

31项相关回归通过，新增测试确认记录可回收，并在真实测试DSO上验证两条路径的补丁字节和补丁数完全相同。v3失败后交换已关闭；v4恢复重新按12G物理+8G交换上限启动，阶段边界GC后使用malloc_trim归还空闲页，仍不跳过分析步骤。当前日志 `build/bootstrap-evidence/gcc-build/cc1-packed-runner.log`，证据 `evidence/native-preparation-entryframes-packed/`，新Workspace `gcc-cc1-heap-entryframes-native-v4-packed`。正式性能计时前仍须swapoff和核验。

v4已在真实cc1任务验证压缩效果：进入第一方向翻译前父进程RSS降到159396KiB，随后约138672KiB；翻译子进程运行约28分钟时RSS为975764KiB，未再次OOM。但JAL-fixup探测链接在 `/tmp` 报设备无空间。实测 `/tmp` 为7.9GiB tmpfs，根分区仍有23GiB可用，因此改用磁盘临时目录继续处理，不增加内存上限。

已对停止的v1/v2/v3 staging中完全相同的dump和安全导出文件逐一SHA-256核对后硬链接去重，保留内容并回收3790970880字节；去重清单为GCC根 `evidence/failed-stage-dedup.json`，不修改当时运行的v4文件。v4正常异常后由工作流清理其staging，失败日志留在外部证据目录。

新v5设置 `TMPDIR=/root/kaiwen/chimera-gcc-bootstrap-build/prepare-tmp`，在ext4根分区生成临时探测对象；沿用压缩安全地址、12G物理+8G交换和4小时保护。日志为用户态 `build/bootstrap-evidence/gcc-build/cc1-disktemp-runner.log`，阶段证据 `evidence/native-preparation-entryframes-disktemp/`，Workspace名 `gcc-cc1-heap-entryframes-native-v5-disktemp`。当前尚未完成完整预处理或迁移验证。
