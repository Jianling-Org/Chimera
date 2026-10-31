# GCC 标量控制候选与迁移准入

本实验为 make 编译内核的 8 核/16 核对照准备 GCC 工具链。构建成功、原生运行正确和迁移准入是三个独立阶段。

当前板端目录：`/root/kaiwen/chimera-gcc-bootstrap-build`。

- 源码：官方 GCC 15.2.0，已核对官方 SHA-512；私有依赖也完成随附校验。
- 主机编译器：修补后的 Clang/Clang++ 21.1.0。
- 编译选项：`-O2 -g1 -march=rv64gc -mabi=lp64d -fno-vectorize -fno-slp-vectorize -fpass-plugin=/root/.chimera/toolchain_build/plugins/lib/chimera/llvm/ChimeraStackObject.so`。
- 配置：C-only、关闭 bootstrap/multilib/NLS、release checking、系统 zlib、无 ISL。
- 构建：`make -j8 all-gcc`，首次耗时 1050.26 秒，退出码 0。
- 安装：未执行系统安装；`/usr/bin/gcc` 保持不变。

`build-stack-scalar/gcc/xgcc` 配合 `-B.../build-stack-scalar/gcc/` 选择对应 cc1。原生链接测试额外使用 `-B/usr/lib/gcc/riscv64-linux-gnu/15/` 查找系统 CRT/libgcc，不能省略首个 `-B` 导致误用系统 cc1。

## 已识别并修正的动态栈对象

补丁：[0001-gcc-heap-transient-buffers.patch](patches/0001-gcc-heap-transient-buffers.patch)。对原始 GCC 15.2.0 源码使用 `patch -p1` 应用。

1. `driver::set_up_specs` 的 specs 路径缓冲区改为 `auto_vec<char>` 管理的堆内存，保持函数作用域的有效期。
2. `destringize_and_run` 的 `_Pragma` 文本改为 `XNEWVEC` 分配，在预处理器弹出对应输入缓冲区后释放。原有词法和宏上下文恢复流程保留。

补丁针对实际二进制报告的两处未证明动态栈帧，不修改编译器生成目标代码的向量化策略，不放宽检查器的未知尺寸策略。主机编译器关闭自动向量化，不影响新 GCC 根据其命令行生成目标 RVV 代码的能力。

增量重编耗时 45.89 秒；简单 C 编译/运行、`_Pragma` 诊断 push/pop 与 `-Werror`、自定义 specs 定义宏测试均通过。补丁反向 dry-run 通过，原始源码和两个原始二进制已保留。

## 当前准入状态

初始 xgcc 保守 strict gate 检查有 246 项发现，其中 2 项本地未证明、244 项继承。应用补丁后本地项归零，仍有 241 项继承传播发现；因此尚未通过迁移准入。正在导出继承来源报告并顺序检查 cc1。

未生成新的可迁移 GCC Workspace，未进行编译器迁移测试，未将新编译器加入 bootstrap 注册表。原生 smoke 通过不能代替这些步骤。

本轮无 RVV 栈访存映射时不生成 StackObject 映射节；报告中的 `stack_object_plugin=false` 不能单独解释成编译选项未生效。应结合编译命令和实际访存覆盖判断。

证据目录为 `evidence/` 与 `evidence/heap-buffers/`。后者保存补丁、源码原件、二进制原件、测试日志、检查报告及后续 `xgcc-inheritance.json`、`cc1-inheritance.json`。

## GNU 堆式 alloca 候选

xgcc 继承报告进一步定位到 execute、process_command、预处理器和 demangler 等函数中的动态栈分配。采用 GCC/libiberty 已有的 `USE_C_ALLOCA` 分支进行下一轮完整构建，增加 `-DUSE_C_ALLOCA -DCHIMERA_GCC_HEAP_ALLOCA -DSTACK_DIRECTION=-1`，不复用旧对象。

补丁 [0002-gcc-thread-local-heap-alloca.patch](patches/0002-gcc-thread-local-heap-alloca.patch) 为该候选增加线程局部回收链与 ASTRDUP 临时状态，以及头部长度加法的溢出保护；未开启实验宏时保持上游原行为。它不使整个 GCC 成为线程安全库，只隔离所改分配器的线程状态。

[分配器测试](tests/allocator-test.c) 直接编译 GNU 分配器，验证两个线程各 1000 轮分配/嵌套调用/字符串复制后缓冲区保持正确；超大尺寸请求以退出码 1 拒绝。两项均通过，补丁反向 dry-run 通过。

独立目录 `build-heap-scalar` 已完成 configure 并启动 `make -j8 all-gcc`。随后执行 smoke 和保守 strict 检查，检查进程置于 12 GiB、无 swap 的 systemd scope；目前尚无该候选的通过结论。

旧候选的 cc1 来源分析在约 545 秒时被主动结束，为新构建释放资源，退出码 -15；这不是旧 cc1 检查通过或失败的结论。停止原因保存在 `evidence/heap-buffers/cc1-diagnostic-stop.json`。旧二进制及 xgcc 的完整来源报告继续保留。

## 堆候选首次结果与解码器 VLA

`build-heap-scalar` 完整构建成功，耗时 1055.31 秒。xgcc strict gate 仍未通过，但发现数从 241 降到 108，待证明函数从 26 降到 3：`cplus_demangle_print_callback`、`d_demangle_callback`、`is_ctor_or_dtor`。

三处使用 `CP_DYNAMIC_ARRAYS` 分支中的原生 C99 VLA，未经过 alloca 宏，因此不受 `USE_C_ALLOCA` 控制。已向板端提交实验宏下取消 `CP_DYNAMIC_ARRAYS` 的修正，让它使用现有便携 alloca 分支。已提交的后续任务依次执行增量重编、libiberty 上游 check、smoke/pragma/specs 测试、xgcc/cc1 strict 检查并导出来源报告。

此前读取日志的自动审批服务曾超时，现已恢复访问并核验结果。补丁 [0003-gcc-demangler-disable-vla.patch](patches/0003-gcc-demangler-disable-vla.patch) 增量重编成功；libiberty 上游解码测试 858 项（C++ 418、D 365、Rust 75）全部通过，其余测试日志共 47 条 PASS，无 FAIL/ERROR。简单 C、pragma、specs 编译运行测试均通过。

xgcc 默认 conservative 策略的 strict gate 检查返回 0，`findings_total=0`、`pending_proof=0`，没有排除项或条件豁免；检查记录的 ELF SHA-256 与当前二进制一致。cc1 同策略检查仍在运行，已超过一小时，尚无最终结论。它置于 12 GiB、禁用 swap 的 scope 中，后续以实际报告和内存事件为准。

条件控制器已启动：仅当两项检查均通过、策略无放宽且 ELF 身份匹配后，顺序执行 native profile 的 prepare，再验证并注册。工作区位于 `/root/kaiwen/chimera-gcc-bootstrap-build/workspaces`，日志位于 `evidence/native-preparation`。控制器启动、xgcc 通过或原生 smoke 通过均不代表 cc1 已准入或编译器已完成迁移验收。

后续结果（2026-10-16）：cc1 在 6056.71 秒后返回 1，有 36 项本地根因、1169 项继承传播、93 项待证明。控制器已写 STOP，没有启动预处理。报告已保存到本地证据目录。

下一独立候选为 `build-heap-notail`：主机编译增加 `-fno-optimize-sibling-calls`，私有 GMP 使用官方 `malloc-reentrant` 临时区模式。已验证新 GMP 配置启用 `WANT_TMP_REENTRANT`，不启用 `WANT_TMP_ALLOCA`。原因、十个根因函数和下一步检查见 [中文构建记录](../../docs/GCC-BOOTSTRAP-BUILD.zh-CN.md)。旧候选的 xgcc 通过结论不能转用于新二进制，两个可执行文件均须重新检查。

该候选现已构建成功（1050.26 秒），GMP 175 项上游测试、libiberty 测试和 C smoke 通过；新的 xgcc 也通过 strict 检查（115.48 秒），哈希已核对。cc1 检查仍在运行。新条件控制器等待检查结束后再决定是否预处理，日志为 `build/bootstrap-evidence/gcc-build/notail-continuation.log`。当前仍没有编译器迁移验收或新的内核性能对比结论。

后续最终结果：`heap-notail` 的 cc1 在 5068.25 秒后未通过，剩余 123 项继承、26 个待证明函数，本地项为 0。条件流程已停止，没有生成可用 cc1 Workspace。剩余待证明函数集中在 MPFR 和三个 GCC 函数，详见中文构建记录。

下一独立候选 `build-heap-entryframes` 已启动：在原 flags 上增加 `-DMPFR_ALLOCA_MAX=0 -mllvm -enable-shrink-wrap=false`，禁用 MPFR 栈临时区和主机代码延迟建帧，并新增 MPFR 上游测试。配置已通过，构建与完整严格检查尚无最终结果；日志为 `build/bootstrap-evidence/gcc-build/entryframes-runner.log`。
