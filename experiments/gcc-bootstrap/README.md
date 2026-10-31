# GCC 标量控制候选与迁移准入

本目录保留 GCC 15.2.0 的标量控制适配补丁和分配器测试。构建选项、候选检查与准备失败见[构建记录](../../docs/GCC-BOOTSTRAP-BUILD.zh-CN.md)；后续固定版本的运行与性能结果见[同16并发记录](../gcc-performance/k3-20261030/README.md)。

## 构建输入

源码及私有依赖按 GCC 官方 SHA-512 清单核验。主机编译器为修补后的 Clang/Clang++ 21.1.0，基础选项为 `-O2 -g1 -march=rv64gc -mabi=lp64d -fno-vectorize -fno-slp-vectorize` 并加载 StackObject 插件。配置采用 C-only，关闭 bootstrap、multilib、NLS，无 ISL，使用系统 zlib；不执行系统安装。

xgcc 使用首个 `-B` 选择同目录 cc1，原生链接另通过系统 GCC 目录查找 CRT/libgcc。不能省略首个 `-B` 而误用系统 cc1。

## 适配补丁

| 补丁 | 作用 |
|---|---|
| [0001](patches/0001-gcc-heap-transient-buffers.patch) | specs 路径改为作用域内堆缓冲区；`_Pragma` 文本在输入缓冲区弹出后释放 |
| [0002](patches/0002-gcc-thread-local-heap-alloca.patch) | 在 `CHIMERA_GCC_HEAP_ALLOCA` 下使用线程局部分配链与 ASTRDUP 状态，检查长度加法溢出 |
| [0003](patches/0003-gcc-demangler-disable-vla.patch) | 实验宏下关闭 demangler 的 `CP_DYNAMIC_ARRAYS`，使用已有 alloca 回退 |
| [0004](patches/0004-mpfr-tsprintf-thousands-test.patch) | 按 MPFR 官方修正更新旧 glibc 千位分隔符测试期望，不改库实现 |

前三项按顺序应用于对应 GCC 15.2.0 源树；第四项用于其 MPFR 测试。GNU 堆式 alloca 候选增加 `-DUSE_C_ALLOCA -DCHIMERA_GCC_HEAP_ALLOCA -DSTACK_DIRECTION=-1`。未开启实验宏时保留上游分支，线程局部分配链也不使整个 GCC 成为线程安全库。

后续候选还使用 `-fno-optimize-sibling-calls`、GMP `malloc-reentrant`、`MPFR_ALLOCA_MAX=0` 和 `-mllvm -enable-shrink-wrap=false`，分别处理尾递归证明缺口、私有临时区及延迟建帧。`REGEX_MALLOC` 候选使用 regex 已有堆分配分支。这些工作负载适配不放宽检查器规则，也不改变 GCC 根据命令行生成 RVV 目标代码的能力。

## 已记录的检查

[分配器测试](tests/allocator-test.c)需与修补后的 libiberty 编译，验证两个线程各1000轮分配、嵌套调用和字符串复制，以及超大尺寸请求拒绝；它不是可独立链接的单文件测试。

历史候选的 GMP 上游175项、libiberty 解码858项及其他47条 PASS 均通过。MPFR 的旧 `tsprintf` 失败按官方补丁修正后 check 返回0，修正前后 GCC ELF 身份一致。早期未通过的候选和12GiB准备 OOM日志分别保留，不能因后续候选成功而改写其结果。

heap-entryframes 的 xgcc/cc1曾通过 conservative strict；2026-10-30的性能记录采用固定版本和 `assume-scalar-independent` 范围，两者不是同一份检查凭证。新构建须分别重新检查两个 ELF、生成匹配 Workspace，再验证真实迁移和运行结果。
