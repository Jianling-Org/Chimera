# GCC 构建与准备记录

本文整理2026-10-15至21日的 GCC 标量候选、严格检查和 Workspace 准备结果。适配补丁见 [GCC 实验目录](../experiments/gcc-bootstrap/README.md)；2026-10-30的固定版本结果见[同16并发记录](../experiments/gcc-performance/k3-20261030/README.md)。不同候选的检查报告与性能数据分别保留。

## 构建输入

GCC 15.2.0 官方源码使用以下 SHA-512 核对：

```text
89047a2e07bd9da265b507b516ed3635adb17491c7f4f67cf090f0bd5b3fc7f2ee6e4cc4008beef7ca884b6b71dffe2bb652b21f01a702e17b468cca2d10b2de
```

gettext/GMP/MPFR/MPC 私有依赖使用 GCC 随附清单核验。主机编译器为修补后的 Clang/Clang++ 21.1.0，初始选项为 `-O2 -g1 -march=rv64gc -mabi=lp64d -fno-vectorize -fno-slp-vectorize`，加载 StackObject 插件。配置为 C-only，关闭 bootstrap、multilib、NLS，无 ISL，使用系统 zlib。

构建位于独立目录，不替换系统 GCC。xgcc 通过首个 `-B` 选择匹配的 cc1；原生链接测试另用系统 GCC 目录查找 CRT/libgcc。每次改变源码或编译选项后重新检查两个 ELF，不继承旧候选的通过结论。

## 标量候选与严格检查

| 候选 | 调整 | 已记录结果 |
|---|---|---|
| stack-scalar | 关闭主机自动向量化，携带 StackObject 元数据 | 构建1050.26秒；两个显式动态缓冲区修正后，xgcc仍有241项继承发现 |
| heap-scalar | GNU `USE_C_ALLOCA`、线程局部分配链、demangler 取消 VLA | 构建1055.31秒；xgcc conservative strict零发现；cc1在6056.71秒后失败，36项本地、1169项继承、93项待证明 |
| heap-notail | 禁用尾调用，GMP使用 `malloc-reentrant` | 构建1050.26秒；xgcc在115.48秒通过；cc1在5068.25秒后仍有123项继承、26个待证明函数 |
| heap-entryframes | `MPFR_ALLOCA_MAX=0`，关闭 shrink wrapping | 构建1055.28秒；xgcc/cc1分别在115.54/4682.89秒通过 conservative strict，零发现、零待证明 |
| entryframes-regexmalloc | 在 release 重新准入后启用 `REGEX_MALLOC` | 消除 libiberty regex 动态 SP 帧候选，后续完成正式 cc1 Workspace |

heap-notail 的26个待证明函数包括23个 MPFR 函数，以及 GCC 的 `tree_to_poly_int64`、`tree_to_poly_uint64` 和 `check_load_store_for_partial_vectors` 中一个 lambda。部分固定帧在尾递归或延迟建帧路径上仍有证明缺口，不能将全部 finding 都解释成源码 VLA。

GMP 上游175项测试通过。libiberty 解码测试858项通过，其他日志47条 PASS。MPFR 首次 check 为179通过、3跳过、1失败；唯一失败是旧 `tsprintf` 千位分隔符期望，按官方 patch01 修正测试后 check 返回0，两个 GCC ELF 的 SHA 不变。对应补丁只修改测试，不改变库实现。

heap-entryframes 的准入 ELF SHA-256：

- xgcc：`47899daf51ea563d4c107019e1c6b019efefdfc08dc56e10421b6d4d2fc49bf1`
- cc1：`fd6cc6047b55842b56400282944a1ab3d5c4234a84fee0fd14eca6091bc563b9`

这些是当时候选的身份，不替代后续重编版本的记录；2026-10-30实验采用的范围另见性能报告。

## cc1 准备阶段的内存问题

| 轮次 | 结果与定位 |
|---|---|
| v1 | 2210.05秒后被12GiB cgroup OOM终止，退出-9 |
| v2 | 允许8GiB临时交换后，仍在7120.13秒 OOM |
| v3 | 释放 SafetyAnalysisResult 内层工作图后，6570.12秒仍 OOM；安全分析已结束，但逐指令记录使父进程保留约9GiB RSS |
| v4 | 改用精确安全地址的 uint64 表，翻译前父进程降至159396KiB，随后约138672KiB；之后 JAL 探测因7.9GiB tmpfs空间不足失败 |
| v5 | 临时探测文件移到磁盘目录继续处理，仍保留独立轮次和原失败日志 |
| regexmalloc release-native-v2 | 2026-10-21正式管线返回0，9660.85秒；重做安全分析、补丁与发布校验，复用文件先核对 SHA |

内存修正只改变跨阶段保留的数据表示。安全记录、策略、导出诊断和补丁集合保持原值；弱引用回归确认工作图可回收，真实 DSO 测试核对完整记录与压缩地址两条路径的补丁字节和计数。

早期准备使用过临时交换，退出后已关闭；正式性能计时不复用带交换的准备时间。Workspace 发布也不表示已通过运行时迁移。

## 编译链运行

make 严格检查31.21秒、prepare 496.72秒。首轮64目标编译只完成15个，make退出2，GCC报告 `Interrupted system call`；418次 proposal 全部 NACK，真实迁移为零。退出账本归零不能把该轮变成迁移或性能通过。

信号安装增加 `SA_RESTART`，并用真实 fork/signal/waitpid 回归验证等待恢复。安全源指令随后改走既有 route/map/save/ACK/exit-trap 生命周期；缺表和 translated body 拒绝仍保留。嵌套信号帧故障另见[故障记录](BOOTSTRAP-NESTED-SIGNAL-FAILURE.zh-CN.md)。

## 证据位置

历史记录位于独立 GCC 根 `/root/kaiwen/chimera-gcc-bootstrap-build`，包括：

- `evidence/demangler-heap/`、`heap-notail/`、`heap-entryframes/`：候选构建与检查。
- `evidence/native-preparation-entryframes-*/`：原准备失败、资源和阶段日志。
- `evidence/final-pipeline-status.json`、`cc1-final-pipeline/`：正式发布状态。
- `evidence/make-release-native/`：make 准备结果。

这些路径是历史证据位置，不是新机器上可直接执行的构建目录。新任务按[GCC 工作流](developer/gcc-workflow.md)选择实际输入和新输出目录。
