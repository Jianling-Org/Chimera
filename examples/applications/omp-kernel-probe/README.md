# OpenMP 算子探针

本目录是仓库自带的最小浮点 GEMV 应用，用于观察 OpenMP 并行区、算子调用、分块工作量和线程迁移。驱动在 [probe.c](probe.c)，接口在 [kernel.h](kernel.h)，算子在 [kernel.c](kernel.c)。它不包含量化模型或外部输入，矩阵在程序内确定性初始化。

## 构建与产物检查

在 Linux / RISC-V64 / RVV 目标上，需要支持目标的 Clang、LLVM libomp 头文件和库以及目标 objdump。在本目录运行：

```bash
CC=clang bash build-k3.sh
ldd ./omp-kernel-probe
objdump -d --disassemble=probe_kernel ./omp-kernel-probe
objdump -d ./omp-kernel-probe | grep __kmpc_fork_call
```

[build-k3.sh](build-k3.sh) 分别编译驱动与算子，禁用 LTO 以保留真实算子调用；只有算子启用 `-ffast-math`，驱动验证保留通常的浮点语义。链接应使用 libomp，反汇编应确认 `probe_kernel` 中确实有 RVV 指令。允许向量化的参数不能证明产物已生成 RVV。

预期路径是应用 `__kmpc_fork_call@plt` → libomp 调度/微任务调用 → 编译器生成的 outlined 函数 → `probe_kernel`。具体路径以使用的 libomp 和反汇编为准；libgomp 程序不能直接作为同一调用链的证据。

## 原生输入与运行矩阵

```bash
./omp-kernel-probe --mode serial --threads 1 --rounds 256 --passes 100 > serial.native.jsonl
./omp-kernel-probe --mode omp --schedule static --threads 16 --rounds 256 --passes 100 > static.native.jsonl
./omp-kernel-probe --mode omp --schedule dynamic --threads 16 --rounds 256 --passes 100 > dynamic.native.jsonl
```

默认 `mode=omp`、`schedule=dynamic`、`threads=16`、`rows=1024`、`cols=4096`、`chunk=8`、`rounds=32`、`passes=20`，线程数上限 256。上例显式增加 rounds/passes 以提供观察窗口，先试运行再选择适合机器的时长。比较时保持尺寸、rounds、数据和线程安排一致。

## 检查、必要重编与准备

从仓库 [RVV Profile](../../platforms/k3/linux-riscv64-rvv-1024-256-bidirectional.toml) 选择合适场景，配置 scalar_root、翻译器、目标工具及依赖根，确保包含此次使用的 libomp。以下在本目录执行，`PROFILE` 使用绝对路径：

```bash
ELF="$PWD/omp-kernel-probe"
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" --strict
```

发现问题时，用新目录生成 metadata 计划并清洁重编两个源文件；脚本接受 `CC` 覆盖：

```bash
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" \
  --rebuild-stage metadata --rebuild-dir "$METADATA_PLAN"
CC="$METADATA_PLAN/cc" bash build-k3.sh
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" \
  --rebuild-stage gate --rebuild-dir "$GATE_PLAN"
CC="$GATE_PLAN/cc" bash build-k3.sh
chimera-pkg check-elf --profile "$PROFILE" --input "$ELF" --strict
```

metadata 已通过时可结束修复；SVF/function-pointer 决策需对应工具链，不能强行改为 gate。计划说明见 [集成 CLI](../../../doc/integration/cli.md#固定重编计划)，安全细节见 [安全点文档](../../../doc/developer/architecture/safepoints/README.md)。

严格检查通过后准备、打包：

```bash
chimera-pkg --debug prepare --profile "$PROFILE" --input "$ELF" --workspace omp-kernel-probe
chimera-pkg workspace pack --workspace omp-kernel-probe --output omp-kernel-probe.workspace
```

目标机独立安装同内容 ELF 和目标解析依赖，再安装 `.workspace`。本应用没有需声明的外部 resources；ELF 或依赖变化后重新检查与准备。

## Chimera 运行与线程选择

```bash
chimera-user verify --workspace omp-kernel-probe
chimera-user register --workspace omp-kernel-probe --input "$ELF"
chimera-user --debug run --workspace omp-kernel-probe --input "$ELF" -- \
  --mode omp --schedule dynamic --threads 16 --rounds 256 --passes 100 \
  > dynamic.chimera.stdout.log 2> dynamic.runtime.log &
PID=$!
```

从 JSON 的 `worker.tid` 识别实际计算线程，等待 Runtime ready 后在另一终端选择对应 TID：

```bash
chimera-user migrate --workspace omp-kernel-probe \
  --threads "$WORKER_TID" --direction 1024-to-256
```

`--parent-thread "$PID" --migration-count N` 按较大 TID 选择非主线程，不识别计算角色。serial 模式计算线程是主线程；`--mode omp --threads 1` 仍经过 OpenMP 并行区。不能把线程总数当作迁移计算线程数，也不能把提交成功当作完成 ACK。反向迁移先确认线程状态，再选对应 route。

## 日志口径

应用自身每行日志是 JSON 对象。Chimera 启动时还会向 stdout 写入 `parent_thread_id=<pid>` 通知，因此保留原始 `dynamic.chimera.stdout.log`，不要将整个文件作为 JSONL 解析；stderr 诊断另存于 `dynamic.runtime.log`。应用结束后可提取以 `{` 开头的应用记录用于统计：

```bash
grep '^{' dynamic.chimera.stdout.log > dynamic.chimera.jsonl
```

应用 JSON 字段如下：

| 记录或字段 | 含义 |
| --- | --- |
| `config` | pid、模式、尺寸、rounds、passes、请求线程数 |
| `pass.seconds` | 完整计算墙钟时间，含并行区及同步，不含初始化、验证和日志 |
| `pass.elements/checksum/valid` | 工作量与结果检查，valid 必须为 true |
| `worker.tid/ith/rows/chunks` | 线程身份、团队序号及工作量 |
| `worker.loop_seconds` | 分块循环墙钟时间，含调度与抢占，不是独占 CPU 时间 |
| `worker.finish_wait_seconds` | 每轮结尾显式 barrier 的累计等待时间 |
| `worker.cpu_begin/cpu_end` | pass 首尾核位置快照，不能证明期间未换核 |

线程时间相互重叠，不能相加当整体耗时；`finish_wait_seconds` 不含每轮开始 single 同步和并行区退出开销。静态分工按线程序号领取固定 chunk；动态分工每线程先处理一个 chunk，再从共享原子计数器领取。

## 验证与可比较范围

先核对所选 pass 的 `valid=true`、checksum 与工作量，再把 `worker.tid` 与 Runtime 事件关联。保留原生/Chimera 的相同参数、核分配、实际线程集合与稳定窗口，丢弃预热、发生迁移以及紧随其后的过渡 pass；独立重复并报告中位数与波动。全部计算线程迁移和部分迁移分别记录。

```text
翻译线程工作量占比 = 已确认翻译线程的 rows 之和 / 全部线程 rows 之和
整体耗时倍率 = Chimera 稳定 pass.seconds 中位数 / 原生稳定 pass.seconds 中位数
```

本探针重复使用同一浮点矩阵，省略完整计算图、量化打包和其他应用行为，结果仅适用于所测算子与条件。替换算子时同时调整初始化、参数及参考结果验证，保留统计口径。

[应用集成者指南](../../../doc/integration/README.md) · [应用使用者指南](../../../doc/user/README.md)
