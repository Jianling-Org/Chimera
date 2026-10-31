# make 嵌套信号帧故障（2026-10-21）

当前为根因定位及候选修复，尚未通过最终验收，没有有效的异构内核构建加速比。

用户已明确允许部署并重启。候选 `6.18.3-chimera-bootstrap-exec-signal-depth-v1` 已成功启动，十轮真实嵌套 ACK 拒绝与 fork/exec/failed-exec 继承测试通过；正常 64 对象迁移预检正在新证据 `evidence/signal-depth-v1` 下运行。不能以拒绝测试通过代替正常迁移验收。下方“未安装”均为部署前过程记录。

候选 Image 已构建成功，退出跟踪确认 `exit_group(0)`，版本 `6.18.3-chimera-bootstrap-exec-signal-depth-v1`，SHA-256 为 `36132878493371bb93357c35bc09359222a5c982b75f6165e4792a861cb78368`。正在构建匹配版本模块，尚未安装或重启。期间磁盘保护两次暂停；完成输出及旧 llama Workspace 均完整归档并逐成员 SHA 核验后，才回收板端可恢复文件。原启动镜像保留。

运行时无 SHA 后，Release 完整构建仍出现 make 的 `bad frame in __riscv_sys_rt_sigreturn`。独立 debug 构建成功、两子树十轮成功均不能证明故障消失。Release 重新注册后先在 9.45 秒复现，再在带 raw syscall 跟踪的一轮中于 322.79 秒退出 2，保留两个 core。

证据位于板端 GCC 根的 `evidence/kernel-full-release-core-v{2,3}`。板端 `core_uses_pid=1`，转储名是 `core.<PID>`，不能只查名为 `core` 的文件。GDB 显示 make 位于 jobserver 的 `pselect` 等待路径。

PID 701465 的记录给出了完整顺序：

1. 外层信号帧 `0x3fdd058d40` 保存向量 magic `0x53465457`、大小 `0x1038`、vlenb 128。
2. 内层帧 `0x3fdd0578c0` 在迁移后于 CPU0 返回，当前帧已清为 END，状态为 `0x200004020`（VS 关闭）。
3. 翻译 trap 返回目标组 original。
4. 外层帧随后返回，仍携带原有向量记录，但 VS 仍关闭，内核拒绝该帧。向量记录头、reserved 和尾部 END 未见损坏。

运行时只能清除自己的当前帧，不能因此使更早的应用信号帧失效。候选在内核跟踪活动 native 信号帧数量，并在 ACK 提交前要求深度恰为 1。拒绝发生在迁移 CPU 或向量状态之前，沿现有失败路径释放 pending 和 reservation，不放宽 sigreturn 校验。

生命周期审查：正常返回递减；成功 exec 清零；fork 继承相同用户栈上的活动帧；新 clone 栈及内核线程清零；计数饱和时保持拒绝。`siglongjmp` 跳过 sigreturn 会使计数保守偏大，进而阻止后续迁移直到 exec。这是候选的已知限制，尚需评估，不能声称已经解决所有信号控制流。

候选仅编译，不安装、不重启。板端内核证据目录为 `bootstrap-evidence/signal-depth-candidate-v1`，包含原文件备份、逐项 SHA、候选补丁及编译日志。宿主 libbpf 的三个只读字符串指针遇到 const 正确性错误；显式 GNU11 和 Clang21 均未消除错误，不能简单归因于默认 C23。现以独立 `host-const.patch` 将三个结果指针改为 `const char *`，不改字符串内容或运行逻辑，保留全部严格告警；此前失败日志均保留。

后续必须审查计数生命周期、失败回滚及账本，完成候选编译和嵌套信号回归，再按授权决定部署；部署后重跑曾失败的完整构建及最终迁移验收。上述故障复现轮次均不计入性能数据。
