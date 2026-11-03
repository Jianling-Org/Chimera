# K3 GCC：同一批16个编译进程从8核扩展到16核

之前的[GCC功能验收](../gcc-validation/k3-20261029/README.md)和[同-j16性能对照](../gcc-performance/k3-20261030/README.md)已经通过，范围是固定Chimera `578ab8321`、内核 `6.18.3-chimera-d02cd7352`、已准备的GCC/Workspace和 `assume-scalar-independent` 条件。此脚本复用这些工件，另建演示输出，不修改或重跑旧验收。

准确说是16个并发 `cc1` 编译进程，各主要使用一个工作线程；上级 `xgcc` 进程也会显示在htop中。脚本不会伪造16个忙线程。

## 运行

需要在原K3以root运行，脚本和 `run-demo.sh` 放在同一目录。标准库Python即可，其余依赖来自已验收目录，不能在另一台普通Linux机器直接运行。

终端1先打开：

```sh
htop
```

按F4输入 `cc1`，便于只看16个实际工作的编译器；需要时通过F2的列设置显示CPU/Processor编号。顶部同时显示16个核的利用率。

终端2：

```sh
bash /root/chimera-gcc-demo-tools-v1/run-demo.sh --check
bash /root/chimera-gcc-demo-tools-v1/run-demo.sh
```

`--check` 只读检查身份、78项receipt和资源，不编译。如果4.2独立审计或其他Chimera任务仍在运行，会明确拒绝启动。请等当前任务结束，不要并发运行本演示。

流程先串行生成一个原生参考对象，随后输出 `PHASE1` 才进入16进程演示。你会看到：

1. 同一批16个 `cc1` 完成真实bootstrap/Runtime初始化，在演示自身的 `AllowedCPUs=0-7` 中编译，默认保留15秒供观察。
2. 脚本将**仅本演示单元**的cpuset扩展为 `0-15`。原 `prefer-x100` 自动策略继续运行，原进程经Runtime ACK和物理跨VLEN提交分布到两簇。这里没有重启第二批编译器，也没有通过手工迁移接口搬运进程。
3. 16项编译退出0，全部对象SHA与新原生参考逐字节相同；再链接实际编译对象，在静态X100/A100上执行，与独立Python无符号整数参考逐项核对输出。

任务是有限的编译工作，不保证每一瞬间16核都满载；`htop` 是观察工具，正确性和真实迁移以保留的证据为准。默认输入6144个函数，若编译结束过快、没覆盖展示窗口，脚本会失败保留证据，并明确提示扩大输入，不会打印虚假的PASS。可以显式调整：

```sh
bash /root/chimera-gcc-demo-tools-v1/run-demo.sh --functions 8192 --hold-seconds 20
```

输出根默认为 `/root/chimera-gcc-live-demo/UTC时间-随机ID/`。里面有实际 `cc1-pids.csv`，也可另开终端：

```sh
htop -p "$(cat /root/chimera-gcc-live-demo/本次目录/cc1-pids.csv)"
```

## PASS的含义

除16项编译和产物/数值检查外，脚本还要求两阶段都观测到同批16个PID，第一阶段只在CPU0–7并覆盖8核，第二阶段实际编译进程覆盖CPU0–15且同一采样周期存在两簇工作；必须有原 `cc1` 在放开cpuset后产生成功rawACK和物理跨簇提交，逐方向与全局计数精确一致。只有放开16核、没有真实迁移，不会通过。PID/starttime/ELF、真实初始化和处理函数、九项账本、timeout、原kernel和健康、trace丢失及私有probe清理都保留。初始化只是在放行源码前取得真实见证，不是手工设置ready。

这是演示，不是新的性能成绩或完整验收替代。详细trace耗时不能用作推理/编译吞吐；离散BKOPS0/1/2及精确status1/2维护消息按原授权单列记录，不推断持续时长或因果损失，其他故障仍失败。

单元限制12GiB/10GiB high、0swap、15分钟，启动需12GiB MemAvailable和6GiB可用磁盘。Ctrl+C只停止本演示单元，退出钩子先记录真实资源，再清理本次私有探针；失败证据与输出不自动删除。整个演示不写频率、电源、驱动、内核日志级别，不改生产Runtime或分析器。

## 离线检查

```sh
python -B -m unittest discover -s tests -p test_gcc_live_demo.py -v
```

这些检查拒绝无迁移、错误PID/CPU、计数不一致、timeout/账本异常、错误对象和错误数值；核对输入及整数参考与已验收fixture一致。它们不声称已在K3实际验证新cpuset分阶段演示。首次板端完整演示是否通过，以新输出的 `result.json`、`unit.resources.json` 和 `trace-cleanup.json` 为准。
