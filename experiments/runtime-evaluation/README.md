# K3 初始化开销与模型迁移复测

本目录为性能报告3.2和4.1提供新的复测入口。脚本补齐了测量和自动验收流程，尚未产生新的K3测量结果；旧报告的初始化耗时、123轮模型结果及迁移次数仍属于历史记录。

## 两项测试

| 入口 | 测试内容 | 输出 |
|---|---|---|
| `measure_startup.py` | cc1版本查询、极小C编译、bsearch/fork/mmap三个实际Kbuild任务；原生与bootstrap交替三对 | 每次monotonic时窗、产物SHA、三次中位数、增加时间及比例 |
| `run_llama_acceptance.py` | 七档线程数、十次16线程重复、至少7200秒混合线程负载 | 本次原生PPL、逐轮PPL、实际轮数、raw ACK与CPU迁移、ready、账本及健康记录 |

模型测试采用固定TinyLlama输入参数：context/batch512、ubatch128、chunks1、seed1234，`-t`与`-tb`同步为2/4/8/12/16/24/32。新原生参考固定CPU0–7、16线程，预先声明PPL绝对容差0.01。每个自动轮次要求实际主线程迁移和完整线程ready旁证，整套测试要求两个方向均有与成功ACK关联的物理CPU提交。

混合阶段累计每条实际应用命令的monotonic运行时间达到7200秒，包含命令启动、bootstrap与迁移，排除冷却、SHA和轮间核验。轮数随实际任务耗时变化，不固定为106轮或总计123轮。这里记录的是带详细探针的功能验收时间，不用于推理吞吐或单次迁移时延。

## 准备输入

使用已完成应用准备、静态准入和bootstrap注册的K3环境。新脚本不重新编译生产Runtime、不生成Workspace，也不改变频率、电源或存储驱动。按[应用示例](../../examples/applications/llama-cpp/reference-v32/README.md)和[GCC验收记录](../gcc-validation/k3-20261029/README.md)准备工件及注册表。

复制对应的`*.example.json`到独立目录，填写实际路径、SHA256、源码提交、内核版本、Workspace凭据SHA及receipt行数。示例中的`REPLACE_`值不能直接运行。模型、GCC、bootstrap DSO、registry、Profile和Workspace必须来自同一已验证环境；使用条件Profile时，保留其assume-scalar-independent及libc标量叶函数等条件。

4.1协议固定模型SHA为`6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca`，语料SHA为`b62ca0b765cc22e0f1ab25b0a53ae2b04c5a462650c49bbb9b18c315c1c18033`。脚本不会下载模型；改变输入应另立协议，不复用本次4.1结论。

初始化测试还要固定内核源码和已prepare的Kbuild输出树。先为这两个只读输入树生成清单，把清单文件本身作为配置中的asset填写SHA：

```sh
python experiments/runtime-evaluation/evaluation_common.py --inventory /path/to/kernel-source /new/source-inputs.json
python experiments/runtime-evaluation/evaluation_common.py --inventory /path/to/prepared-seed /new/seed-inputs.json
```

清单必须放在输入树之外；运行前后都会重新核对文件内容和符号链接。编译使用的外部生成头文件也应列入输入清单。按实际保存的Kbuild命令填写三个任务的argv，替换旧wrapper为所固定的xgcc，保留相同`-B`和编译选项，移除依赖文件写入及shell后处理，把唯一编译输出改为`{output}`。不通过shell解释argv，不修改原源码/seed树。极小C输入单独作为asset，使用stdin传给编译器。

原生和bootstrap使用相同的argv、cwd、stdin、输出路径、TLS设置及CPU0–7约束。每项先做原生/初始化两次不计分探测，bootstrap探测必须记录指定GCC/cc1的实际initialized日志，不能把单纯加载preload当成初始化成功。正式三对测量关闭该日志，交替先后顺序。产物和stdout必须与原生探测一致，全程迁移计数增量和退出账本均为零。

注册、工件准备、清单生成及SHA核验均在正式计时之外。输入树应保持只读，结果写入全新的实验目录。

## 查看计划与运行

```sh
python experiments/runtime-evaluation/measure_startup.py --config /run/startup.json --plan
python experiments/runtime-evaluation/run_llama_acceptance.py --config /run/llama.json --plan

sudo python experiments/runtime-evaluation/measure_startup.py --config /run/startup.json --output /new/startup-run --run
sudo python experiments/runtime-evaluation/run_llama_acceptance.py --config /run/llama.json --output /new/llama-run --run
```

`--plan`只检查配置和列出协议，不运行硬件负载。`--run`创建唯一有界systemd单元，使用12GiB上限、10GiB high、0swap；初始化测试最长45分钟，模型验收最长4小时，单条命令最长600秒。运行目录已存在时拒绝覆盖；没有自动重试。

结果目录不能位于被测源码、prepared seed或Workspace内。模型探针使用本次单元独有的命名空间；正常退出、终止或OOM后，ExecStopPost都核对并清理该命名空间，不清除其他任务的探针。清理失败不会报告测试通过。

运行前要求userspace频率为X100 2.2GHz/A100 1.8GHz，只读核对而不设置频率。空闲130秒建立温度基线，各轮开始不超过基线+3°C。需要至少6GiB剩余空间，并保留原始内核字节、连续序号、SHA、begin/end控制记录及30秒健康采样。

本复测协议将实际BKOPS0/1/2以及精确匹配的c0e00000.ufshc status1/2维护消息单列保留。状态3/未知、critical health非零、I/O错误、其他告警或证据丢失仍失败。离散健康样本不能推断维护持续时长或因果损失。该规则只用于新实验，不回写旧123轮结果或旧GCC验收策略。

模型自动启动器使用与生产bootstrap入口相同的`inherit:PID`偏好登记，等待应用runtime在exec后自行发布ready；它不代替应用设置ready。详细trace使用已归档的私有tracefs后端，不改动归档代码。线程采样周期50毫秒，包含PID/TID starttime、实际CPU、允许CPU、ready、温度、频率及整个测试cgroup内存；这些是验收旁证。

## 结果判定

逐条命令保存真实返回码、stdout/stderr及monotonic窗口；失败文件原样保留。模型PPL必须来自本轮新日志中唯一的Final estimate行，拒绝缺失、NaN/Inf及超容差结果。原生不允许迁移，自动组的计数增量须与所观测TID的成功ACK及物理CPU提交逐方向相符，退出后九项账本归零且迁移超时无增量。

`result.json`是单元内执行结果；只有外层`completion.json`同时核对实际`success/exited/0`、零swap、零OOM以及内部全部检查通过，才能报告本次复测成功。整个套件的内存峰值来自`unit.resources.json`，不是独立隔离后的单轮峰值。`evidence-sha256.json`索引所有保留证据。

## 离线检查

```sh
python -B -m unittest discover -s tests -p test_runtime_evaluation.py -v
```

离线检查覆盖计时边界、失败保存、初始化证据、PPL、线程/ACK判定和配置约束，不使用K3 proc接口，也不生成硬件通过记录。报告修改建议见[补充脚本后的修改说明](../../docs/validation/performance-report-update.zh-CN.md)。本目录新编写脚本和对应离线测试按[Apache-2.0](../../LICENSES/Apache-2.0.txt)分发，归档后端的原许可继续适用。
