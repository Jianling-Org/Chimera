# K3 初始化开销与模型迁移复测

初始化复测及两套v5模型重测已完成实际运行、独立全raw审计、本地必要原字节核验和中文报告。结果与SHA见[2026-11-02归档](k3-20261102/README.zh-CN.md)。4.1/4.2各291自动轮、274混合轮，真实应用混合时间分别7231.521526972298/7220.839470380568秒；按用户确认的相对PPL2%验收。数值差异原因仍未定位，旧所有失败原样保留，不混旧123/66。以下协议和入口供新独立输出使用，禁止覆盖归档。

## 测试入口

| 入口 | 测试内容 | 输出 |
|---|---|---|
| `measure_startup.py` | cc1版本查询、极小C编译、bsearch/fork/mmap三个实际Kbuild任务；原生与bootstrap交替三对 | 每次monotonic时窗、产物SHA、三次中位数、增加时间及比例 |
| `run_llama_acceptance.py` | 七档线程数、十次16线程重复、至少7200秒混合线程负载 | 本次原生PPL、逐轮PPL、实际轮数、raw ACK与CPU迁移、ready、账本及健康记录 |

模型驱动按两个构建协议分别建立原生参考，不合并统计。第四版示例保留1%相对PPL容差，第五版使用独立配置与输出：

| 配置 | 构建与参考 | PPL判据 |
| --- | --- | --- |
| `llama.example.json` | 4.1应用适配构建，原生CPU0–7、16线程 | 相对误差不超过0.01，即1% |
| `llama-scalar.example.json` | 4.2标量控制构建，原生CPU8–15、16线程 | 相对误差不超过0.01，即1% |
| `llama-ppl2pct.example.json` | 4.1同一应用构建及原默认参数，运行协议v5 | 相对误差不超过0.02，即2% |
| `llama-scalar-ppl2pct.example.json` | 4.2标量控制构建及原默认参数，运行协议v5 | 相对误差不超过0.02，即2% |

第四版完整测试在混合阶段出现PPL12.6510，相对本次原生参考12.7928偏差约1.1084%，超过1%，该次失败保留。用户随后确认“改为2%新协议重测，报告披露并保留旧失败”。第五版将授权记录作为SHA绑定输入，两套构建均使用新原生参考及2%判据，原线程矩阵、十次重复、7200实际应用秒、迁移、账本、timeout及健康要求不变。原数值差异原因尚未定位；报告须写明这是验收容差调整，不能写成数值问题已修复。关闭FlashAttention的诊断及其超时不计入第五版，模型命令恢复原默认参数。

第二版4.1原生参考PPL为12.7928，自动t2为12.7184，超过原绝对容差0.01。随后同一ELF在静态X100和A100的原生对照分别得到12.7928和12.7184，2线程与16线程一致。用户接受这一偏差，第三版将PPL判据改为1%相对误差，迁移见证、账本、timeout和健康判据保留。旧版本仍使用各自原阈值，失败记录不改写；新配置和结果独立保存，并在报告注明阈值调整依据。

v2至v5协议的自动组均从CPU0–7启动，以prefer-a100登记，由实际Runtime发布ready并允许双向迁移。配置必须显式填写`automatic_preference`，不能在同一协议标识下改变策略。prefer-a100沿用向量负载的A100优先分配；原prefer-x100先填X100的8个逻辑槽位，不保证低并发主线程跨簇迁移。v1仍保留其prefer-x100含义，旧失败结果不改写，各版数据独立保留。新版继续要求每轮真实主线程迁移，未发生迁移仍失败。

第四、第五版使用`thread_evidence=kernel-lifecycle-v2`，以TGID、线程创建/退出、CLONE_THREAD及starttime确定完整线程集合。50毫秒采样会遗漏退出前出现的短线程，不能仅据采样TID过滤全局迁移记录。初始化发布和当前可接受迁移信号也须分开核验：所有归属线程须有实际ready/exec-ready及处理函数见证，每次实际提交须有此前内核`hmp_runtime_ready`正返回，再与raw ACK、物理CPU及全局方向增量逐项对应。Runtime在处理转换信号时会临时屏蔽5和41，不能要求在处理函数内或退出时始终解屏蔽。原始采样布尔值保留，新初始化核验另存文件。

4.2使用与4.1相同的固定模型、语料和当前Chimera版本，区别是应用编译配置与参考CPU。这是新的构建对照，不重现旧4.2的软件与输入差异，也不替代历史make启动继承测试。报告须标明协议版本及prefer-a100策略。

原生组通过已核对SHA的[标量syscall启动器](../gcc-performance/k3-20261030/harness/native-launch-image-v3.c)选择静态簇，再exec模型ELF，只使用`x100`和`a100`两种模式。该BSP会把未管理任务的单核亲和性扩展到整个HMP簇，普通`taskset -c 8`也不能代替A100静态选择入口。脚本核对两簇在线及cgroup实际可用CPU，采集器核对原生线程实际CPU、完整簇mask、preference none及零迁移。模型两组固定相同的`glibc.rtld.optional_static_tls=65536`，不继承其他GLIBC_TUNABLES设置。自动组使用自己的ready登记流程，不使用上述启动器中绑定GCC环境的auto模式。

模型测试采用固定TinyLlama输入参数：context/batch512、ubatch128、chunks1、seed1234，`-t`与`-tb`同步为2/4/8/12/16/24/32。每个自动轮次要求实际主线程迁移和完整线程ready旁证，整套测试要求两个方向均有与成功ACK关联的物理CPU提交。

混合阶段累计每条实际应用命令的monotonic运行时间达到7200秒，包含命令启动、bootstrap与迁移，排除冷却、SHA和轮间核验。轮数随实际任务耗时变化，不固定为106轮或总计123轮。这里记录的是带详细探针的功能验收时间，不用于推理吞吐或单次迁移时延。

## 准备输入

使用已完成应用准备、静态准入和bootstrap注册的K3环境。新脚本不重新编译生产Runtime、不生成Workspace，也不改变频率、电源或存储驱动。按[应用示例](../../examples/applications/llama-cpp/reference-v32/README.md)和[GCC验收记录](../gcc-validation/k3-20261029/README.md)准备工件及注册表。

复制对应的`*.example.json`到独立目录，填写实际路径、SHA256、源码提交、内核版本、Workspace凭据SHA及receipt行数。示例中的`REPLACE_`值不能直接运行。模型、GCC、bootstrap DSO、registry、Profile和Workspace必须来自同一已验证环境；使用条件Profile时，保留其assume-scalar-independent及libc标量叶函数等条件。

依赖库也须与实际原生进程一致。本次恢复曾在prepare和静态verify通过后，因标量包的libstdc++比目标机版本更新，在bootstrap-register实际加载校验中缺少符号而失败。核对主程序的实际动态库解析路径、版本及SHA，与Workspace每个dependency的来源逐项对应；标量包不能直接替代另一个版本的原生库。使用原生依赖方案时，在独立空scalar_root下重新严格检查和prepare，再完成bootstrap-register。原Profile中绑定某个libc SHA的叶函数合同不能用于另一个SHA的libc。对于不再选择的标量库，移除其不适用的例外并重新检查；不向系统库添加新的合同，也不替换合同摘要来获得准入。

4.1协议固定模型SHA为`6d58c8fbdaa822b004d7ba473f9b9ad4d1ef7c2dd2c4cf9f9856451aa44bf0ca`，语料SHA为`b62ca0b765cc22e0f1ab25b0a53ae2b04c5a462650c49bbb9b18c315c1c18033`。脚本不会下载模型；改变输入应另立协议，不复用本次4.1结论。

### 4.2标量控制构建

在新llama.cpp源码副本中，按原顺序应用[两个RVV兼容补丁](../../examples/applications/llama-cpp/patch/README.md)。在根CMakeLists所有目标创建完成后加入：

```cmake
include("/absolute/Chimera/examples/applications/llama-cpp/scalar-control.cmake")
```

该片段对llama、common、cpp-httplib及perplexity控制目标追加`-march=rv64gc -fno-vectorize -fno-slp-vectorize`，保留ggml目标的显式RVV。配置时同时把C、C++的Release选项固定为`-O3 -DNDEBUG -fno-vectorize -fno-slp-vectorize`，关闭全部目标的自动循环/SLP向量化。使用patched Clang、StackObject及检查结果要求的gate配置，OpenMP开启、OpenSSL关闭，并导出`compile_commands.json`。不要在原暂停源码或旧构建目录上修改、增量重编。

构建后核对实际反汇编与编译命令，确认控制目标没有被后续优化参数重新启用向量化，ggml中仍存在显式RVV指令。生成与最终ELF绑定的命令审计记录：

```sh
python experiments/runtime-evaluation/llama_build.py \
  --elf /new/inputs/llama-perplexity \
  --scalar-control /absolute/Chimera/examples/applications/llama-cpp/scalar-control.cmake \
  --compile-commands /new/build/compile_commands.json \
  --source-commit CHIMERA_COMMIT_40_HEX --output /new/build-record.json
```

该记录只核对编译选项和输入摘要。最终ELF仍须严格check通过，重新prepare，并完成官方verify、注册及实际迁移测试。在`llama-scalar.example.json`中分别绑定scalar-control片段、编译命令和该记录的SHA；运行前后会重算命令审计并核对ELF绑定。

`patches/llama-cpp-rvv-migration-call-boundaries-4fc4ec554.patch`是本次恢复工件使用的应用适配候选：在两个RVV兼容补丁后应用，为5个RVV helper保留调用边界，RISC-V FlashAttention使用已有非tiled路径。它改变了应用的编译/执行配置，尚未完成本次板端验收；不加入通用补丁series，不将旧结果归于该候选。

在上述补丁后应用`patches/llama-cpp-q8-k-zero-call-boundary-4fc4ec554.patch`：只把Q8_K零块分支的两个memset改为局部volatile清零，保留全部量化算术及标量fallback。该修正用于消除跨外部memset调用的活跃向量栈，未增加库例外。原实现与候选在VLEN256/1024两簇的144项原生字节及保护区对照已通过；这不替代最终ELF严格检查、prepare或模型迁移验收。

初始化测试还要固定内核源码和已prepare的Kbuild输出树。先为这两个只读输入树生成清单，把清单文件本身作为配置中的asset填写SHA：

```sh
python experiments/runtime-evaluation/evaluation_common.py --inventory /path/to/kernel-source /new/source-inputs.json
python experiments/runtime-evaluation/evaluation_common.py --inventory /path/to/prepared-seed /new/seed-inputs.json
```

清单必须放在输入树之外；运行前后都会重新核对文件内容和符号链接。编译使用的外部生成头文件也应列入输入清单。按实际保存的Kbuild命令填写三个任务的argv，替换旧wrapper为所固定的xgcc，保留相同`-B`和编译选项，移除依赖文件写入及shell后处理，把唯一编译输出改为`{output}`。不通过shell解释argv，不修改原源码/seed树。极小C输入单独作为asset，使用stdin传给编译器。

原生和bootstrap使用相同的argv、cwd、stdin、输出路径、TLS设置及CPU0–7约束。每项先做原生/初始化两次不计分探测，bootstrap探测必须记录指定GCC/cc1的实际initialized日志，不能把单纯加载preload当成初始化成功。正式三对测量关闭该日志，交替先后顺序。产物和stdout必须与原生探测一致，全程迁移计数增量和退出账本均为零。

注册、工件准备、清单生成及SHA核验均在正式计时之外。输入树应保持只读，结果写入全新的实验目录。

### 第四版线程证据输入

在目标K3上从实际内核BTF记录布局，并绑定被测Runtime和内核的ready判定源码：

```sh
python experiments/runtime-evaluation/model_thread_trace.py --record-layout /new/kernel-task-layout.json
python experiments/runtime-evaluation/model_thread_trace.py --record-contract /new/readiness-source-contract.json \
  --chimera-source /fixed/Chimera-source --kernel-source /fixed/kernel-source
```

需要目标机的`bpftool`。采集器使用Linux/RISC-V的current=tp接口，字段偏移来自实际BTF，不使用猜测值。把这两份文件及各自SHA填入`thread_layout`、`readiness_contract`；运行前后会重新核对。既有`task_newtask`和exec/exit事件、ACK、任务状态及内核资格检查都位于本单元私有tracefs命名空间，六项probe的丢失检查及退出清理保持一致。

## 查看计划与运行

```sh
python experiments/runtime-evaluation/measure_startup.py --config /run/startup.json --plan
python experiments/runtime-evaluation/run_llama_acceptance.py --config /run/llama.json --plan
python experiments/runtime-evaluation/run_llama_acceptance.py --config /run/llama-scalar.json --plan

sudo python experiments/runtime-evaluation/measure_startup.py --config /run/startup.json --output /new/startup-run --run
sudo python experiments/runtime-evaluation/run_llama_acceptance.py --config /run/llama.json --output /new/llama-run --run
sudo python experiments/runtime-evaluation/run_llama_acceptance.py --config /run/llama-scalar.json --output /new/llama-scalar-run --run
```

`--plan`只检查配置和列出协议，不运行硬件负载。`--run`创建唯一有界systemd单元，使用12GiB上限、10GiB high、0swap；初始化测试最长45分钟，模型验收最长4小时，单条命令最长600秒。运行目录已存在时拒绝覆盖；没有自动重试。

结果目录不能位于被测源码、prepared seed或Workspace内。模型探针使用本次单元独有的命名空间；正常退出、终止或OOM后，ExecStopPost都核对并清理该命名空间，不清除其他任务的探针。清理失败不会报告测试通过。

运行前要求userspace频率为X100 2.2GHz/A100 1.8GHz，只读核对而不设置频率。空闲130秒建立温度基线，各轮开始不超过基线+3°C。需要至少6GiB剩余空间，并保留原始内核字节、连续序号、SHA、begin/end控制记录及30秒健康采样。

本复测协议将实际BKOPS0/1/2以及精确匹配的c0e00000.ufshc status1/2维护消息单列保留。状态3/未知、critical health非零、I/O错误、其他告警或证据丢失仍失败。离散健康样本不能推断维护持续时长或因果损失。该规则只用于新实验，不回写旧123轮结果或旧GCC验收策略。

模型自动启动器使用与生产bootstrap入口相同的`inherit:PID`偏好登记，等待应用runtime在exec后自行发布ready；它不代替应用设置ready。详细trace使用已归档的私有tracefs后端，不改动归档代码。线程采样周期50毫秒，包含PID/TID starttime、实际CPU、允许CPU、ready、温度、频率及整个测试cgroup内存；这些是验收旁证。

## 结果判定

逐条命令保存真实返回码、stdout/stderr及monotonic窗口；失败文件原样保留。模型PPL必须来自本轮新日志中唯一的Final estimate行，拒绝缺失、NaN/Inf及超容差结果。原生不允许迁移，自动组的计数增量须与所观测TID的成功ACK及物理CPU提交逐方向相符，退出后九项账本归零且迁移超时无增量。

`result.json`是单元内执行结果；只有外层`completion.json`同时核对实际`success/exited/0`、零swap、零OOM以及内部全部检查通过，才能报告本次复测成功。整个套件的内存峰值来自`unit.resources.json`，不是独立隔离后的单轮峰值。`evidence-sha256.json`索引所有保留证据。

第四版逐轮的`case.json`、`trace-summary.json`及`eligibility-summary.json`保存完整证据；`kernel-initialization-validation.json`单列初始化核验。多小时汇总只保留紧凑摘要及完整case/trace的路径和SHA，审计仍须读取原文件与raw trace，不以摘要代替原始见证。

## 离线检查

```sh
python -B -m unittest discover -s tests -p test_runtime_evaluation.py -v
```

离线检查覆盖计时边界、失败保存、初始化证据、PPL、线程/ACK判定和配置约束，不使用K3 proc接口，也不生成硬件通过记录。报告修改建议见[补充脚本后的修改说明](../../docs/validation/performance-report-update.zh-CN.md)。本目录新编写脚本和对应离线测试按[Apache-2.0](../../LICENSES/Apache-2.0.txt)分发，归档后端的原许可继续适用。
