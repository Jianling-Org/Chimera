# K3 GCC：同16并发测试与性能记录（2026-10-30）

本记录对应 `dev/automigration-subprocess` 的被测提交 `578ab8321c0788ab8cba1ad24324f220e1e4a149`，内核为 `6.18.3-chimera-d02cd7352`。结论为固定配置、`assume-scalar-independent` 条件下通过；本次提交归档测试侧代码与结果，没有修改生产 Runtime、GCC 或内核迁移实现。

## 已完成结果

完整 Image 三组均为 `make -j16`，各1预热、3正式，正式顺序轮换。原生的16个编译任务限制在X100的8核；两个自动组同样16个任务，可跨两簇16核。以下为3次正式测量的中位数：

| 组别 | 秒 | 相对同16并发原生耗时减少 |
|---|---:|---:|
| 原生 X100，不迁移 | 1130.860216 | 0% |
| prefer-x100 | 815.503384 | 27.886456% |
| prefer-a100 | 829.433934 | 26.654601% |

原始采样确认原生GCC/cc1始终在CPU0–7，两个自动组每轮均观测到CPU0–15。三个正式组的平均子进程CPU时间/墙时约为7.506、14.880、14.675；这包含make/编译/汇编/链接，不表示持续16核满载。每轮Image/vmlinux/System.map/config均与canonical逐项SHA一致。

[完整中文报告](results/同16并发性能报告.zh-CN.md)、[结构化统计](results/performance-summary-j16.json)、[对照图](results/同16并发性能对照.png)和[SVG](results/同16并发性能对照.svg)保留发布时字节。旧Image的原生-j8/自动-j16不作为同并发主结论，未与新Image时间混池。此前96轮单位矩阵保留并重新审计，最终有效套件共108轮、89正式、19预热。

## 归档内容与代码改动

- `harness/image_controller_j16_v2.py`：全新i5轮次、三组均16任务、每组1预热3正式、交错轮换、独立有界systemd单元。
- `harness/performance_round_j16_v2.py`：原生CPU0–7约束、保存PID/starttime/允许CPU/ready及原始CPU ticks，统一0.5秒采样和内部monotonic编译窗口。
- `harness/native-launch-image-v3.c`：测试专用标量syscall启动器。省略可选CHIMERA_LAUNCH_PID stdout通知，避免污染Kbuild的编译器识别；bootstrap、registry、继承、每exec ready和迁移handler不变。
- `harness/prelaunch_j16_v2.py`、维护策略及边界用例：核对固定源码、ELF、78行receipt、编译器探针和空间余量。用户授权BKOPS0/1/2及精确控制器维护日志单列保留，状态3、I/O、critical health等真实故障条件不变。
- `harness/final_audit_j16_1.py`：原始metrics/kernel/health、迁移账本、时窗、退出资源、源码/工件身份、预检rawACK+CPU和canonical独立重放。
- `harness/build_report_j16_1.py`：仅在独立审计实际success/exited/0之后生成报告。`record_resources.py`与`watchdog.py`是本实验的退出资源记录和磁盘紧急看护。

`harness/`是执行时的逐字节快照，原始首轮控制器/worker/prelaunch保留用于解释计时前计划测试import失败；它们没有产生Image性能样本。当前入口以`provenance.json`的current字段为准。`harness/dependencies/`保留被新审计器引用的旧只读审计代码，不包含GCC源码或工具链二进制。

## 复核与复现边界

```sh
python -B -m unittest discover -s tests -p test_gcc_performance_record.py -v
```

仓库内离线检查验证所有快照/发布文件的SHA、计划同并发与轮换、中位数/范围/吞吐/速度比复算、记录的真实退出，以及12项不依赖设备的维护边界；另两项依赖K3证据的检查已在板端实际执行通过。离线检查不声称重新执行硬件迁移或重读未提交的原始日志。

快照保留当时绝对实验路径，依赖板端验收目录、固定ELF/Workspace与真实内核接口，不是直接从仓库运行的通用CI工具。完整复现需要同身份K3环境与设备端证据；重跑应建立新的实验根与轮次ID，并通过前置身份/容量检查，不能覆盖已完成结果。旧单位、Image stdout失败及同16并发prelaunch失败的原始记录均保留在设备端。

[provenance.json](provenance.json)索引本提交携带文件；[completion.json](results/completion.json)记录板端退出和发布链，[report-publication.json](results/report-publication.json)绑定报告/统计，[chart-publication.json](results/chart-publication.json)绑定图表与输入统计。完整独立审计共核对101829个证据文件，证据manifest SHA为`37c90eed401315c47e8c95abef3c2fbd097274e596f7f1cc3e99f9ab32a11b03`；原始板端日志、模型、Workspace、凭据、个人目录和工具链不纳入本提交。

测量结束后专用watchdog已停止，定时任务已删除。归档代码与新增离线检查的许可证见[LICENSE.md](LICENSE.md)。
