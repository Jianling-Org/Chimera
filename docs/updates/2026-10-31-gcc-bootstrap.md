# GCC 子进程迁移与同16并发测试

本次更新加入 exec 子进程初始化、按进程选择迁移策略，以及 GCC 大程序准备阶段的内存改进。代码来源为开发提交 `0c6e21538`，提交对应关系见[来源记录](gcc-bootstrap-sync.json)。

## exec 启动

`libchimera-bootstrap.so` 随普通动态 ELF 的 exec 重新加载，依据当前可执行文件查找已验证的 Workspace。Runtime 初始化完成后才发布 ready；没有注册记录的 shell、汇编器等辅助程序保持未就绪，不使用父程序的 Workspace。

`chimera-user bootstrap-register` 发布注册表；`run --registry ... --bootstrap ...` 启动程序树。`--preference prefer-x100` 与 `prefer-a100` 选择可继承的任务策略，并隐含 `--automigrate`。用法见[使用者 CLI](../user/cli.md#exec-子进程与迁移策略)。

该路径需要内核提供 `inherit:TID`、`ready:TID` 以及 `/proc/prefer_x100`、`/proc/prefer_a100` 接口。仓库现有的15份冻结内核补丁未随本次用户态更新扩展，不能据此推定它们已提供新接口。实验使用的内核版本另列于报告中，部署前须核对实际接口。

## 大程序准备与运行

- 函数指针元数据中的已链接地址不再重复加装载基址。
- offset map 使用紧凑存储，汇编、gzip 文本与 JSON 按流处理；不再保留用完的 JAL 探测文件。
- PLT 入口按 `@plt` 后缀识别，生成翻译 DSO 时使用 `-nostartfiles`，避免引入应用 CRT finalizer。
- 策略信号使用 `SA_RESTART`，避免 GCC 等待子进程时因 `EINTR` 失败。
- 安全源指令通过正常 route/map/save/ACK 路径迁移，并由 translated exit trap 返回目标组原代码。缺失安全表和 translated body 再次迁移仍会拒绝。

内容摘要和完整静态表校验在注册阶段完成。执行时核对文件身份、验证凭据、ABI 与布局；该方式用于受控发布的 Workspace。文件或凭据发生变化后须重新注册，不能把可任意改写的凭据当作认证来源。细节见[启动开销与离线验证](../BOOTSTRAP-STARTUP-COST.zh-CN.md)。

## 性能记录

[2026-10-30 GCC 记录](../../experiments/gcc-performance/k3-20261030/README.md)绑定开发源码 `578ab8321`、内核 `6.18.3-chimera-d02cd7352` 和固定 ELF、Profile、依赖，采用 `assume-scalar-independent` 范围。

完整 Image 三组都使用 `make -j16`：原生的16个编译任务限于 X100 的8核；两个自动组同为16个任务，可跨 X100/A100 两簇运行。各组1次预热、3次正式测量；中位数依次为1130.860216、815.503384、829.433934秒。相对原生耗时缩短27.886456%和26.654601%。

早期 `native -j8 / auto -j16` 结果保留为历史记录，不参与上述统计。并行任务上限也不表示整个构建期间持续占满16核。存储维护观测、频率、温度和采样边界见[完整报告](../../experiments/gcc-performance/k3-20261030/results/同16并发性能报告.zh-CN.md)。

Kbuild 实验使用专用启动器，省略可选的 `CHIMERA_LAUNCH_PID` 标准输出通知，避免污染编译器识别输出。生产 CLI 保留该通知接口；这里没有通过过滤编译器标准输出来取得结果。

## 验证范围

Linux 上已执行 bootstrap/exec、文件身份与 receipt、信号等待恢复、迁移决策、翻译器及性能归档回归，并通过10项可移植 C 测试。完整 Python 回归中的旧文档路径、发布夹具和 shell 换行问题已在原公开提交 `c1e5188` 复现；本次检查的结果另列于[来源记录](gcc-bootstrap-sync.json)。

本次未重新执行公开整合版本的 K3 硬件验收，归档中的迁移和性能结果仍属于报告所绑定的原开发版本。SVF 插件需要 LLVM 21.1.0；当前验证环境缺少该精确版本，插件构建与 conformance 端到端自测未完成。
