# Bootstrap 启动开销与离线验证

## 2026-10-21 实现

运行时不读取程序、翻译 DSO 或映射文件计算 SHA。完整内容校验在准备和 `bootstrap-register` 阶段完成，`file_identity.py` 的 SQLite 缓存按设备、inode、长度、mtime 纳秒和 ctime 纳秒索引。事务覆盖缓存未命中时的计算，避免多个注册进程同时重复扫描同一未变文件；硬链接共享缓存。修改或替换文件后重新验证。

注册生成三份凭据：

- `artifacts/verified-files.tsv`：已核验摘要与文件身份，包含原始程序、实际解析的原生依赖、迁移产物及 manifest。
- `artifacts/verified-variants.tsv`：离线计算的 variant 语义指纹。
- `artifacts/verified-tables.tsv`：完整映射/安全表验证成功后，绑定上述文件身份凭据的版本。

完整表验证在实际 ELF 的专用注册子进程执行。预加载 runtime 完整验证后直接退出，不进入应用 main。文件凭据未变时不重复验证。普通执行只做文件身份、ABI、地址布局、路由、指针/数量及 no-link 重定位边界检查；缺少或过期凭据拒绝就绪，不能自动回退到逐文件 SHA 或静默跳过验证。

该机制用于受控发布的 Workspace，不能将可被攻击者任意改写的凭据当作认证来源。安装或搬移 Workspace 后应重新注册，不复制另一台机器的 inode 凭据。

## 开销测试与连续调整

最初只移除运行时 SHA 时，小文件编译仍从原生 0.0962 秒变为 2.9127 秒。分段计时定位到：完整表验证约 2.143 秒，DSO 装载约 15.8 毫秒。因此进一步把全表验证移到注册阶段，保留运行时布局检查。

第二次调整后，三次交替测试的中位数如下；测试中不启用自动迁移，以隔离初始化开销。

| 工作负载 | 原生 | Bootstrap | 额外开销 |
| --- | ---: | ---: | ---: |
| cc1 `--version` | 8.79 ms | 30.39 ms | 21.60 ms |
| 极小 C 文件编译 | 94.71 ms | 127.75 ms | 33.04 ms / 34.9% |
| 内核 `lib/bsearch.c` | 1.4342 s | 1.4631 s | 2.01% |
| 内核 `kernel/fork.c` | 5.0657 s | 5.1069 s | 0.81% |
| 内核 `mm/mmap.c` | 3.4476 s | 3.4995 s | 1.51% |

真实内核命令来自同配置保存的 Kbuild 命令，重定向输出、去除依赖文件写入，使用同一 GCC。每项原生/Bootstrap 交替三次，生成对象全部 SHA 一致。它们只是启动开销样本，不代表完整内核加速比；极短任务仍存在可见相对开销，后续需继续观察。

板端证据位于独立 GCC 根 `evidence/no-runtime-sha-v3/overhead.json` 和 `kernel-probes/results.json`。新版 64 对象、16 并发迁移预检通过，覆盖 CPU0–15，31 个 cc1 被采样到跨组执行，产物及运行输出一致，退出账本、pending、reservation 为零，无迁移超时增量。相关 Python 回归 55 项和 20 子测试通过，portable C 合同 11 项通过。

## 后续完整构建

后续对照改用同一重编 GCC、make、源码及配置，普通 X100 组不设置 preload、registry 或自动迁移，异构组承担全部初始化和迁移开销。该阶段证据位于 `evidence/kernel-performance-final-v1`，不与更早的逐执行全量校验数据混合。2026-10-30的三组同16并发结果另见[性能记录](../experiments/gcc-performance/k3-20261030/README.md)。
