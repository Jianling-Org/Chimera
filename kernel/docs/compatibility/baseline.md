# 内核源码与接口

## 获取源码

补丁集使用 Spacemit 平台源码提交 `b1944b2fc1cd68ade89219eb2773fbccc74a66f0`，其内核版本为 Linux 6.18.3。该版本包含 K3 平台实现。

通过具有仓库读取权限的 SSH 账户获取源码：

```bash
git clone --no-checkout git@code.ruyicommunity.cn:735522978001541/chimera.git linux-k3
git -C linux-k3 checkout --detach b1944b2fc1cd68ade89219eb2773fbccc74a66f0
```

先运行 `kernel/scripts/check/source_identity.py linux-k3 --expect base`，再按 `kernel/patches/series` 应用全部 15 份补丁。应用后使用 `--expect frozen` 核对源码；工具按[重放记录](../../patches/source-replay-proof.json)中的固定身份检查，不比较编译产物。补丁文件、顺序及摘要见 [重放记录](../../patches/source-replay-proof.json)。

## 配置与权限

完整 K3 配置见 [frozen.config](../../configs/k3/frozen.config)。配置启用 BPF、BPF_SYSCALL、RISCV_ISA_V 及动态抢占；部署还需要匹配的 BTF、uprobe 和 Chimera 控制接口。

`prefer_a100_stats` 权限为 0444，`prefer_a100` 为 0600，`prefer_a100_ack` 为 0222，`set_ai_thread` 为 0200。ACK 路径按当前线程与 proposal 状态处理。部署时核对实际节点权限、BPF 装载权限及 map 对象身份。

主线程和工作线程均可迁移，遵循相同的双向状态机、signal frame 一致性与退出清理规则。准备或提交失败保留源 CPU、PC 和上下文；translated body 不得再次迁移。完整规则见[自动迁移状态机](../../../docs/architecture/automigration.md)。
