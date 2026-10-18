# K3 内核支持

此目录提供 Spacemit K3 的双向自动迁移补丁、内核配置和构建检查工具。补丁支持 X100（CPU 0–7，VLEN 256）与 A100（CPU 8–15，VLEN 1024）之间的迁移，并提供 proposal/ACK、线程注册及迁移统计接口。

从[源码与接口说明](docs/compatibility/baseline.md)取得指定的 Linux 平台源码，按 [series](patches/series) 顺序应用 15 份补丁，再按[构建、部署与回退](docs/deployment/build-and-rollback.md)操作。完整 K3 配置见 [frozen.config](configs/k3/frozen.config)。

使用 `scripts/check/source_identity.py` 核对补丁应用后的源码身份。该补丁集依赖 Spacemit 平台实现，不能直接应用于任意上游 Linux 源码。

ISCAS 版权声明覆盖的内核贡献文件见应用补丁后的根目录 `COPYRIGHT`。现有作者和逐文件许可证保留。
