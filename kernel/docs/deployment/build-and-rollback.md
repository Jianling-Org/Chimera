# 构建、部署与回退

本页说明如何在 K3 板端构建配套内核，以及部署后的核对项目。构建脚本只生成镜像和模块；安装与重启使用板卡已有的启动管理方式。

## 准备源码与配置

按[内核源码与接口](../compatibility/baseline.md)取得指定版本，在独立、无本地修改的源码目录中按 `kernel/patches/series` 应用补丁。分别核对原始源码和应用补丁后的源码身份；发生冲突时先保存现场并检查差异。

在 K3 上，从 Chimera 仓库根目录执行，将路径替换为应用补丁后的内核源码：

```bash
KERNEL_SOURCE=/absolute/path/to/patched-linux-source
cp kernel/configs/k3/frozen.config "$KERNEL_SOURCE/.config"
kernel/scripts/verify/build_frozen.sh "$KERNEL_SOURCE"
```

脚本检查源码、配置和版本号，再执行 `make -j8 Image modules`。构建需要足够内存；开始前确认板端资源可用。

## 构建结果

成功时脚本输出 `Build complete; evidence: ...`，镜像位于内核源码的 `arch/riscv/boot/Image`。构建记录默认保存在 `~/.chimera/kernel-build/` 的时间戳目录；可通过 `CHIMERA_KERNEL_EVIDENCE` 指定尚不存在的输出目录。

脚本统一传入 `LOCALVERSION=-chimera-child-freeze`，与配置中的 `CONFIG_LOCALVERSION="-prefer-a100"` 组成版本号 `6.18.3-prefer-a100-chimera-child-freeze`，并在编译前后核对。使用此入口可避免查询版本与实际构建使用不同后缀。

构建记录包含配置、编译器、命令、日志和镜像摘要，用于关联本机构建与实际部署文件。构建、启动后接口检查及动态验证均通过，才完成本机验证；无需复现测试镜像的二进制哈希。

## 部署与回退

安装前保留可启动的旧内核、initrd 和启动项。内核改动需完成 panic 风险、锁顺序、任务生命周期、reservation 泄漏、signal frame 一致性及 translated body 重入审查。

按板卡启动管理流程安装并重启。启动后核对运行版本、`boot_id`、启动项和实际加载的 kernel/initrd，随后完成[自动迁移验证](../../../docs/validation/automigration.md)中的测试项目，包括至少两小时的混合线程数负载。

出现异常时保存日志与构建产物，并选择保留的启动项回退。每次启动的运行验证结果应与该次 `boot_id` 关联。
