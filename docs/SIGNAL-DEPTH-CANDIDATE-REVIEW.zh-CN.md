# 信号帧候选部署前审查（2026-10-21）

候选：`6.18.3-chimera-bootstrap-exec-signal-depth-v1`。当前仅构建和暂存，没有安装或重启；不是验收通过版本。

Image、994 个模块和独立 initramfs 已准备好。全部模块按最终 `.ko` 检查存在性、vermagic 和 SHA。最终 Image 按 Kbuild 记录的 objcopy 参数从模块构建完成后的 vmlinux 重新生成，避免混用前一次链接的 Image。

| 文件 | SHA-256 |
| --- | --- |
| Image | `710a49a014b5633bd5f57b2e68ceca5588c2adc217770a5446aa29baab68ab28` |
| Image.gz | `46425dcf449d4d1dab39d8d442198d8d71562736d1f210fece3d70c343dd529a` |
| initrd | `6e5013fd2003a2db7a35f229f98a1437fca32297486e0b24457c76ca864192e7` |

板端完整清单：`/root/kaiwen/chimera-bootstrap-kernel-build/bootstrap-evidence/signal-depth-candidate-v1/candidate-ready.json`。initramfs 在私有挂载命名空间内生成，已经检查包含目标版本模块与 init；主机 `/lib/modules` 仍未安装该版本。当前运行内核仍为 `6.18.3-chimera-bootstrap-exec`。

审查结论及限制：

- 新计数不分配内存、不新增锁。成功构造 native 帧后递增，正常恢复完成后递减，饱和时保持拒绝。
- ACK 在 CPU 和向量提交前要求深度恰为 1；失败沿现有清理路径释放 pending 和 reservation，不修改旧 CPU、PC 或信号帧。
- exec 清零；同栈 fork 继承计数，新 clone 栈与内核线程清零。兼容 ABI 没有这套 native 计数，因此不能通过该 ACK 门禁。
- 不修改 translated body 再入保护，不放宽向量帧检查；宿主工具的三个 const 指针修正另列补丁。
- `siglongjmp` 跳过 sigreturn 会留下保守计数，阻止后续迁移直到 exec。这是已知限制，尚非完整信号控制流解决方案。
- 已有编译、产物校验和旧内核故障证据；候选尚未上板回归，不能报告功能通过。嵌套 ACK 测试还须结合正常迁移预检，避免把其他原因的 EAGAIN 当作门禁命中。

准备执行的部署方案（等待新候选授权）：

1. 核对无其他任务占用开发板，保留当前 exec 和 generic 启动文件及 `/boot/env_k3.txt`。
2. `/boot` 空间不足，先将不再使用的 child-freeze 启动文件完整备份并核验，移出启动分区以容纳候选；冻结版本材料保留可恢复。当前启动分区完整本地备份为工作区 `build/boot-before-signal-depth-candidate.tar.gz`。
3. 安装独立版本模块和候选 Image.gz/initrd，最后原子更新 env 中两个文件名；DTB 与其他启动参数保持原样。失败则恢复原 env，使用原 exec 镜像和模块。
4. 重启一次，检查版本、模块、启动告警和 exec 继承。先测嵌套信号拒绝、正常双向迁移及账本，再重跑曾失败的完整 make 构建。若启动失败，需要串口或人工选择原启动配置，不能声称可在失联后自动恢复。

此前授权的是恢复既有配套内核。此处为新候选内核，部署和重启需另行确认；在确认前不修改系统启动配置。
