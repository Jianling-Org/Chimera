# 翻译器已知问题

## 待解决：共享对象中的 `jal *_translated` 重定位

状态：已记录，尚未修复。

使用 `-fPIC -shared` 编译翻译后的汇编时，指向全局翻译函数的直接
`jal *_translated` 可能产生无效的 RISC-V 重定位：

```text
relocation R_RISCV_JAL against `*_translated' which may bind externally can not be used when making a shared object
```

当前翻译流程会把跨函数直接跳转改写为带 `_translated` 后缀的目标函数。问题出现在输出作为共享对象链接时：翻译目标符号具有全局可见性或可能被外部抢占，导致 `R_RISCV_JAL` 的直接跳转范围和绑定约束不满足。

后续修改该路径前，需要在链接级别比较以下方案，并使用 RISC-V 工具链验证：

- 保留 `jal`，同时将翻译函数符号设为本地或隐藏（前提是外部组件不需要直接解析）；
- 为跨函数翻译调用生成适合 PIC（位置无关代码）的调用形式；
- 调整离线链接合同或链接器选项。

在完成链接和目标机验证前，不要把本地汇编生成成功当作共享对象可链接，也不要把该问题混入普通 handler 支持统计。
