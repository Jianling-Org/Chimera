# RVV256→RVV1024 过渡路径语义差分

本目录独立验证 `rvv_sbt_rvv1024.py` 生成的迁移过渡代码。它不修改、也不复用
`verify/run_verify.py` 的标量后端结论；两条后端必须分别通过自己的目标机语义
门禁。

每个用例将 `simulated_cpu_state` 解释为 **RVV256 原生紧凑布局**：`vN` 位于
`state + N * 32B`，而 CSR 页仍使用既有 `0x1000..0x1040` ABI。C harness 会：

- 将完整 `0x1040` 状态块、状态块前后 64B canary（哨兵）初始化为确定值；
- 显式设置 `state.vlenb = 32`、`state.vstart = 0`，并在运行前读取真实硬件
  `vlenb`，只接受 `128`（即 VLEN=1024 bit）；
- 通过 `get_simulated_cpu_state_addr()` 为翻译器的 `--state-base-mode helper`
  提供状态基址，避免测试依赖在线 TLS 注入库；
- 将候选执行后的完整状态块、相关 load/store 内存和全部 canary 与独立 C
  reference 逐字节比较。

当前最小集合覆盖：`csrwi vxrm, 1`（验证 `vcsr[2:1]` 更新并保留 `vxsat`）、
无掩码 `vadd.vv`、`v0.t` 掩码 `vadd.vv`、`vmseq.vi` 加 `vfirst.m`，以及
`vle32.v` / `vse32.v`。这只是新路径的目标机语义门槛起点，不是“全部 RVV256
指令已验证”的声明。

## 本地生成与静态汇编

```bash
cd rvv_sbt_tool

python3 verify/rvv1024_transition/run_verify.py list
python3 verify/rvv1024_transition/run_verify.py check-env
python3 verify/rvv1024_transition/run_verify.py translate --case all
python3 verify/rvv1024_transition/run_verify.py assemble --case all
```

`assemble` 只调用 LLVM 的 RISC-V 汇编器，最高只能证明生成文本可汇编；它不能
证明算术、掩码关闭 lane、FOF、异常、迁移或性能语义。

## 目标机差分

需要 RISC-V Linux 环境中的 RVV 1.0 工具链，以及真实或 QEMU 的 **VLEN=1024**
目标。QEMU 示例：

```bash
cd rvv_sbt_tool

python3 verify/rvv1024_transition/run_verify.py check-env
python3 verify/rvv1024_transition/run_verify.py full --case all \
  --qemu-cpu 'rv64,v=true,vlen=1024,elen=64,vext_spec=v1.0'
```

也可分阶段执行 `build`、`run`，或输出可复制的部署说明：

```bash
python3 verify/rvv1024_transition/run_verify.py print-target-steps --case all
```

`full` 只有在所有 case 的程序退出为 0 时才表示该最小集合的目标语义差分通过。
若当前机器缺少交叉编译器/QEMU 或目标硬件，则应仅报告“已生成/已静态汇编”；
不得把本地 pytest、文本检查或 LLVM 对象文件称为目标机语义验证。
