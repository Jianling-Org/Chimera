"""翻译器输出侧的跨模块 ABI（应用二进制接口）契约。

两条 RVV 过渡路径虽然都通过 ``t6`` 访问状态块，但状态块中向量 payload
的解释不同：

* RVV1024 → RVV256：每个逻辑 vreg 槽位为 128 字节；
* RVV256 → RVV1024：源 RVV256 物理 vreg 按每个 32 字节紧凑保存。

因此，状态符号和地址查表 profile 必须在翻译输出中固定下来。运行时目录
之外的实现负责定义这些 TLS（线程局部存储）符号并解释查表 profile；这里
只负责让两个翻译入口发射一致的符号和立即数。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TranslationOutputContract:
    """一条翻译输出所需的状态符号和地址查表 profile。"""

    state_symbol: str
    lookup_profile: int
    # 非 TLS 单元/目标汇编 fixture 可以使用独立对象名。旧标量 ABI 的
    # Initial-Exec 符号是 ``simulated_cpu_state_ptr``，但本地 fixture 一直
    # 以 ``simulated_cpu_state`` 命名；新双向契约则两种模式使用同一精确符号。
    non_tls_state_symbol: str


# 旧的标量入口和直接构造 ProgramEmitter 的调用仍使用旧 ABI。这样本次改动
# 可以只影响两条需要并存的 RVV1024/RVV256 专用路径，不把标量验证路径
# 误认为已经完成了新的双状态运行时接入。
LEGACY_OUTPUT_CONTRACT = TranslationOutputContract(
    state_symbol="simulated_cpu_state_ptr",
    lookup_profile=0,
    non_tls_state_symbol="simulated_cpu_state",
)


# 新契约：用 RVV256 执行 RVV1024 语义。a0=1 传给地址查表函数，状态
# 符号必须由运行时以 TLS 对象形式提供。
RVV1024_TO_RVV256 = TranslationOutputContract(
    state_symbol="simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
    lookup_profile=1,
    non_tls_state_symbol="simulated_cpu_state_riscv64_rvv_1024_riscv64_rvv_256",
)


# 新契约：用 RVV1024 执行 RVV256 源状态。a0=2 传给地址查表函数，状态
# payload 的紧凑布局由该路径的 state_view 负责解释。
RVV256_TO_RVV1024 = TranslationOutputContract(
    state_symbol="simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
    lookup_profile=2,
    non_tls_state_symbol="simulated_cpu_state_riscv64_rvv_256_riscv64_rvv_1024",
)


__all__ = [
    "LEGACY_OUTPUT_CONTRACT",
    "RVV1024_TO_RVV256",
    "RVV256_TO_RVV1024",
    "TranslationOutputContract",
]
