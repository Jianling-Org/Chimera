"""RVV256 规划元数据的唯一定义点。

``specs.py``（登记静态事实、构造 registry）与 ``lowering.py``/``wide_chunk.py``
（消费元数据执行降低）互相需要对方：registry 绑定的 lowerer 定义在
lowering，而 lowerer 又要读取每个规格的 builder 绑定。把元数据类型与访问器
放进本中立模块后，三方依赖收敛为

    specs -> lowering -> wide_chunk -> lowering_metadata
    specs -> lowering_metadata

不再存在需要用函数内延迟 import 掩盖的环。

这里只承载“只读规划事实”，不得引入任何标签或汇编行；跨后端公共协议仍以
``riscv.extensions.rvv.translation.contracts`` 为唯一来源。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from riscv.extensions.rvv.translation.lowering import AssemblyLineBuilder
from riscv.extensions.rvv.translation.contracts import InstructionSpec


@dataclass(frozen=True, slots=True)
class RVV256SameWidthSpec:
    """可复用同一宽循环的等宽逐元素规划事实。"""

    operand_form: str
    vector_operand_positions: tuple[int, ...]
    scalar_operand_position: int | None
    allowed_sews: tuple[int, ...] = ()  # Empty: no restriction beyond the instruction spec.
    lowering: Literal["direct", "not_base_v", "and_not_base_v"] = "direct"


@dataclass(frozen=True, slots=True)
class RVV256LoweringMetadata:
    """lowerer 所需、但不属于跨后端公共协议的只读事实。"""

    builder: AssemblyLineBuilder | None
    same_width: RVV256SameWidthSpec | None
    conservative_mask_supported: bool


def lowering_metadata(spec: InstructionSpec) -> RVV256LoweringMetadata:
    """取得经过类型校验的 RVV256 规划元数据。"""

    metadata = spec.lowering_metadata
    if not isinstance(metadata, RVV256LoweringMetadata):
        raise TypeError(f"{spec.opcode} 不属于 RVV256 registry")
    return metadata


__all__ = [
    "RVV256LoweringMetadata",
    "RVV256SameWidthSpec",
    "lowering_metadata",
]
