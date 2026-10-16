"""RVV1024 过渡后端规划元数据的唯一定义点。

与 RVV256 侧的 ``riscv.extensions.rvv.backends.rvv256.lowering_metadata`` 同理：``specs.py``
（登记规格、构造 registry）与 ``lowering.py``（执行降低）互相需要对方。
把 builder 绑定类型与访问器放进本中立模块后，依赖收敛为

    specs -> lowering -> lowering_metadata
    specs -> lowering_metadata

不再需要函数内延迟 import。这里只承载只读事实，不产生标签或汇编行。
"""

from __future__ import annotations

from dataclasses import dataclass

from riscv.extensions.rvv.translation.lowering import AssemblyLineBuilder
from riscv.extensions.rvv.translation.contracts import InstructionSpec


@dataclass(frozen=True, slots=True)
class TransitionLoweringMetadata:
    """过渡后端 lowerer 的唯一结构化 builder 绑定。"""

    builder: AssemblyLineBuilder


def lowering_metadata(spec: InstructionSpec) -> TransitionLoweringMetadata:
    """取得经过运行时类型校验的过渡后端 builder 元数据。"""

    metadata = spec.lowering_metadata
    if not isinstance(metadata, TransitionLoweringMetadata):
        raise TypeError(f"{spec.opcode} 不属于 RVV1024 transition registry")
    return metadata


__all__ = [
    "TransitionLoweringMetadata",
    "lowering_metadata",
]
