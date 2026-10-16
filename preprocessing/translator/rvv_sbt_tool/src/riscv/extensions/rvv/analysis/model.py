"""RVV 配置、候选集合、函数摘要与分析结果。"""

from __future__ import annotations

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Optional
from riscv.frontend.model import ProgramStructure, FunctionStructure


class AVLKind(str, Enum):
    """AVL（活动向量长度）来源。"""

    X0 = "x0"
    CONSTANT = "constant"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AVLInfo:
    """一条 vset 指令的 AVL 静态信息。

    ``value`` 只有在 ``kind`` 为 ``CONSTANT`` 时才有意义；当 AVL 来自
    普通寄存器时，``register`` 保存寄存器名称，便于后续扩展更完整的
    标量常量传播。未知值不会被伪造为某个静态整数。
    """

    kind: AVLKind = AVLKind.UNKNOWN
    value: Optional[int] = None
    register: Optional[str] = None

    def display(self) -> str:
        if self.kind is AVLKind.CONSTANT and self.value is not None:
            return str(self.value)
        return self.kind.value


LEGAL_LMULS: tuple[float, ...] = (0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0)


LMUL_TOKENS: dict[float, str] = {
    0.125: "mf8",
    0.25: "mf4",
    0.5: "mf2",
    1.0: "m1",
    2.0: "m2",
    4.0: "m4",
    8.0: "m8",
}


@dataclass(frozen=True)
class VTypeSpec:
    """完整且确定的 RVV vtype 配置。

    ``vta`` 和 ``vma`` 沿用现有翻译器的整数表示：1 表示 agnostic，0
    表示 undisturbed。只有完整配置才能转换为此类型；不完整分析结果
    必须使用 ``VTypeCandidate``，不能默认 tail/mask policy。
    """

    sew: int
    lmul: float
    vta: int
    vma: int

    def lmul_token(self) -> str:
        return LMUL_TOKENS.get(self.lmul, f"m{self.lmul:g}")

    def __str__(self) -> str:
        tail_policy = "ta" if self.vta else "tu"
        mask_policy = "ma" if self.vma else "mu"
        return f"e{self.sew},{self.lmul_token()},{tail_policy},{mask_policy}"


def parse_init_vtype(value: str) -> VTypeSpec:
    """解析公开 ``--init-vtype`` 参数并返回确定的 vtype。

    CLI、CFG 分析与发射器必须共享同一解析实现。过去只有
    :class:`StateTracker` 解析该字符串，导致片段入口虽然在线性状态中已经
    知道 vtype，``TranslationPipeline.prepare()`` 产生的 CFG 分析却仍把
    主入口标成 unknown。把解析结果提升为模型层事实后，准备阶段和发射阶段
    不会再对同一个公开参数给出互相矛盾的判断。

    数值形式和命名形式都只接受当前 ELEN=64 profile 可解释的配置。
    命名形式省略 tail 或 mask 策略时分别使用 tu、mu。
    """

    text = str(value).strip()
    if text.startswith(("0x", "0X")) or text.isdigit():
        base = 16 if text.startswith(("0x", "0X")) else 10
        raw_vtype = int(text, base)
        if raw_vtype & ~0xff:
            raise ValueError("--init-vtype 不允许 vill 或 vtype 保留位")
        vsew_bits = (raw_vtype >> 3) & 0x7
        vlmul_bits = raw_vtype & 0x7
        if vsew_bits > 3:
            raise ValueError("--init-vtype 只支持 SEW=8/16/32/64")
        if vlmul_bits == 4:
            raise ValueError("--init-vtype 的 LMUL 编码 0b100 是保留值")
        sew_map = {
            0: 8,
            1: 16,
            2: 32,
            3: 64,
        }
        lmul_map = {
            0: 1.0,
            1: 2.0,
            2: 4.0,
            3: 8.0,
            5: 0.125,
            6: 0.25,
            7: 0.5,
        }
        return VTypeSpec(
            sew=sew_map[vsew_bits],
            lmul=lmul_map[vlmul_bits],
            vta=(raw_vtype >> 6) & 0x1,
            vma=(raw_vtype >> 7) & 0x1,
        )

    fields: dict[str, str] = {}
    flags: set[str] = set()
    for part in text.split(","):
        normalized = part.strip()
        if "=" in normalized:
            key, field_value = normalized.split("=", 1)
            key = key.strip()
            if key not in {"sew", "lmul"} or key in fields:
                raise ValueError(f"--init-vtype 未知或重复字段: {key}")
            fields[key] = field_value.strip()
        else:
            if normalized not in {"ta", "tu", "ma", "mu"} or normalized in flags:
                raise ValueError(f"--init-vtype 未知或重复策略: {normalized}")
            flags.add(normalized)

    if {"ta", "tu"} <= flags or {"ma", "mu"} <= flags:
        raise ValueError("--init-vtype 的 tail/mask 策略互相冲突")

    if "sew" not in fields:
        raise ValueError("--init-vtype 语义形式缺少必填字段 sew (如 sew=32)")
    if "lmul" not in fields:
        raise ValueError("--init-vtype 语义形式缺少必填字段 lmul (如 lmul=2)")

    try:
        sew = int(fields["sew"])
    except ValueError as exc:
        raise ValueError(
            f"--init-vtype: 无效的 sew 值 '{fields['sew']}'，应为整数"
        ) from exc
    if sew not in {8, 16, 32, 64}:
        raise ValueError("--init-vtype 只支持 SEW=8/16/32/64")

    lmul_text = fields["lmul"]
    valid_lmul = {
        "1": 1.0,
        "2": 2.0,
        "4": 4.0,
        "8": 8.0,
        "0.5": 0.5,
        "0.25": 0.25,
        "0.125": 0.125,
        "f2": 0.5,
        "f4": 0.25,
        "f8": 0.125,
    }
    try:
        lmul = valid_lmul[lmul_text]
    except KeyError as exc:
        raise ValueError(
            f"--init-vtype: 无效的 lmul 值 '{lmul_text}'，"
            "支持: 1/2/4/8/0.5/0.25/0.125/f2/f4/f8"
        ) from exc

    return VTypeSpec(
        sew=sew,
        lmul=lmul,
        vta=1 if "ta" in flags else 0,
        vma=1 if "ma" in flags else 0,
    )


@dataclass(frozen=True)
class VTypeCandidate:
    """CFG 到达某条指令时的一种可能 vtype。

    与 ``VTypeSpec`` 的区别是本类型允许字段未知。未知字段必须在合并
    路径、动态 ``vsetvl`` 或缺少前置配置时保留，不能用 ``ta,ma`` 等默认
    值填充，否则会让后端生成错误的 tail/mask 语义。
    """

    sew: Optional[int]
    lmul: Optional[float]
    vta: Optional[int]
    vma: Optional[int]
    avl: AVLInfo = AVLInfo()
    source_instruction: Optional[int] = None
    unknown_reason: Optional[str] = None

    @property
    def known_vtype(self) -> bool:
        return (
            self.sew is not None
            and self.lmul is not None
            and self.vta is not None
            and self.vma is not None
        )

    @property
    def is_fully_known(self) -> bool:
        return self.known_vtype and self.avl.kind is not AVLKind.UNKNOWN

    def to_vtype_spec(self) -> VTypeSpec:
        """将完整候选转换为旧 emitter 使用的确定配置。"""

        if not self.known_vtype:
            reason = self.unknown_reason or "vtype candidate is incomplete"
            raise ValueError(f"cannot convert incomplete vtype candidate: {reason}")
        return VTypeSpec(
            sew=self.sew,  # type: ignore[arg-type]
            lmul=self.lmul,  # type: ignore[arg-type]
            vta=self.vta,  # type: ignore[arg-type]
            vma=self.vma,  # type: ignore[arg-type]
        )

    @classmethod
    def from_spec(
        cls,
        spec: VTypeSpec,
        *,
        avl: AVLInfo | None = None,
        source_instruction: int | None = None,
    ) -> "VTypeCandidate":
        return cls(
            sew=spec.sew,
            lmul=spec.lmul,
            vta=spec.vta,
            vma=spec.vma,
            avl=avl or AVLInfo(),
            source_instruction=source_instruction,
        )

    def display(self) -> str:
        """生成面向人工检查的紧凑文本，不承担机器接口职责。"""

        sew = f"e{self.sew}" if self.sew is not None else "e?"
        if self.lmul is None:
            lmul = "m?"
        else:
            lmul = VTypeSpec(self.sew or 8, self.lmul, 0, 0).lmul_token()
        tail = "ta" if self.vta == 1 else "tu" if self.vta == 0 else "t?"
        mask = "ma" if self.vma == 1 else "mu" if self.vma == 0 else "m?"
        return f"{sew},{lmul},{tail},{mask},avl={self.avl.display()}"


UNKNOWN_VTYPE_CANDIDATE = VTypeCandidate(
    sew=None,
    lmul=None,
    vta=None,
    vma=None,
    avl=AVLInfo(),
    unknown_reason="no statically known incoming vtype",
)


UNKNOWN_SECONDARY_ENTRY_CANDIDATE = VTypeCandidate(
    sew=None,
    lmul=None,
    vta=None,
    vma=None,
    avl=AVLInfo(),
    unknown_reason="possible secondary entry without incoming vtype",
)


UNKNOWN_UNREACHABLE_CANDIDATE = VTypeCandidate(
    sew=None,
    lmul=None,
    vta=None,
    vma=None,
    avl=AVLInfo(),
    unknown_reason="no recognized CFG entry",
)


class VTypeEffectKind(str, Enum):
    """函数返回时相对于入口 vtype 的静态效果。"""

    PRESERVE_INPUT = "preserve-input"
    SET_CONSTANT = "set-constant"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VTypeEffect:
    """一个可组合的函数级 vtype 效果。

    ``candidate`` 只对 ``SET_CONSTANT`` 有意义，并且必须包含完整的
    SEW/LMUL/VTA/VMA。AVL 可以未知，因为本摘要只承诺 vtype 字段，不会
    把动态 AVL 伪造为某个常量。
    """

    kind: VTypeEffectKind
    candidate: Optional[VTypeCandidate] = None
    # 来源地址只用于人工诊断，不参与效果集合的语义相等性；否则同一
    # ``UNKNOWN`` 效果在大量调用点会产生无意义的集合膨胀。
    source_instruction: Optional[int] = field(default=None, compare=False, hash=False)
    reason: Optional[str] = None

    def __post_init__(self) -> None:
        if self.kind is VTypeEffectKind.SET_CONSTANT:
            if self.candidate is None or not self.candidate.known_vtype:
                raise ValueError("SET_CONSTANT effect requires a complete vtype candidate")
        elif self.candidate is not None:
            raise ValueError("only SET_CONSTANT effect may carry a candidate")

    @classmethod
    def preserve(cls) -> "VTypeEffect":
        return cls(VTypeEffectKind.PRESERVE_INPUT)

    @classmethod
    def set_constant(
        cls,
        candidate: VTypeCandidate,
        *,
        source_instruction: int | None = None,
    ) -> "VTypeEffect":
        canonical_candidate = VTypeCandidate(
            sew=candidate.sew,
            lmul=candidate.lmul,
            vta=candidate.vta,
            vma=candidate.vma,
            avl=candidate.avl,
            # 摘要效果的语义只由配置字段决定；保留来源由调用点的
            # InstructionAnalysis/provenance 负责，避免同配置重复扩散。
            source_instruction=None,
            unknown_reason=None,
        )
        return cls(
            VTypeEffectKind.SET_CONSTANT,
            candidate=canonical_candidate,
            source_instruction=source_instruction,
        )

    @classmethod
    def unknown(
        cls,
        reason: str,
        *,
        source_instruction: int | None = None,
    ) -> "VTypeEffect":
        return cls(
            VTypeEffectKind.UNKNOWN,
            source_instruction=source_instruction,
            reason=reason,
        )


@dataclass(frozen=True)
class FunctionVTypeSummary:
    """函数正常返回路径的 vtype 效果集合。"""

    effects: frozenset[VTypeEffect] = frozenset()
    normal_return: bool = False
    unknown_exit: bool = False
    provenance: str = "internal-cfg:summary"

    @property
    def has_unknown_effect(self) -> bool:
        return any(effect.kind is VTypeEffectKind.UNKNOWN for effect in self.effects)

    def display(self) -> str:
        values: list[str] = []
        for effect in sorted(self.effects, key=lambda item: item.kind.value):
            if effect.kind is VTypeEffectKind.SET_CONSTANT and effect.candidate:
                values.append(str(effect.candidate.to_vtype_spec()))
            else:
                values.append(effect.kind.value)
        return "; ".join(values) if values else "unknown"


@dataclass(frozen=True)
class AnalysisMetrics:
    """程序级分析统计，供 dump.S 前后结果审计。"""

    known_vector_count: int = 0
    unknown_vector_count: int = 0
    unknown_reasons: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class InstructionAnalysis:
    """一条源指令的 CFG/vtype 分析结果。"""

    address: int
    possible_vtypes: frozenset[VTypeCandidate] = frozenset()
    definite_vtype: Optional[VTypeCandidate] = None
    vtype_unknown: bool = False
    avl_information: tuple[AVLInfo, ...] = ()
    provenance: str = "internal-cfg"

    def complete_specs(self) -> tuple[VTypeSpec, ...]:
        """返回所有完整候选，供后端 vtype 分发使用。"""

        specs: list[VTypeSpec] = []
        seen: set[VTypeSpec] = set()
        ordered_candidates = sorted(
            self.possible_vtypes,
            key=lambda candidate: candidate.display(),
        )
        for candidate in ordered_candidates:
            if not candidate.known_vtype:
                continue
            spec = candidate.to_vtype_spec()
            if spec not in seen:
                specs.append(spec)
                seen.add(spec)
        return tuple(specs)

    def known_specs(self) -> tuple[VTypeSpec, ...]:
        """返回可以安全交给后端的完整 vtype 配置。

        ``VTypeCandidate`` 允许 SEW、LMUL、VTA 或 VMA 未知；此方法只
        暴露四个字段都已经被静态证明的候选，避免后端重新实现“未知
        候选不能转换为 ``VTypeSpec``”这一安全边界。
        """

        return self.complete_specs()

    def has_unknown_candidate(self) -> bool:
        """判断该指令是否仍存在不能静态解释的 vtype 路径。"""

        return self.vtype_unknown or any(
            not candidate.known_vtype
            for candidate in self.possible_vtypes
        )

    def annotation(self) -> str:
        values = sorted(candidate.display() for candidate in self.possible_vtypes)
        return "; ".join(values) if values else "unknown"


@dataclass(frozen=True)
class FunctionAnalysis:
    """函数级 CFG 与 vtype 分析结果。"""

    function_start: int
    structure: FunctionStructure
    instructions: Dict[int, InstructionAnalysis] = field(default_factory=dict)
    vtype_summary: Optional[FunctionVTypeSummary] = None

    def at(self, address: int) -> InstructionAnalysis:
        return self.instructions.get(
            address,
            InstructionAnalysis(address=address, vtype_unknown=True),
        )


@dataclass(frozen=True)
class ProgramAnalysis:
    """完整程序的分析结果。"""

    structure: ProgramStructure
    functions: Dict[int, FunctionAnalysis] = field(default_factory=dict)
    provenance: str = "internal-cfg"
    function_summaries: Dict[int, FunctionVTypeSummary] = field(default_factory=dict)
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)
    def for_function(self, start_address: int) -> Optional[FunctionAnalysis]:
        return self.functions.get(start_address)
