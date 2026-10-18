"""RISC-V 源程序和结构分析数据，独立于构建算法与扩展。"""

from __future__ import annotations

from dataclasses import field, dataclass
from typing import Any, List, Dict, Optional
from enum import Enum
import hashlib, json
from array import array
from bisect import bisect_left
from collections.abc import Iterator, Mapping


class _InstructionMetadata:
    # Existing callers may attach metadata; allocate its dictionary lazily,
    # while the declared source fields use slots for the common parsed case.
    __slots__ = ("__dict__",)


@dataclass(slots=True)
class RVInstruction(_InstructionMetadata):
    """
    统一的 RISC-V 指令数据对象 (Data Transfer Object)
    连接 Frontend (解码器) 与 Backend (模板引擎) 的桥梁。
    """
    address: int          # 指令所在的物理/虚拟地址 (如 0x34)
    opcode: str           # 操作码助记符 (如 'vfmacc.vv', 'blez')
    op_str: str           # 原始操作数字符串 (如 'v4, v28, v16')

    # 结构化的操作数列表 (提取出的目标寄存器、源寄存器等)
    operands: List[Any] = field(default_factory=list)

    # 标签信息 (如果该地址是某个标签的目标)
    label: Optional[str] = None  # 如 '.L6', '.L33', 'daxpy_k' 等

    # 原始机器码字节流 (备用，用于 debug 或对齐计算)
    raw_bytes: bytes = b''

    # 原始文本信息，用于程序级翻译、调试和 offset map 生成。
    raw_line: str = ''
    raw_bytes_hex: str = ''

    # objdump 控制流目标信息，例如 `jal 38320 <memset@plt>`。
    # operands 保持兼容性的清洗结果，目标地址单独保存供程序级翻译使用。
    target_address: Optional[int] = None
    target_symbol: Optional[str] = None

    successors: tuple[int, ...] = ()

    @property
    def base_name(self) -> str:
        """
        返回基础指令名

        例如:
        - 'vadd.vv' -> 'vadd'
        - 'vfmacc.vf' -> 'vfmacc'
        - 'vsetvli' -> 'vsetvli'
        """
        return self.opcode.split('.')[0] if '.' in self.opcode else self.opcode

    @property
    def suffix(self) -> str:
        """
        返回指令后缀

        例如:
        - 'vadd.vv' -> '.vv'
        - 'vfmacc.vf' -> '.vf'
        - 'vsetvli' -> ''
        """
        return '.' + self.opcode.split('.', 1)[1] if '.' in self.opcode else ''

    def __str__(self):
        """方便 Debug 打印"""
        l_flag = f"<{self.label}>" if self.label else ""
        return f"[0x{self.address:04x}] {l_flag:12} {self.opcode:10} {self.op_str}"


@dataclass
class RVFunction:
    """
    objdump 中的函数级代码块。

    程序级翻译路径以函数为单位输出 `<name>_translated`，同时保留函数
    起始地址用于生成稳定的局部标签和 offset map 注释。
    """
    name: str
    start_addr: int
    instructions: List[RVInstruction] = field(default_factory=list)

    # CFG 由共用结构分析构造；扩展分析结果由各扩展单独持有。
    cfg: Any = None


@dataclass
class RVProgram:
    """完整程序的统一输入容器。"""

    functions: List[RVFunction] = field(default_factory=list)
    symbols: dict[str, int] = field(default_factory=dict)
    global_labels: dict[str, int] = field(default_factory=dict)

    @property
    def instructions(self) -> List[RVInstruction]:
        """按函数顺序展开指令，便于调试和注释输出。"""

        return [insn for function in self.functions for insn in function.instructions]


class CFGEdgeKind(str, Enum):
    """反汇编文本能够证明的控制流边类型。

    CFG 层只描述源程序的控制流事实，不尝试把未解析的间接跳转猜成
    某个目标。``FALLTHROUGH`` 也单独记录，便于审计条件分支和调用的
    顺序后继是否被错误地省略。
    """

    FALLTHROUGH = "fallthrough"
    CONDITIONAL_BRANCH = "conditional-branch"
    UNCONDITIONAL_JUMP = "unconditional-jump"
    DIRECT_CALL = "direct-call"
    TAIL_CALL = "tail-call"
    INDIRECT_CALL = "indirect-call"
    INDIRECT_JUMP = "indirect-jump"
    RETURN = "return"
    TERMINAL = "terminal"


class CFGEntryKind(str, Enum):
    """基本块入口的文本证据等级。

    当前输入只有反汇编文本，无法观察 ELF 重定位、异常表或任意间接
    跳转目标。因此没有前驱的块仍然作为保守候选入口，但必须保留其
    ``SECONDARY_CANDIDATE`` 来源，不能误报为已证明可达或可证明死代码。
    """

    PRIMARY = "primary"
    SECONDARY_CANDIDATE = "secondary-candidate"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True, slots=True)
class ControlFlowEdge:
    """一条指令级控制流证据。

    ``target_address`` 为 ``None`` 时表示文本中知道存在控制流转移，
    但目标是未解析的间接地址。该记录不会被用于虚构 CFG 后继，只用于
    分析报告和 unknown 原因追踪。
    """

    source_address: int
    target_address: Optional[int]
    kind: CFGEdgeKind
    resolved: bool
    provenance: str = "text"


@dataclass(slots=True)
class BasicBlock:
    """一个函数内的基本块。

    ``instruction_addresses`` 按源程序顺序保存指令地址；边使用基本块
    起始地址表示，避免 CFG 层依赖具体的 ``RVInstruction`` 类型。
    """

    start_address: int
    instruction_addresses: tuple[int, ...]
    successors: tuple[int, ...] = ()
    predecessors: tuple[int, ...] = ()
    unknown_exit: bool = False

    @property
    def end_address(self) -> int:
        return self.instruction_addresses[-1]


class InstructionBlockMap(Mapping[int, int]):
    """Exact address lookup using two packed RV64 address arrays."""

    def __init__(self, blocks: Mapping[int, int]):
        self.addresses = array("Q", sorted(blocks))
        self.block_addresses = array("Q", (blocks[address] for address in self.addresses))

    def __getitem__(self, address: int) -> int:
        index = bisect_left(self.addresses, address)
        if index == len(self.addresses) or self.addresses[index] != address:
            raise KeyError(address)
        return self.block_addresses[index]

    def __iter__(self) -> Iterator[int]:
        return iter(self.addresses)

    def __len__(self) -> int:
        return len(self.addresses)


@dataclass
class ControlFlowGraph:
    """函数级 CFG，以及指令地址到基本块的索引。

    ``entry_address`` 保留为兼容字段，表示函数的主入口。实际分析入口
    使用 ``entry_addresses``：除主入口外，还可以包含没有被当前直接边连接
    到、但可能是冷代码、异常落点或次级函数入口的基本块。只保留单一入口
    会把这些代码错误地当作“已经证明不可达”，进而使后续 vtype 分析无条件
    回退到 unknown。
    """

    entry_address: Optional[int]
    blocks: Dict[int, BasicBlock] = field(default_factory=dict)
    instruction_to_block: Mapping[int, int] = field(default_factory=dict)
    unknown_exit: bool = False
    entry_addresses: tuple[int, ...] = ()
    # Store transfers and block exits. Interior fallthrough is represented by
    # instruction order and reconstructed by edges_for_source when requested.
    edges: tuple[ControlFlowEdge, ...] = ()
    entry_kinds: Dict[int, CFGEntryKind] = field(default_factory=dict)
    unknown_exit_addresses: frozenset[int] = frozenset()
    # 按源地址建立的快速索引。放在兼容字段之后，避免改变旧的
    # ``ControlFlowGraph(...)`` 位置参数顺序。控制流重写器会对程序中的
    # 每条标量指令查询一次边事实；若每次都线性扫描整个 ``edges``，大型
    # dump 会把本应线性的发射过程拖成平方级。
    edges_by_source: Dict[int, tuple[ControlFlowEdge, ...]] = field(default_factory=dict)

    def entry_points(self) -> tuple[int, ...]:
        """返回本 CFG 的全部候选入口，并兼容旧的单入口构造方式。"""

        if self.entry_addresses:
            return self.entry_addresses
        if self.entry_address is None:
            return ()
        return (self.entry_address,)

    @property
    def secondary_entry_addresses(self) -> tuple[int, ...]:
        """返回除主入口外的候选入口。"""

        primary = self.entry_address
        return tuple(
            address
            for address in self.entry_points()
            if address != primary
        )

    def block_for(self, address: int) -> Optional[BasicBlock]:
        block_address = self.instruction_to_block.get(address)
        if block_address is None:
            return None
        return self.blocks.get(block_address)

    def successors_for(self, address: int) -> tuple[int, ...]:
        """返回一条指令的后继指令地址。"""

        block = self.block_for(address)
        if block is None:
            return ()
        try:
            index = block.instruction_addresses.index(address)
        except ValueError:
            return ()
        if index + 1 < len(block.instruction_addresses):
            return (block.instruction_addresses[index + 1],)
        return tuple(block.successors)

    def edges_for_source(self, address: int) -> tuple[ControlFlowEdge, ...]:
        """返回指定源指令的边事实，保持旧手工构造 CFG 的兼容性。"""

        edges = (
            self.edges_by_source.get(address, ())
            if self.edges_by_source
            else tuple(edge for edge in self.edges if edge.source_address == address)
        )
        if edges:
            return edges
        block = self.block_for(address)
        if block is not None and address != block.end_address:
            return tuple(
                ControlFlowEdge(address, successor, CFGEdgeKind.FALLTHROUGH, True)
                for successor in self.successors_for(address)
            )
        return ()

    def reachable_addresses(self) -> set[int]:
        """返回从全部候选入口可到达的指令地址。

        旧实现直接返回所有已建块地址，无法区分真正不可达的代码。这里
        按基本块边重新遍历；没有前驱且不属于候选入口的孤立环仍会被保留
        在 ``unreachable_addresses`` 中，供分析结果显式标记。
        """

        reachable_blocks: set[int] = set()
        worklist = [
            self.instruction_to_block[address]
            for address in self.entry_points()
            if address in self.instruction_to_block
        ]
        while worklist:
            block_address = worklist.pop()
            if block_address in reachable_blocks:
                continue
            block = self.blocks.get(block_address)
            if block is None:
                continue
            reachable_blocks.add(block_address)
            worklist.extend(block.successors)

        return {
            address
            for block_address in reachable_blocks
            for address in self.blocks[block_address].instruction_addresses
        }

    def unreachable_addresses(self) -> set[int]:
        """返回没有从任何已知入口连接到的指令地址。"""

        return set(self.instruction_to_block) - self.reachable_addresses()


@dataclass
class ProgramCFG:
    """多个函数的 CFG 集合。"""

    functions: Dict[int, ControlFlowGraph] = field(default_factory=dict)

    def for_function(self, start_address: int) -> Optional[ControlFlowGraph]:
        return self.functions.get(start_address)


class CallEdgeKind(str, Enum):
    """调用点的返回语义。"""

    DIRECT_CALL = "direct-call"
    TAIL_CALL = "tail-call"
    INDIRECT_CALL = "indirect-call"


@dataclass(frozen=True, slots=True)
class CallEdge:
    """一条调用图边。

    ``target_function_start`` 只有在目标地址属于当前反汇编程序中的某个
    非外部桩函数时才填写。目标落在函数内部时仍记录所属函数起点，便于
    审计，但 ``target_is_function_entry`` 为假，不能把函数头摘要套到这个
    内部入口上。外部符号和未解析间接调用仍保留边记录，但不能被摘要
    分析当作可知的被调用函数。
    """

    caller_function_start: int
    call_address: int
    target_address: Optional[int]
    target_symbol: Optional[str]
    kind: CallEdgeKind
    target_function_start: Optional[int] = None
    target_is_function_entry: bool = False
    resolved: bool = False
    provenance: str = "text"


@dataclass
class CallGraph:
    """程序级直接/间接调用边集合。"""

    edges_by_caller: dict[int, tuple[CallEdge, ...]] = field(default_factory=dict)
    edge_by_call_address: dict[int, CallEdge] = field(default_factory=dict)

    def edges_for(self, function_start: int) -> tuple[CallEdge, ...]:
        return self.edges_by_caller.get(function_start, ())

    def edge_for_call(self, call_address: int) -> CallEdge | None:
        return self.edge_by_call_address.get(call_address)

    def resolved_callees(self, function_start: int) -> tuple[int, ...]:
        """返回当前函数中可以在文本中确定的被调函数起点。"""

        return tuple(
            edge.target_function_start
            for edge in self.edges_for(function_start)
            if (
                edge.target_function_start is not None
                and edge.target_is_function_entry
                and edge.resolved
            )
        )


@dataclass(frozen=True)
class StructureMetrics:
    direct_edge_count: int = 0
    unresolved_control_transfer_count: int = 0
    secondary_entry_count: int = 0
    unreachable_count: int = 0


@dataclass(frozen=True)
class FunctionStructure:
    cfg: ControlFlowGraph
    entry_addresses: tuple[int, ...]
    secondary_entry_addresses: tuple[int, ...]
    unreachable_addresses: frozenset[int]


@dataclass(frozen=True)
class PLTTarget:
    address: int
    symbol: str
    # Original-module GOT slot, decoded from the PLT instructions. IFUNC
    # synthetic names identify resolvers, not callable implementations.
    got_address: int | None = None


@dataclass(frozen=True)
class ProgramStructure:
    functions: dict[int, FunctionStructure]
    call_graph: CallGraph
    input_fingerprint: str
    metrics: StructureMetrics
    # Direct PLT transfers and adjacent AUIPC/JALR pairs. Arbitrary entry at
    # JALR still requires checking the live register against its candidate.
    plt_candidates: dict[int, PLTTarget]


def compute_program_fingerprint(program: object) -> str:
    """为 ``RVProgram`` 计算与汇编语义相关的稳定输入指纹。

    指纹只包含解析后的源程序事实：函数身份、指令地址、操作码、操作
    数、直接控制流目标地址和目标符号。它不包含 ``analysis``、``cfg``
    等派生字段，因此给指令挂接分析结果不会改变指纹；相反，修改任意
    一个发射器依赖的源字段都会使旧分析失效。
    """

    functions = getattr(program, "functions", ())
    digest = hashlib.sha256()
    digest.update(b"[")
    for index, function in enumerate(functions):
        instructions: list[dict[str, object]] = []
        for instruction in getattr(function, "instructions", ()):
            instructions.append(
                {
                    "address": instruction.address,
                    "opcode": instruction.opcode,
                    "operands": [str(operand) for operand in instruction.operands],
                    "target_address": instruction.target_address,
                    "target_symbol": instruction.target_symbol,
                }
            )
        if index:
            digest.update(b",")
        # Preserve the canonical JSON byte stream while retaining at most one
        # function's serialization, rather than a second whole-program IR.
        payload = {
            "name": function.name,
            "start_addr": function.start_addr,
            "instructions": instructions,
        }
        digest.update(json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
    digest.update(b"]")
    return digest.hexdigest()
