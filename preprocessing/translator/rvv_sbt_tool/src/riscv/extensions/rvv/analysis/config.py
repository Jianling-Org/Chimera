# src/riscv/extensions/rvv/analysis/config.py
"""
状态追踪器：追踪指令流中的向量配置状态 (SEW, LMUL, VL)

RISC-V 向量扩展 (RVV) 的关键概念:
- SEW (Standard Element Width): 标准元素宽度，如 8/16/32/64 bit
- LMUL (Length Multiplier): 向量长度乘数，如 1/2/4/8/f8/f4/f2
- VLEN: 向量寄存器总位数 (如 1024)
- VLMAX: 最大向量长度 = VLEN * LMUL / SEW

vsetvli/vsetivli 指令设置这些参数，影响后续向量指令的行为。
"""

from riscv.extensions.rvv.instruction import is_config_instruction
from typing import Dict, Any
from riscv.frontend.model import RVInstruction
from riscv.extensions.rvv.analysis.model import VTypeSpec, parse_init_vtype, LMUL_TOKENS


class StateTracker:
    """
    追踪向量配置状态机
    """

    # 当前项目允许识别的 LMUL 文本 token。
    #
    # 这里显式列出合法值，而不是继续使用宽松的
    # `op.startswith("m")` 判断，原因很直接：
    # - `ma` / `mu` 是 mask policy，而不是 LMUL；
    # - 若仅靠前缀判断，`mu` 会被误当成 LMUL 进入 `float("u")`，
    #   从而在 `vsetvli ..., mu` 场景下直接抛异常；
    # - 显式白名单能把“配置字段解析”和“策略字段解析”彻底隔开。
    VALID_LMUL_OPERANDS = {token: value for value, token in LMUL_TOKENS.items()}

    def __init__(self, vlenb: int):
        """
        初始化状态追踪器

        :param vlenb: VLEN/8，即向量寄存器字节数
        """
        self.vlenb = vlenb
        self.vlen = vlenb * 8  # VLEN in bits

        # 当前向量配置状态
        self.sew: int = 64          # Standard Element Width (bits)
        self.lmul: float = 1.0      # Length Multiplier
        self.vl: int = 0            # Vector Length (当前有效元素数)
        self.vtype: int = 0         # 原始 vtype CSR 值
        self.vta: int = 0           # Vector Tail Agnostic (0=dirty, 1=agnostic)
        self.vma: int = 0           # Vector Mask Agnostic (0=dirty, 1=agnostic)

        # 当前配置指令的操作数字符串 (用于调试)
        self.config_str: str = ""

    def clone(self) -> "StateTracker":
        """Return a copy of the current static vector state."""
        cloned = StateTracker(vlenb=self.vlenb)
        cloned.sew = self.sew
        cloned.lmul = self.lmul
        cloned.vl = self.vl
        cloned.vtype = self.vtype
        cloned.vta = self.vta
        cloned.vma = self.vma
        cloned.config_str = self.config_str
        return cloned

    def apply_vtype_spec(self, spec: VTypeSpec) -> None:
        """
        Apply a CFG-provided entry vtype candidate to this tracker.

        This updates only the Python-side static vtype fields. Runtime VL is
        still read from simulated CSR state by generated code.
        """
        self.sew = spec.sew
        self.lmul = spec.lmul
        self.vta = spec.vta
        self.vma = spec.vma
        self.vtype = self.get_vtype_value()
        self.config_str = f"source:{spec}"

    def update(self, insn: RVInstruction) -> bool:
        """
        根据指令更新状态

        :param insn: 当前指令
        :return: 是否为配置指令且状态已更新
        """
        if not is_config_instruction(insn):
            return False

        # 解析 vsetvli/vsetivli/vsetvl 指令
        if insn.opcode == 'vsetvli':
            self._parse_vsetvli(insn)
        elif insn.opcode == 'vsetivli':
            self._parse_vsetivli(insn)
        elif insn.opcode == 'vsetvl':
            self._parse_vsetvl(insn)
        else:
            return False

        self.config_str = insn.op_str
        return True

    def _parse_vsetvli(self, insn: RVInstruction) -> None:
        """
        解析 vsetvli 指令

        格式: vsetvli rd, rs1, e64, m4, ta, ma
              vsetvli a5, a0, e64, m4, ta, ma
              vsetvli a6, zero, e64, m4, ta, ma
        """
        operands = insn.operands
        if len(operands) < 3:
            return

        # 解析 SEW (如 e64 -> 64)
        for op in operands:
            if op.startswith('e') and op[1:].isdigit():
                self.sew = int(op[1:])

        self._update_lmul_from_operands(operands)

        # tail policy:
        # - `ta` -> agnostic -> 1
        # - `tu` -> undisturbed -> 0
        self.vta = 1 if 'ta' in operands else 0

        # mask policy:
        # - `ma` -> agnostic -> 1
        # - `mu` -> undisturbed -> 0
        self.vma = 1 if 'ma' in operands else 0

    def _parse_vsetivli(self, insn: RVInstruction) -> None:
        """
        解析 vsetivli 指令 (立即数版本)

        格式: vsetivli zero, 0x1, e64, m1, ta, ma
        """
        operands = insn.operands
        if len(operands) < 3:
            return

        # 解析 SEW
        for op in operands:
            if op.startswith('e') and op[1:].isdigit():
                self.sew = int(op[1:])

        self._update_lmul_from_operands(operands)

        # tail policy:
        # - `ta` -> agnostic -> 1
        # - `tu` -> undisturbed -> 0
        self.vta = 1 if 'ta' in operands else 0

        # mask policy:
        # - `ma` -> agnostic -> 1
        # - `mu` -> undisturbed -> 0
        self.vma = 1 if 'ma' in operands else 0

    def _parse_vsetvl(self, insn: RVInstruction) -> None:
        """
        解析 vsetvl 指令 (vtype 来自寄存器 rs2，静态不可知)

        格式: vsetvl rd, rs1, rs2
        语义:
            rs2 保存 vtype CSR 值 (动态)
            VL = (rs1 == x0) ? VLMAX : min(rs1, VLMAX)
            rd = VL

        由于 rs2 是动态寄存器值，无法在翻译阶段静态确定 SEW/LMUL/VTA/VMA。
        仅标记已解析，不修改内部状态字段。
        后续 handler 若依赖当前 SEW/LMUL，应自行从 simulated_cpu_state 读取。
        """
        operands = insn.operands
        if len(operands) < 3:
            return

        self.config_str = insn.op_str

    def _update_lmul_from_operands(self, operands: list[str]) -> None:
        """
        从操作数列表中提取并更新 LMUL。

        只接受 RVV 合法的 LMUL token，例如：
        - `m1`, `m2`, `m4`, `m8`
        - `mf2`, `mf4`, `mf8`

        像 `ma` / `mu` 这样的 policy token 虽然同样以 `m` 开头，
        但不属于 LMUL，必须在这里被显式排除。
        """
        for op in operands:
            normalized = op.strip().lower()
            if normalized in self.VALID_LMUL_OPERANDS:
                self.lmul = self.VALID_LMUL_OPERANDS[normalized]
                return

    def get_vlmax(self) -> int:
        """
        计算当前配置下的最大向量长度

        VLMAX = (VLEN * LMUL) / SEW

        :return: 最大元素数
        """
        if self.sew == 0:
            return 0

        # VLEN * LMUL / SEW
        vlmax = int((self.vlen * self.lmul) / self.sew)
        return vlmax

    def get_vtype_value(self) -> int:
        """
        计算 vtype CSR 的值

        vtype 编码格式 (RVV 1.0):
        - bits 2-0: vlmul (LMUL 编码)
        - bits 5-3: vsew (SEW 编码)
        - bit 6: vta (vector tail agnostic)
        - bit 7: vma (vector mask agnostic)

        SEW 编码: e8=0, e16=1, e32=2, e64=3（当前 ELEN=64）
        LMUL 编码: m1=0, m2=1, m4=2, m8=3, mf8=5, mf4=6, mf2=7

        :return: vtype CSR 值
        """
        vsew = {8: 0, 16: 1, 32: 2, 64: 3}[self.sew]
        vlmul = {"m1": 0, "m2": 1, "m4": 2, "m8": 3,
                 "mf8": 5, "mf4": 6, "mf2": 7}[LMUL_TOKENS[self.lmul]]

        # 按 RVV 1.0 规定的真实位布局组合 vtype。
        #
        # 之所以这里显式拆开写，而不是延续旧版那种“整体左移”的写法，
        # 是为了避免把 `vlmul/vsew/vta/vma` 的字段位置再次写反。
        vtype = vlmul | (vsew << 3) | (self.vta << 6) | (self.vma << 7)
        return vtype

    def apply_init_vtype(self, init_vtype: str) -> None:
        """
        解析 --init-vtype 参数并更新内部状态 (仅 SEW/LMUL/VTA/VMA)。

        仅更新 StateTracker 的 Python 内部字段，不产生任何输出代码。
        实际翻译结果从 simulated_cpu_state 读取 vl，因此 vl 不由本方法管理。

        支持两种形式：
        1. 原始数值：以 0x/0X 开头或纯十进制数字，解码为 sew/lmul/vta/vma
        2. 语义字段：如 sew=32,lmul=2,ta,ma（必填 sew、lmul；可选 ta/tu、ma/mu）

        :param init_vtype: CLI 参数字符串
        :raises ValueError: 参数格式无效或缺少必填字段
        """
        spec = parse_init_vtype(init_vtype)
        self.sew = spec.sew
        self.lmul = spec.lmul
        self.vta = spec.vta
        self.vma = spec.vma

    def get_state_str(self) -> str:
        """
        获取当前状态的字符串表示

        :return: 如 "[Tracker] SEW=64, LMUL=8.0, VLMAX=16"
        """
        return f"[Tracker] SEW={self.sew}, LMUL={self.lmul}, VLMAX={self.get_vlmax()}"

    def get_state_dict(self) -> Dict[str, Any]:
        """
        获取当前状态的字典表示

        :return: {'sew': 64, 'lmul': 8.0, 'vlmax': 16, 'vlen': 128}
        """
        return {
            'sew': self.sew,
            'lmul': self.lmul,
            'vl': self.vl,
            'vlmax': self.get_vlmax(),
            'vlen': self.vlen,
            'config_str': self.config_str,
        }

    def __str__(self) -> str:
        return self.get_state_str()
