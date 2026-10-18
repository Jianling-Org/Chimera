#!/usr/bin/env python3
"""RVV256→RVV1024 过渡路径的最小目标语义差分 runner。

本 runner 与现有 ``verify/run_verify.py`` 相互独立。它验证的不是固定 128B
逻辑 vreg 槽位，而是在线迁移时捕获的 RVV256 raw payload：源 ``vN`` 位于
``simulated_cpu_state + N * 32B``。候选代码由新路径生成，并通过 helper 状态
基址模式调用 C harness 提供的 ``get_simulated_cpu_state_addr()``。

本机可执行 ``translate`` / ``assemble``；只有在 RISC-V VLEN=1024 目标环境
中运行 ``build`` / ``run`` / ``full``，才会取得语义差分证据。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from string import Template


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
DEFAULT_ARTIFACT_ROOT = HERE / "artifacts"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from riscv.frontend.parser import AsmParser  # noqa: E402
from riscv.extensions.rvv.runtime.access import STATE_BASE_MARKER  # noqa: E402
from riscv.extensions.rvv.runtime.geometry import RVV256_TO_RVV1024_GEOMETRY  # noqa: E402
from rvv_sbt_rvv1024 import translate  # noqa: E402


@dataclass(frozen=True)
class TransitionCase:
    """一个以同一初始紧凑状态运行 reference/candidate 的最小差分 case。"""

    name: str
    command: str
    vtype: str
    description: str
    c_source: str


_COMMON_C = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define STATE_SIZE 0x1040u
#define CANARY_SIZE 64u
#define RAW_VREG_OFFSET(n) ((size_t)(n) * 32u)
#define VSTART_OFFSET 0x1000u
#define VCSR_OFFSET 0x1018u
#define VL_OFFSET 0x1020u
#define VTYPE_OFFSET 0x1028u
#define VLENB_OFFSET 0x1030u

/* 目标 vtype 只作为 state 快照内容；翻译器的静态形状来自对应 case.vtype。 */
#define VTYPE_E8_M1_TA_MA  0x00000000000000c0ULL
#define VTYPE_E32_M1_TA_MA 0x00000000000000d0ULL

struct guarded_state {
    uint8_t before[CANARY_SIZE];
    uint8_t state[STATE_SIZE];
    uint8_t after[CANARY_SIZE];
};

static struct guarded_state state_fixture __attribute__((aligned(64)));
static uint8_t expected_state[STATE_SIZE];

/*
 * 过渡汇编以 --state-base-mode helper 生成。该符号模拟在线运行时的兼容
 * helper，但状态本体仍由本 harness 持有，便于在前后加入 canary。
 */
__attribute__((noinline)) uint8_t *get_simulated_cpu_state_addr(void) {
    return state_fixture.state;
}

static uint8_t *state_bytes(void) {
    return state_fixture.state;
}

static uint64_t load_u64(const uint8_t *base, size_t offset) {
    uint64_t value;
    memcpy(&value, base + offset, sizeof(value));
    return value;
}

static void store_u64(uint8_t *base, size_t offset, uint64_t value) {
    memcpy(base + offset, &value, sizeof(value));
}

static void init_state(uint64_t vl, uint64_t vtype) {
    memset(state_fixture.before, 0xc3, sizeof(state_fixture.before));
    memset(state_fixture.after, 0x3c, sizeof(state_fixture.after));
    memset(state_bytes(), 0xa5, STATE_SIZE);
    store_u64(state_bytes(), VSTART_OFFSET, 0);
    store_u64(state_bytes(), VCSR_OFFSET, 0);
    store_u64(state_bytes(), VL_OFFSET, vl);
    store_u64(state_bytes(), VTYPE_OFFSET, vtype);
    store_u64(state_bytes(), VLENB_OFFSET, 32);
}

static void snapshot_expected_state(void) {
    memcpy(expected_state, state_bytes(), STATE_SIZE);
}

static int require_transition_profile(void) {
    unsigned long hardware_vlenb = 0;
    __asm__ volatile("csrr %0, vlenb" : "=r"(hardware_vlenb));
    if (hardware_vlenb != 128) {
        fprintf(stderr, "需要 VLEN=1024（vlenb=128），实际 vlenb=%lu\n", hardware_vlenb);
        return 1;
    }
    if (load_u64(state_bytes(), VLENB_OFFSET) != 32) {
        fprintf(stderr, "state.vlenb 不是 RVV256 所需的 32\n");
        return 1;
    }
    if (load_u64(state_bytes(), VSTART_OFFSET) != 0) {
        fprintf(stderr, "一期迁移测试要求 state.vstart=0\n");
        return 1;
    }
    return 0;
}

static int check_state(void) {
    for (size_t index = 0; index < CANARY_SIZE; ++index) {
        if (state_fixture.before[index] != 0xc3 || state_fixture.after[index] != 0x3c) {
            fprintf(stderr, "state canary mismatch at %zu\n", index);
            return 1;
        }
    }
    for (size_t index = 0; index < STATE_SIZE; ++index) {
        if (state_bytes()[index] != expected_state[index]) {
            fprintf(stderr,
                    "state mismatch at 0x%zx: got=%02x expected=%02x\n",
                    index, state_bytes()[index], expected_state[index]);
            return 1;
        }
    }
    return 0;
}

#define MEMORY_WORDS 16u
struct guarded_u32_memory {
    uint8_t before[CANARY_SIZE];
    uint32_t words[MEMORY_WORDS];
    uint8_t after[CANARY_SIZE];
};

static void init_u32_memory(struct guarded_u32_memory *memory) {
    memset(memory->before, 0x6d, sizeof(memory->before));
    memset(memory->words, 0x5a, sizeof(memory->words));
    memset(memory->after, 0xd6, sizeof(memory->after));
}

static int check_u32_memory(
    const struct guarded_u32_memory *actual,
    const struct guarded_u32_memory *expected
) {
    if (memcmp(actual->before, expected->before, CANARY_SIZE) != 0 ||
        memcmp(actual->after, expected->after, CANARY_SIZE) != 0) {
        fprintf(stderr, "memory canary mismatch\n");
        return 1;
    }
    if (memcmp(actual->words, expected->words, sizeof(actual->words)) != 0) {
        fprintf(stderr, "memory payload mismatch\n");
        return 1;
    }
    return 0;
}
'''


def _template(text: str, **values: object) -> str:
    """填充 C 模板中的少量 case 常量，避免 C 花括号与 Python f-string 混淆。"""
    return Template(text).substitute({name: str(value) for name, value in values.items()})


def _vadd_source(*, masked: bool) -> str:
    """构造 e32,m1 vadd 的 reference；masked form 专门覆盖 v0.t 的旧值保持。"""
    mask_setup = r'''
    uint8_t *mask = state_bytes() + RAW_VREG_OFFSET(0);
    memset(mask, 0, (VL + 7u) / 8u);
    for (size_t i = 0; i < VL; ++i) {
        if ((i % 3u) != 1u) mask[i / 8u] |= (uint8_t)(1u << (i % 8u));
    }
'''
    expected_update = (
        "if ((i % 3u) != 1u) expected_vd[i] = lhs[i] + rhs[i];"
        if masked else "expected_vd[i] = lhs[i] + rhs[i];"
    )
    return _COMMON_C + _template(
        r'''
extern void translated_func(void);
int main(void) {
    enum { VL = 7 };
    init_state(VL, VTYPE_E32_M1_TA_MA);
    uint32_t *vd = (uint32_t *)(state_bytes() + RAW_VREG_OFFSET(8));
    uint32_t *lhs = (uint32_t *)(state_bytes() + RAW_VREG_OFFSET(16));
    uint32_t *rhs = (uint32_t *)(state_bytes() + RAW_VREG_OFFSET(24));
    for (size_t i = 0; i < VL; ++i) {
        vd[i] = (uint32_t)(0x1000u + i * 17u);
        lhs[i] = (uint32_t)(i * 13u + 3u);
        rhs[i] = (uint32_t)(i * 19u + 5u);
    }
$mask_setup
    snapshot_expected_state();
    uint32_t *expected_vd = (uint32_t *)(expected_state + RAW_VREG_OFFSET(8));
    for (size_t i = 0; i < VL; ++i) { $expected_update }
    if (require_transition_profile()) return 2;
    translated_func();
    return check_state();
}
''',
        mask_setup=mask_setup if masked else "",
        expected_update=expected_update,
    )


def _vmseq_vfirst_source() -> str:
    """用同一函数内的 vmseq→vfirst 覆盖 raw mask 写回和标量结果。"""
    return _COMMON_C + r'''
extern long translated_func(void);
int main(void) {
    enum { VL = 19 };
    init_state(VL, VTYPE_E8_M1_TA_MA);
    uint8_t *source = state_bytes() + RAW_VREG_OFFSET(4);
    for (size_t i = 0; i < VL; ++i) source[i] = (uint8_t)((int)(i % 5u) - 2);
    snapshot_expected_state();
    uint8_t *expected_mask = expected_state + RAW_VREG_OFFSET(1);
    long expected_first = -1;
    for (size_t i = 0; i < VL; ++i) {
        uint8_t bit = (uint8_t)(1u << (i % 8u));
        if (source[i] == (uint8_t)-1) {
            expected_mask[i / 8u] |= bit;
            if (expected_first < 0) expected_first = (long)i;
        } else {
            expected_mask[i / 8u] &= (uint8_t)~bit;
        }
    }
    if (require_transition_profile()) return 2;
    long result = translated_func();
    if (result != expected_first) {
        fprintf(stderr, "vfirst result=%ld expected=%ld\n", result, expected_first);
        return 1;
    }
    return check_state();
}
'''


def _unit_memory_source(*, load: bool) -> str:
    """构造 e32,m1 unit load/store reference，并比较完整相关内存与 canary。"""
    if load:
        setup = r'''
    for (size_t i = 0; i < VL; ++i) {
        memory.words[i] = (uint32_t)(0x3000u + i * 23u);
        vd[i] = (uint32_t)(0xdead0000u + i);
    }
    expected_memory = memory;
    snapshot_expected_state();
    uint32_t *expected_vd = (uint32_t *)(expected_state + RAW_VREG_OFFSET(8));
    for (size_t i = 0; i < VL; ++i) expected_vd[i] = memory.words[i];
'''
    else:
        setup = r'''
    for (size_t i = 0; i < VL; ++i) {
        vd[i] = (uint32_t)(0x4000u + i * 29u);
        memory.words[i] = (uint32_t)(0x77770000u + i);
    }
    expected_memory = memory;
    snapshot_expected_state();
    for (size_t i = 0; i < VL; ++i) expected_memory.words[i] = vd[i];
'''
    return _COMMON_C + _template(
        r'''
extern void translated_func(uint32_t *);
int main(void) {
    enum { VL = 7 };
    init_state(VL, VTYPE_E32_M1_TA_MA);
    struct guarded_u32_memory memory;
    struct guarded_u32_memory expected_memory;
    init_u32_memory(&memory);
    uint32_t *vd = (uint32_t *)(state_bytes() + RAW_VREG_OFFSET(8));
$setup
    if (require_transition_profile()) return 2;
    translated_func(memory.words);
    if (check_state()) return 1;
    return check_u32_memory(&memory, &expected_memory);
}
''',
        setup=setup,
    )


def _csrwi_vxrm_source() -> str:
    """构造 ``csrwi vxrm, 1`` 的 source-state reference。

    这个 case 不把候选交给真实硬件 ``vxrm``；它验证迁移器是否只在
    ``state.vcsr[2:1]`` 更新源端舍入模式，并保留 sticky ``vxsat``。因此即使
    后续数据指令才恢复硬件 vcsr，CSR 指令本身也有可观测的完整状态差分。
    """
    return _COMMON_C + r'''
extern void translated_func(void);
int main(void) {
    init_state(0, VTYPE_E8_M1_TA_MA);
    /* vxsat=1, vxrm=2；csrwi vxrm,1 后应为 vxsat=1, vxrm=1。 */
    store_u64(state_bytes(), VCSR_OFFSET, 5);
    snapshot_expected_state();
    store_u64(expected_state, VCSR_OFFSET, 3);
    if (require_transition_profile()) return 2;
    translated_func();
    return check_state();
}
'''


CASES: dict[str, TransitionCase] = {
    "csrwi_vxrm": TransitionCase(
        name="csrwi_vxrm",
        command="csrwi vxrm, 1",
        vtype="sew=8,lmul=1",
        description="写 source vxrm；验证 vcsr[2:1] 更新且保留 vxsat。",
        c_source=_csrwi_vxrm_source(),
    ),
    "vadd_e32_m1": TransitionCase(
        name="vadd_e32_m1",
        command="vadd.vv v8, v16, v24",
        vtype="sew=32,lmul=1",
        description="无掩码整数加法；比较完整 raw state。",
        c_source=_vadd_source(masked=False),
    ),
    "masked_vadd_e32_m1": TransitionCase(
        name="masked_vadd_e32_m1",
        command="vadd.vv v8, v16, v24, v0.t",
        vtype="sew=32,lmul=1",
        description="v0.t 掩码加法；验证关闭 lane 保留旧目的值。",
        c_source=_vadd_source(masked=True),
    ),
    "vmseq_vfirst_e8_m1": TransitionCase(
        name="vmseq_vfirst_e8_m1",
        command="vmseq.vi v1, v4, -1\nvfirst.m a0, v1",
        vtype="sew=8,lmul=1",
        description="bit-packed mask compare 后立即扫描；比较 mask state 与 a0 返回值。",
        c_source=_vmseq_vfirst_source(),
    ),
    "vle32_e32_m1": TransitionCase(
        name="vle32_e32_m1",
        command="vle32.v v8, (a0)",
        vtype="sew=32,lmul=1",
        description="unit load；比较完整 state、相关内存与双侧 canary。",
        c_source=_unit_memory_source(load=True),
    ),
    "vse32_e32_m1": TransitionCase(
        name="vse32_e32_m1",
        command="vse32.v v8, (a0)",
        vtype="sew=32,lmul=1",
        description="unit store；比较完整 state、相关内存与双侧 canary。",
        c_source=_unit_memory_source(load=False),
    ),
}


def _default_llvm_tool(name: str) -> str:
    """优先 PATH，其次兼容当前 macOS 上的 Homebrew LLVM 安装位置。"""
    found = shutil.which(name)
    if found:
        return found
    homebrew = Path("/opt/homebrew/opt/llvm/bin") / name
    return str(homebrew) if homebrew.exists() else name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "list", "check-env", "translate", "assemble", "build", "run", "full",
            "print-target-steps",
        ),
        help="要执行的验证阶段。",
    )
    parser.add_argument("--case", dest="case_name", default="all", help="case 名称或 all")
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=DEFAULT_ARTIFACT_ROOT,
        help="生成物根目录（默认是本目录下被忽略的 artifacts/）。",
    )
    parser.add_argument("--cc", default="riscv64-unknown-linux-gnu-gcc")
    parser.add_argument("--qemu", default="qemu-riscv64")
    parser.add_argument(
        "--qemu-cpu",
        default="rv64,v=true,vlen=1024,elen=64,vext_spec=v1.0",
        help="QEMU VLEN 必须是 1024 bit；C harness 会再次读取 vlenb 门禁。",
    )
    parser.add_argument("--llvm-mc", default=_default_llvm_tool("llvm-mc"))
    parser.add_argument("--llvm-objdump", default=_default_llvm_tool("llvm-objdump"))
    parser.add_argument(
        "--cflags",
        default="-O2 -static -march=rv64gcv -mabi=lp64d",
        help="传给目标 C 编译器的固定 ABI/ISA 编译选项。",
    )
    return parser.parse_args()


def selected_cases(case_name: str) -> list[TransitionCase]:
    """按稳定名称顺序选择 case，避免 artifact 输出随 dict 插入顺序漂移。"""
    if case_name == "all":
        return [CASES[name] for name in sorted(CASES)]
    try:
        return [CASES[case_name]]
    except KeyError as exc:
        raise SystemExit(f"未知 case: {case_name}") from exc


def case_directory(case: TransitionCase, artifact_root: Path) -> Path:
    """所有可再生产物隔离在 ignored artifact 根下，绝不污染 verify 源目录。"""
    return artifact_root / case.name


def executable_path(command: str) -> str | None:
    """同时支持 PATH 名称和显式绝对/相对路径。"""
    path = Path(command).expanduser()
    if path.exists():
        return str(path)
    return shutil.which(command)


def require_tool(command: str, purpose: str) -> str:
    """缺少工具时给出阶段性诊断，避免把本机限制误报成翻译器失败。"""
    resolved = executable_path(command)
    if resolved is None:
        raise SystemExit(f"{purpose} 需要工具 {command!r}，当前未找到。")
    return resolved


def run_command(command: list[str], cwd: Path, *, stdout=None) -> None:
    """执行外部工具并保留其诊断；失败时显示完整命令供目标机复现。"""
    try:
        subprocess.run(command, cwd=cwd, check=True, stdout=stdout)
    except FileNotFoundError as exc:
        raise SystemExit(f"找不到外部工具: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        rendered = " ".join(command)
        raise SystemExit(f"命令失败（退出码 {exc.returncode}）：{rendered}") from exc


def translate_case(case: TransitionCase, artifact_root: Path) -> Path:
    """生成候选汇编和独立 C reference，强制选择可由 harness 提供的 helper ABI。"""
    directory = case_directory(case, artifact_root)
    directory.mkdir(parents=True, exist_ok=True)
    instructions = AsmParser().parse_string(case.command)
    assembly = translate(
        instructions,
        # runner 的 reference 状态就是 RVV256 raw 32B 布局；显式传参避免
        # 将来入口默认值变化时悄悄换成别的迁移 profile。
        source_vlenb=RVV256_TO_RVV1024_GEOMETRY.source_vlenb,
        target_vlenb=RVV256_TO_RVV1024_GEOMETRY.target_vlenb,
        init_vtype=case.vtype,
        func_name="translated_func",
        state_base_mode="helper",
        tls_state=True,
    )
    if "get_simulated_cpu_state_addr@plt" not in assembly:
        raise SystemExit(f"case {case.name} 未生成 helper 状态基址调用，harness ABI 不成立")
    if STATE_BASE_MARKER not in assembly:
        raise SystemExit(f"case {case.name} 未观察到紧凑状态访问标记")
    (directory / "translated.s").write_text(assembly, encoding="utf-8")
    (directory / "main.c").write_text(case.c_source, encoding="utf-8")
    print(f"[translate] {case.name}: helper state-base, raw vN=N*32B")
    return directory


def assemble_case(
    case: TransitionCase,
    artifact_root: Path,
    llvm_mc: str,
    llvm_objdump: str,
) -> None:
    """用 LLVM RISC-V backend 做静态汇编门禁，不宣称任何目标机语义。"""
    directory = translate_case(case, artifact_root)
    mc = require_tool(llvm_mc, "assemble")
    run_command(
        [
            mc,
            "-triple=riscv64-unknown-linux-gnu",
            "-mattr=+m,+a,+f,+d,+c,+v,+zicsr",
            "-filetype=obj",
            "translated.s",
            "-o",
            "translated.o",
        ],
        directory,
    )
    objdump = executable_path(llvm_objdump)
    if objdump is not None:
        with (directory / "translated.objdump").open("w", encoding="utf-8") as output:
            run_command([objdump, "-dr", "--mattr=+v", "translated.o"], directory, stdout=output)
    print(f"[assemble] {case.name}: 静态汇编通过（非目标机语义证据）")


def build_case(case: TransitionCase, artifact_root: Path, cc: str, cflags: str) -> None:
    """在 RISC-V 目标工具链上链接 C reference 与候选汇编。"""
    directory = translate_case(case, artifact_root)
    compiler = require_tool(cc, "build")
    run_command(
        [compiler, *cflags.split(), "main.c", "translated.s", "-o", "verify.elf"],
        directory,
    )
    print(f"[build] {case.name}: 目标可执行文件已生成")


def run_case(case: TransitionCase, artifact_root: Path, qemu: str, qemu_cpu: str) -> None:
    """在 VLEN=1024 QEMU 配置运行完整 C reference/candidate 差分。"""
    directory = case_directory(case, artifact_root)
    elf = directory / "verify.elf"
    if not elf.exists():
        raise SystemExit(f"缺少 {elf}；请先执行 build 或 full。")
    emulator = require_tool(qemu, "run")
    run_command([emulator, "-cpu", qemu_cpu, "./verify.elf"], directory)
    print(f"[run] {case.name}: PASS（完整 0x1040 state/相关内存/canary 差分）")


def print_environment(args: argparse.Namespace) -> int:
    """报告分层工具可用性；本机缺目标工具不是生成/静态汇编失败。"""
    python_ok = bool(sys.executable and Path(sys.executable).exists())
    llvm_ok = executable_path(args.llvm_mc) is not None
    cc_ok = executable_path(args.cc) is not None
    qemu_ok = executable_path(args.qemu) is not None
    print(f"Python 翻译环境: {'可用' if python_ok else '缺失'}")
    print(f"LLVM RISC-V 静态汇编: {'可用' if llvm_ok else '缺失'} ({args.llvm_mc})")
    print(f"RISC-V 目标构建器: {'可用' if cc_ok else '缺失'} ({args.cc})")
    print(f"VLEN=1024 运行器/QEMU: {'可用' if qemu_ok else '缺失'} ({args.qemu})")
    if not (cc_ok and qemu_ok):
        print("当前仅可取得生成/静态汇编证据；目标机语义差分尚未执行。")
    return 0 if python_ok else 1


def print_target_steps(case: TransitionCase, artifact_root: Path, args: argparse.Namespace) -> None:
    """输出不依赖当前本机的可复制目标验证步骤。"""
    directory = case_directory(case, artifact_root)
    print(f"[target-steps] {case.name}: {case.description}")
    print("  1. 在目标环境确认 RVV 1.0 且硬件 VLEN=1024 bit（vlenb=128）。")
    print(f"  2. 生成: python3 {HERE / 'run_verify.py'} translate --case {case.name}")
    print(f"  3. 构建: {args.cc} {args.cflags} main.c translated.s -o verify.elf")
    print(f"     工作目录: {directory}")
    print(f"  4. QEMU: {args.qemu} -cpu '{args.qemu_cpu}' ./verify.elf")
    print("  5. 原生目标可直接运行 ./verify.elf；C harness 会拒绝 vlenb!=128、")
    print("     state.vlenb!=32 或 state.vstart!=0，并逐字节比较 state/memory/canary。")


def main() -> int:
    args = parse_args()
    cases = selected_cases(args.case_name)
    artifact_root = args.artifact_root.expanduser().resolve()

    if args.action == "list":
        for case in cases:
            print(f"{case.name}: {case.command!r} [{case.vtype}] - {case.description}")
        return 0
    if args.action == "check-env":
        return print_environment(args)
    if args.action == "print-target-steps":
        for case in cases:
            print_target_steps(case, artifact_root, args)
        return 0

    for case in cases:
        if args.action == "translate":
            translate_case(case, artifact_root)
        elif args.action == "assemble":
            assemble_case(case, artifact_root, args.llvm_mc, args.llvm_objdump)
        elif args.action == "build":
            build_case(case, artifact_root, args.cc, args.cflags)
        elif args.action == "run":
            run_case(case, artifact_root, args.qemu, args.qemu_cpu)
        elif args.action == "full":
            # `full` 优先补静态汇编门禁；若本机没有 LLVM，仍可在目标环境完成
            # C reference/candidate 差分，但输出会明确少了该层静态证据。
            if executable_path(args.llvm_mc) is not None:
                assemble_case(case, artifact_root, args.llvm_mc, args.llvm_objdump)
            else:
                print("[full] 未找到 llvm-mc，跳过静态汇编门禁；继续目标构建/运行。")
            build_case(case, artifact_root, args.cc, args.cflags)
            run_case(case, artifact_root, args.qemu, args.qemu_cpu)
        else:  # argparse choices 已覆盖；保留防御性诊断。
            raise SystemExit(f"未处理的 action: {args.action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
