#include "RVVIntrinsic.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IntrinsicsRISCV.h"

using namespace llvm;

namespace chimera {

Value *
getRVVMemoryPointerOperand(CallBase &CB) {
  switch (CB.getIntrinsicID()) {

  // ---- 内存基址位于 arg 1 的家族 ----
  // (vle/vse: passthru/value 在 arg 0；vsm/vlse/vsse/vlsegN/vssegN
  //  的 value/tuple 同样在 arg 0，ptr 统一在 arg 1)
  // unit-stride
  case Intrinsic::riscv_vle:
  case Intrinsic::riscv_vle_mask:
  case Intrinsic::riscv_vse:
  case Intrinsic::riscv_vse_mask:
  // mask store
  case Intrinsic::riscv_vsm:
  // strided
  case Intrinsic::riscv_vlse:
  case Intrinsic::riscv_vlse_mask:
  case Intrinsic::riscv_vsse:
  case Intrinsic::riscv_vsse_mask:
  // segment load/store（N = 2..8，含 mask 变体）
  case Intrinsic::riscv_vlseg2:  case Intrinsic::riscv_vlseg2_mask:
  case Intrinsic::riscv_vlseg3:  case Intrinsic::riscv_vlseg3_mask:
  case Intrinsic::riscv_vlseg4:  case Intrinsic::riscv_vlseg4_mask:
  case Intrinsic::riscv_vlseg5:  case Intrinsic::riscv_vlseg5_mask:
  case Intrinsic::riscv_vlseg6:  case Intrinsic::riscv_vlseg6_mask:
  case Intrinsic::riscv_vlseg7:  case Intrinsic::riscv_vlseg7_mask:
  case Intrinsic::riscv_vlseg8:  case Intrinsic::riscv_vlseg8_mask:
  case Intrinsic::riscv_vsseg2:  case Intrinsic::riscv_vsseg2_mask:
  case Intrinsic::riscv_vsseg3:  case Intrinsic::riscv_vsseg3_mask:
  case Intrinsic::riscv_vsseg4:  case Intrinsic::riscv_vsseg4_mask:
  case Intrinsic::riscv_vsseg5:  case Intrinsic::riscv_vsseg5_mask:
  case Intrinsic::riscv_vsseg6:  case Intrinsic::riscv_vsseg6_mask:
  case Intrinsic::riscv_vsseg7:  case Intrinsic::riscv_vsseg7_mask:
  case Intrinsic::riscv_vsseg8:  case Intrinsic::riscv_vsseg8_mask:
    return CB.getArgOperand(1);

  // ---- mask load：签名 (ptr, vl)，指针在 arg 0 ----
  case Intrinsic::riscv_vlm:
    return CB.getArgOperand(0);

  default:
    return nullptr;
  }
}

// Indexed gather/scatter：地址是指针向量（index 向量），多地址，
// 无法映射单一 StackObjectID。设计上永久忽略（不进 map、不 warning）。
bool
isIndexedRVVMemoryIntrinsic(CallBase &CB) {
  Function *Callee = CB.getCalledFunction();

  if (!Callee || !Callee->isIntrinsic())
    return false;

  StringRef Name = Callee->getName();

  return Name.starts_with("llvm.riscv.vluxei") ||
         Name.starts_with("llvm.riscv.vloxei") ||
         Name.starts_with("llvm.riscv.vsuxei") ||
         Name.starts_with("llvm.riscv.vsoxei");
}

bool
isUnsupportedRVVMemoryIntrinsic(CallBase &CB) {
  Function *Callee = CB.getCalledFunction();

  if (!Callee ||
      !Callee->isIntrinsic() ||
      !CB.mayReadOrWriteMemory())
    return false;

  StringRef Name = Callee->getName();

  // Only RVV-specific intrinsics qualify as "unsupported RVV memory
  // intrinsic". Generic masked/vp intrinsics (llvm.masked.*, llvm.vp.*)
  // are target-independent and are deliberately NOT treated as RVV
  // accesses: their PCSections are not propagated through RISC-V
  // lowering, and gather/scatter are multi-address. They fall through
  // to the default ignore path instead.
  return Name.starts_with("llvm.riscv.v");
}

} // namespace chimera