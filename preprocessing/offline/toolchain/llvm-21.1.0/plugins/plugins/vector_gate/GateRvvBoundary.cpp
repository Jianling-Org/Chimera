#include "GateRvvBoundary.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Regex.h"

using namespace llvm;

namespace {
constexpr const char *GateAttr = "chimera-no-vectorize";
constexpr const char *BoundaryAttr = "chimera-rvv-call-boundary";

bool scalableState(Type *Ty) {
  if (isa<ScalableVectorType>(Ty))
    return true;
  if (auto *ST = dyn_cast<StructType>(Ty))
    return llvm::any_of(ST->elements(), scalableState);
  if (auto *AT = dyn_cast<ArrayType>(Ty))
    return scalableState(AT->getElementType());
  return false;
}

bool hasExplicitRvvState(const Function &F) {
  if (scalableState(F.getReturnType()))
    return true;
  for (const Argument &A : F.args())
    if (scalableState(A.getType()))
      return true;
  for (const BasicBlock &BB : F)
    for (const Instruction &I : BB) {
      if (scalableState(I.getType()))
        return true;
      if (const auto *AI = dyn_cast<AllocaInst>(&I))
        if (scalableState(AI->getAllocatedType()))
          return true;
      for (const Use &Operand : I.operands())
        if (scalableState(Operand->getType()))
          return true;
      if (const auto *CB = dyn_cast<CallBase>(&I))
        if (const auto *Asm = dyn_cast<InlineAsm>(CB->getCalledOperand()))
          if (Regex("~\\{v[0-9]+\\}").match(Asm->getConstraintString()))
            return true;
    }
  // A scalar vscale/vlen query alone is deliberately not an RVV boundary.
  return false;
}

Function *directCallee(CallBase &CB) {
  return dyn_cast<Function>(CB.getCalledOperand()->stripPointerCasts());
}
} // namespace

PreservedAnalyses chimera::GateRvvBoundaryPass::run(
    Module &M, ModuleAnalysisManager &) {
  SmallPtrSet<Function *, 32> Reachable;
  SmallVector<Function *, 32> Work;
  for (Function &F : M)
    if (!F.isDeclaration() && F.hasFnAttribute(GateAttr))
      Work.push_back(&F);
  while (!Work.empty()) {
    Function *F = Work.pop_back_val();
    if (!Reachable.insert(F).second)
      continue;
    for (BasicBlock &BB : *F)
      for (Instruction &I : BB)
        if (auto *CB = dyn_cast<CallBase>(&I))
          if (Function *Callee = directCallee(*CB))
            if (!Callee->isDeclaration() && !Reachable.contains(Callee))
              Work.push_back(Callee);
  }
  SmallPtrSet<Function *, 32> Boundaries;
  bool Changed = false;
  for (Function *F : Reachable)
    if (hasExplicitRvvState(*F)) {
      Boundaries.insert(F);
      Changed |= !F->hasFnAttribute(BoundaryAttr) ||
                 !F->hasFnAttribute(GateAttr) ||
                 !F->hasFnAttribute(Attribute::NoInline) ||
                 F->hasFnAttribute(Attribute::AlwaysInline);
      F->addFnAttr(GateAttr);
      F->addFnAttr(BoundaryAttr);
      F->removeFnAttr(Attribute::AlwaysInline);
      F->addFnAttr(Attribute::NoInline);
    }
  // Preserve each function's identity, linkage and interposition semantics.
  // Only positive explicit-RVV definitions receive a boundary. Wrappers and
  // scalar callbacks retain ordinary inlining and constant propagation.
  for (Function &F : M)
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CB = dyn_cast<CallBase>(&I))
          if (Function *Callee = directCallee(*CB))
            if (Boundaries.contains(Callee)) {
              Changed |= !CB->hasFnAttr(Attribute::NoInline) ||
                         CB->hasFnAttr(Attribute::AlwaysInline);
              CB->removeFnAttr(Attribute::AlwaysInline);
              CB->addFnAttr(Attribute::NoInline);
            }
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
