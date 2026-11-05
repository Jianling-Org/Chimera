#include "GateRvvBoundary.h"

#include "llvm/ADT/DenseMap.h"
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

bool carriesScalableValues(const CallBase &CB) {
  return scalableState(CB.getType()) ||
         llvm::any_of(CB.args(), [](const Use &Arg) {
           return scalableState(Arg->getType());
         });
}
} // namespace

PreservedAnalyses chimera::GateRvvBoundaryPass::run(
    Module &M, ModuleAnalysisManager &) {
  SmallPtrSet<Function *, 32> Reachable;
  SmallPtrSet<Function *, 32> ExplicitRvv;
  SmallPtrSet<Function *, 32> BoundaryContext;
  DenseMap<Function *, SmallVector<CallBase *, 4>> Calls;
  DenseMap<Function *, SmallVector<Function *, 4>> Callers;
  SmallVector<Function *, 32> Work;
  SmallVector<Function *, 32> Indirect;
  for (Function &F : M)
    if (!F.isDeclaration() && F.hasFnAttribute(GateAttr))
      Work.push_back(&F);
  while (!Work.empty()) {
    Function *F = Work.pop_back_val();
    if (!Reachable.insert(F).second)
      continue;
    if (hasExplicitRvvState(*F))
      ExplicitRvv.insert(F);
    for (BasicBlock &BB : *F)
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);
        if (!CB || CB->isInlineAsm())
          continue;
        Function *Callee = directCallee(*CB);
        if (!Callee) {
          if (BoundaryContext.insert(F).second)
            Indirect.push_back(F);
          continue;
        }
        if (Callee->isDeclaration())
          continue;
        Calls[F].push_back(CB);
        Callers[Callee].push_back(F);
        if (!Reachable.contains(Callee))
          Work.push_back(Callee);
      }
  }

  // Gate remains a property of the definition, independent of its inlining.
  bool Changed = false;
  for (Function *F : ExplicitRvv)
    if (!F->hasFnAttribute(GateAttr)) {
      F->addFnAttr(GateAttr);
      Changed = true;
    }

  // A caller of an indirect-call path can also carry an inlined RVV frame
  // across it. Find that control context before descending into wrappers.
  while (!Indirect.empty()) {
    Function *F = Indirect.pop_back_val();
    for (Function *Caller : Callers[F])
      if (BoundaryContext.insert(Caller).second)
        Indirect.push_back(Caller);
  }
  Work.append(BoundaryContext.begin(), BoundaryContext.end());
  while (!Work.empty()) {
    Function *F = Work.pop_back_val();
    for (CallBase *CB : Calls[F]) {
      Function *Callee = directCallee(*CB);
      if (CB->hasFnAttr(Attribute::NoInline))
        continue;
      if (ExplicitRvv.contains(Callee)) {
        // A scalable call interface already exposes vector state to its
        // caller. Separating it here would add spills without isolating it.
        if (!carriesScalableValues(*CB)) {
          CB->removeFnAttr(Attribute::AlwaysInline);
          CB->addFnAttr(Attribute::NoInline);
          Changed = true;
        }
      } else if (BoundaryContext.insert(Callee).second) {
        // The wrapper can still inline, carrying its protected call site.
        Work.push_back(Callee);
      }
    }
  }
  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
