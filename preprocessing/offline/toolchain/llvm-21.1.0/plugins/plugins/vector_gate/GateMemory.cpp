#include "GateMemory.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace {
constexpr const char *GateAttr = "chimera-no-vectorize";

MDNode *scalarLoopMetadata(LLVMContext &C) {
  Metadata *Vectorize[] = {
      MDString::get(C, "llvm.loop.vectorize.enable"),
      ConstantAsMetadata::get(ConstantInt::getFalse(C))};
  Metadata *Idiom[] = {MDString::get(C, "llvm.loop.idiom.disable")};
  Metadata *Nonforced[] = {MDString::get(C, "llvm.loop.disable_nonforced")};
  Metadata *Operands[] = {nullptr, MDNode::get(C, Vectorize),
                         MDNode::get(C, Idiom), MDNode::get(C, Nonforced)};
  MDNode *Loop = MDNode::getDistinct(C, Operands);
  Loop->replaceOperandWith(0, Loop);
  return Loop;
}

void expandLocalMemset(MemSetInst &MI) {
  Value *Length = MI.getLength();
  if (const auto *N = dyn_cast<ConstantInt>(Length); N && N->isZero()) {
    MI.eraseFromParent();
    return;
  }
  BasicBlock *Before = MI.getParent();
  Function *F = Before->getParent();
  LLVMContext &C = F->getContext();
  BasicBlock *After = Before->splitBasicBlock(MI.getIterator(),
                                             "chimera.memset.end");
  BasicBlock *Body = BasicBlock::Create(C, "chimera.memset.scalar", F, After);
  Before->getTerminator()->eraseFromParent();
  IRBuilder<> B(Before);
  B.SetCurrentDebugLocation(MI.getDebugLoc());
  Value *Zero = ConstantInt::get(Length->getType(), 0);
  B.CreateCondBr(B.CreateICmpEQ(Length, Zero), After, Body);
  B.SetInsertPoint(Body);
  PHINode *Index = B.CreatePHI(Length->getType(), 2, "chimera.memset.index");
  Index->addIncoming(Zero, Before);
  // memset lengths are unsigned. GEP sign-extends a narrower index, so an
  // i32 length on RV64 must not turn offsets >= 2 GiB into negative offsets.
  Type *PointerIndex = F->getParent()->getDataLayout().getIndexType(
      MI.getRawDest()->getType());
  Value *Offset = B.CreateZExtOrTrunc(Index, PointerIndex, "chimera.memset.offset");
  Value *Address = B.CreateGEP(B.getInt8Ty(), MI.getRawDest(), Offset);
  StoreInst *Store = B.CreateStore(MI.getValue(), Address, MI.isVolatile());
  Store->setAlignment(Align(1));
  for (unsigned Kind : {LLVMContext::MD_alias_scope, LLVMContext::MD_noalias,
                        LLVMContext::MD_access_group})
    if (MDNode *MD = MI.getMetadata(Kind))
      Store->setMetadata(Kind, MD);
  Value *Next = B.CreateAdd(Index, ConstantInt::get(Length->getType(), 1));
  Index->addIncoming(Next, Body);
  BranchInst *Backedge = B.CreateCondBr(B.CreateICmpNE(Next, Length), Body, After);
  Backedge->setMetadata(LLVMContext::MD_loop, scalarLoopMetadata(C));
  MI.eraseFromParent();
}

} // namespace

PreservedAnalyses chimera::GateLocalMemsetPass::run(
    Module &M, ModuleAnalysisManager &) {
  SmallVector<MemSetInst *, 16> Work;
  for (Function &F : M)
    if (F.hasFnAttribute(GateAttr))
      for (BasicBlock &BB : F)
        for (Instruction &I : BB)
          if (auto *MI = dyn_cast<MemSetInst>(&I))
            Work.push_back(MI);
  for (MemSetInst *MI : Work)
    expandLocalMemset(*MI);
  return Work.empty() ? PreservedAnalyses::all() : PreservedAnalyses::none();
}
