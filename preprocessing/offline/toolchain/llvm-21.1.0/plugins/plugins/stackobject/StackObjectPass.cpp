#include "StackObjectPass.h"

#include "InlineAsm.h"
#include "PCSectionsMeta.h"
#include "RVVIntrinsic.h"
#include "StackAddress.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"

#include <cstdint>
#include <utility>

using namespace llvm;

namespace chimera {

namespace {

using StackKey =
    std::pair<AllocaInst *, int64_t>;

constexpr uint32_t ExplicitStackObjectLimit =
    0x80000000u;

cl::opt<bool> StackObjectDebug(
    "chimera-stackobject-debug",
    cl::desc("Print successful Chimera StackObject analysis details"),
    cl::init(false),
    cl::Hidden);


uint32_t lookupOrCreateStackObjectID(
    DenseMap<StackKey, uint32_t> &Registry,
    uint32_t &NextID,
    AllocaInst *AI,
    int64_t Offset) {

  StackKey Key{AI, Offset};

  auto It = Registry.find(Key);
  if (It != Registry.end())
    return It->second;

  if (NextID >= ExplicitStackObjectLimit)
    report_fatal_error(
        "Chimera explicit StackObjectID overflow");

  uint32_t ID = NextID++;
  Registry.insert({Key, ID});

  return ID;
}


void printExactStackResult(
    Function &F,
    Instruction &I,
    const StackAddr &Addr,
    uint32_t SOID) {

  errs() << "[Chimera StackObject]\n";
  errs() << "  function: " << F.getName() << "\n";

  errs() << "  instruction: ";
  I.print(errs());
  errs() << "\n";

  errs() << "  alloca: ";
  Addr.Alloca->printAsOperand(errs(), false);
  errs() << "\n";

  errs() << "  offset: " << Addr.Offset << "\n";
  errs() << "  SOID: " << SOID << "\n";
}


void printInlineAsmExactStackResult(
    Function &F,
    Instruction &I,
    const StackAddr &Addr,
    uint32_t SOID,
    unsigned TargetInstructionIndex) {

  errs() << "[Chimera StackObject InlineAsm]\n";
  errs() << "  function: " << F.getName() << "\n";

  errs() << "  instruction: ";
  I.print(errs());
  errs() << "\n";

  errs() << "  target-index: "
         << TargetInstructionIndex << "\n";

  errs() << "  alloca: ";
  Addr.Alloca->printAsOperand(errs(), false);
  errs() << "\n";

  errs() << "  offset: " << Addr.Offset << "\n";
  errs() << "  SOID: " << SOID << "\n";
}


void printUnknownIntrinsicAddressWarning(
    Function &F,
    Instruction &I) {

  errs()
      << "warning: [Chimera StackObject] "
         "cannot determine whether RVV address belongs to "
         "the current function stack\n"
      << "  function: " << F.getName() << "\n"
      << "  instruction: ";

  I.print(errs());
  errs() << "\n";
}


void printUnknownInlineAsmAddressWarning(
    Function &F,
    Instruction &I,
    StringRef Reason) {

  errs()
      << "warning: [Chimera StackObject] "
         "cannot resolve inline-asm RVV address\n"
      << "  function: " << F.getName() << "\n";

  if (!Reason.empty())
    errs() << "  reason: " << Reason << "\n";

  errs() << "  instruction: ";
  I.print(errs());
  errs() << "\n";
}


void printUnsupportedInlineAsmWarning(
    Function &F,
    Instruction &I,
    StringRef Reason) {

  errs()
      << "warning: [Chimera StackObject] "
         "unsupported relevant inline asm\n"
      << "  function: " << F.getName() << "\n";

  if (!Reason.empty())
    errs() << "  reason: " << Reason << "\n";

  errs() << "  instruction: ";
  I.print(errs());
  errs() << "\n";
}


} // namespace


PreservedAnalyses
StackObjectPass::run(
    Function &F,
    FunctionAnalysisManager &) {

  const Module &M = *F.getParent();
  const DataLayout &DL = M.getDataLayout();
  const Triple TargetTriple(M.getTargetTriple());

  if (!TargetTriple.isRISCV64() ||
      DL.getPointerSizeInBits(/*AddressSpace=*/0) != 64)
    report_fatal_error(
        "Chimera StackObject requires a riscv64 target "
        "with 64-bit pointers");

  bool Changed = !F.hasFnAttribute("chimera-stack-object");
  F.addFnAttr("chimera-stack-object");

  /*
   * StackObjectID is function-local.
   *
   * Intrinsics and inline asm share the same registry so that:
   *
   *   intrinsic -> (alloca, offset)
   *   inline asm -> (alloca, offset)
   *
   * receive the same SOID when they refer to the same stack object.
   */
  DenseMap<StackKey, uint32_t> Registry;
  uint32_t NextID = 0;

  for (BasicBlock &BB : F) {
    for (Instruction &I : BB) {

      auto *CB = dyn_cast<CallBase>(&I);
      if (!CB)
        continue;


      /*
      * Inline asm:
      *
      *   - locate the RVV memory instruction;
      *   - resolve its address;
      *   - classify the address;
      *   - assign/query the shared SOID;
      *   - attach deferred Chimera PCSections metadata.
      *
      * Inline asm cannot use the generic IR !pcsections lowering
      * path because a void inline-asm call may not have a NodeMap
      * entry in SelectionDAGBuilder.
      *
      * Therefore use !chimera.pcsections here. visitInlineAsm()
      * will transfer it directly to the exact ISD::INLINEASM node.
      *
      * The target instruction locator will later be consumed by
      * AsmPrinter so that the final label is emitted immediately
      * before the target RVV memory instruction.
      */
      if (isa<llvm::InlineAsm>(
              CB->getCalledOperand())) {

        InlineAsmAccess IA =
            analyzeInlineAsmMemoryAccess(*CB);

        switch (IA.Kind) {

        /*
         * These should normally only mean "nothing to do".
         */
        case InlineAsmAccessKind::NotInlineAsm:
        case InlineAsmAccessKind::NoTarget:
        case InlineAsmAccessKind::ProvenNonStack:
          break;


        /*
         * Relevant inline asm exists, but its instruction
         * structure is outside the M4a whitelist.
         *
         * Do not fail compilation.
         */
        case InlineAsmAccessKind::UnsupportedRelevant:
          if (StackObjectDebug)
            printUnsupportedInlineAsmWarning(
                F,
                I,
                IA.Message);
          break;


        /*
         * We found the target RVV memory instruction,
         * but its internal address expression could not
         * be reduced to CallBaseArg + Constant.
         */
        case InlineAsmAccessKind::UnknownAddress:
          if (StackObjectDebug)
            printUnknownInlineAsmAddressWarning(
                F,
                I,
                IA.Message);
          break;


        /*
         * The inline asm address was reduced to:
         *
         *   IA.Pointer + IA.ExtraOffset
         *
         * Reuse exactly the same StackAddress classifier
         * used by RVV intrinsics.
         */
        case InlineAsmAccessKind::ResolvedInput: {

          StackAddr Addr =
              classifyStackAddress(
                  IA.Pointer,
                  IA.ExtraOffset,
                  DL,
                  F);

          switch (Addr.Kind) {

            case StackAddrKind::ExactStack: {
              uint32_t SOID =
                  lookupOrCreateStackObjectID(
                      Registry,
                      NextID,
                      Addr.Alloca,
                      Addr.Offset);

              LLVMContext &Ctx =
                  F.getContext();

              /*
              * Deferred inline-asm PCSections format:
              *
              *   !chimera.pcsections
              *       !{
              *         !".chimera.stackobj_map!AL",
              *         !{i32 TargetInstructionIndex, i32 SOID}
              *       }
              *
              * A:
              *   final ELF record contains absolute linked VA.
              *
              * L:
              *   first auxiliary value is an internal inline-asm
              *   instruction locator.
              *
              *   It is consumed by the backend and must not appear
              *   in the final .chimera.stackobj_map wire format.
              */
              Constant *TargetIndexConstant =
                  ConstantInt::get(
                      Type::getInt32Ty(Ctx),
                      IA.TargetInstructionIndex);

              Constant *SOIDConstant =
                  ConstantInt::get(
                      Type::getInt32Ty(Ctx),
                      SOID);

              Constant *Aux[] = {
                  TargetIndexConstant,
                  SOIDConstant,
              };

              /*
              * IMPORTANT:
              *
              * Do not use addOrMergePCSection() here.
              *
              * Inline asm uses the deferred carrier because generic
              * SelectionDAG !pcsections propagation cannot reliably
              * associate a void inline-asm CallInst with the actual
              * ISD::INLINEASM node.
              */
              addOrMergeDeferredPCSection(
                  I,
                  ".chimera.stackobj_map!AL",
                  Aux);

              Changed = true;

              if (StackObjectDebug)
                printInlineAsmExactStackResult(
                    F,
                    I,
                    Addr,
                    SOID,
                    IA.TargetInstructionIndex);

              break;
            }


          case StackAddrKind::
              ProvenNotCurrentLocalAlloca:
            /*
             * Proven not to be a current-function
             * local stack object.
             */
            break;


          case StackAddrKind::MultipleLocations:
            /*
             * One RVV memory instruction may access multiple
             * possible locations.
             *
             * By design this is silently ignored.
             */
            break;


          case StackAddrKind::UnknownProvenance:
            /*
             * A single address remains, but we cannot prove
             * whether it belongs to the current function stack.
             */
            errs()
                << "warning: [Chimera StackObject] "
                   "cannot determine whether inline-asm address "
                   "belongs to the current function stack\n"
                << "  function: "
                << F.getName() << "\n"
                << "  instruction: ";

            I.print(errs());
            errs() << "\n";
            break;
          }

          break;
        }
        }

        /*
         * This CallBase is inline asm. Do not feed it into
         * the intrinsic recognizer below.
         */
        continue;
      }


      /*
       * ========================================================
       * Path 1:
       * supported RVV memory intrinsic.
       * ========================================================
       */
      if (Value *Ptr =
              getRVVMemoryPointerOperand(*CB)) {

        StackAddr Addr =
            classifyStackAddress(
                Ptr,
                /*ExtraOffset=*/0,
                DL,
                F);

        switch (Addr.Kind) {

        case StackAddrKind::ExactStack: {
          uint32_t SOID =
              lookupOrCreateStackObjectID(
                  Registry,
                  NextID,
                  Addr.Alloca,
                  Addr.Offset);

          LLVMContext &Ctx =
              F.getContext();

          Constant *SOIDConstant =
              ConstantInt::get(
                  Type::getInt32Ty(Ctx),
                  SOID);

          Constant *Aux[] = {
              SOIDConstant,
          };

          addOrMergePCSection(
              I,
              ".chimera.stackobj_map!A",
              Aux);

          Changed = true;

          if (StackObjectDebug)
            printExactStackResult(
                F,
                I,
                Addr,
                SOID);

          break;
        }


        case StackAddrKind::
            ProvenNotCurrentLocalAlloca:
          /*
           * This access is provably not to a
           * current-function local alloca.
           */
          break;


        case StackAddrKind::MultipleLocations:
          /*
           * One final RVV memory instruction can access
           * multiple locations.
           *
           * Cannot represent this as:
           *
           *   LinkedVA -> one SOID
           *
           * Silently ignore it.
           */
          break;


        case StackAddrKind::UnknownProvenance:
          printUnknownIntrinsicAddressWarning(
              F,
              I);
          break;
        }

        continue;
      }


      /*
       * ========================================================
       * Path 2a:
       * indexed gather/scatter (vluxei/vloxei/vsuxei/vsoxei).
       *
       * The address is a pointer/index vector (multiple addresses),
       * which cannot be mapped to a single StackObjectID. This is a
       * permanent design limitation, not a missing feature: silently
       * ignore, never warn.
       * ========================================================
       */
      if (isIndexedRVVMemoryIntrinsic(*CB))
        continue;

      /*
       * ========================================================
       * Path 2:
       * an RVV-specific memory intrinsic exists,
       * but the current implementation does not support it.
       *
       * TODO: temporary downgrade — this is a real RVV memory
       * access (e.g. first-fault vle8ff, strided-segment vlsseg)
       * not yet covered by the whitelist. Warn and skip instead of
       * failing. Extend getRVVMemoryPointerOperand() to cover these
       * families later.
       * ========================================================
       */
      if (isUnsupportedRVVMemoryIntrinsic(*CB)) {

        errs()
            << "warning: [Chimera StackObject] "
               "unsupported RVV memory intrinsic (not marked)\n"
            << "  function: "
            << F.getName() << "\n"
            << "  instruction: ";

        I.print(errs());
        errs() << "\n";

        continue;
      }


      /*
       * ========================================================
       * Path 3:
       * ordinary call/intrinsic.
       *
       * Ignore.
       * ========================================================
       */
    }
  }


  if (Changed)
    return PreservedAnalyses::none();

  return PreservedAnalyses::all();
}


} // namespace chimera
