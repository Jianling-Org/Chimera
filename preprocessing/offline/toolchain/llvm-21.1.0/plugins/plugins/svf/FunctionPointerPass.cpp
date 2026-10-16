#include "FunctionPointerPass.h"

#include "PCSectionsMeta.h"

#include "SVF-LLVM/LLVMModule.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "SVFIR/SVFIR.h"
#include "Util/CommandLine.h"
#include "Util/ExtAPI.h"
#include "Util/Options.h"
#include "WPA/Andersen.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Cloning.h"

#include <dlfcn.h>

#include <cstdlib>
#include <filesystem>
#include <string>

using namespace llvm;

namespace chimera {

std::string getExtAPIPath() {
  Dl_info Info{};

  /*
   * Ask the dynamic loader which shared object contains this
   * function. Since this function is compiled into
   * ChimeraFunctionPointer.so, dli_fname identifies the plugin.
   */
  if (dladdr(
          reinterpret_cast<const void *>(&getExtAPIPath),
          &Info) == 0 ||
      Info.dli_fname == nullptr) {
    return {};
  }

  std::filesystem::path PluginPath(Info.dli_fname);

  return (PluginPath.parent_path() / "extapi.bc").string();
}


PreservedAnalyses
FunctionPointerPass::run(
    Module &M,
    ModuleAnalysisManager &) {

  /*
   * Collect indirect callsites from the ORIGINAL module.
   *
   * Metadata must eventually be attached to these instructions,
   * not to the SVF analysis clone.
   */
  SmallVector<CallBase *, 16> OriginalCallsites;

  for (Function &F : M) {
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        auto *CB = dyn_cast<CallBase>(&I);

        if (!CB || !CB->isIndirectCall())
          continue;

        OriginalCallsites.push_back(CB);
      }
    }
  }

  if (OriginalCallsites.empty())
    return PreservedAnalyses::all();

  /*
   * Clone the final optimized Full-LTO module.
   *
   * SVF may preprocess/mutate its LLVM module, so it must
   * never operate directly on the module that enters CodeGen.
   *
   * VMap:
   *
   *   original LLVM Value -> cloned LLVM Value
   */
  ValueToValueMapTy VMap;

  std::unique_ptr<Module> AnalysisModule =
      CloneModule(M, VMap);

  /*
   * Reverse function mapping:
   *
   *   cloned Function -> original Function
   *
   * Not every cloned/SVF function is necessarily present here.
   * For example, SVF may introduce/model external functions.
   * Such cases make the corresponding callsite unresolved.
   */
  DenseMap<const Function *, Function *>
      CloneToOriginalFunction;

  for (Function &OriginalF : M) {
    Value *Mapped =
        VMap.lookup(&OriginalF);

    auto *CloneF =
        dyn_cast_or_null<Function>(Mapped);

    if (!CloneF)
      continue;

    CloneToOriginalFunction[CloneF] =
        &OriginalF;
  }

  LLVMContext &Ctx = M.getContext();

  Type *I32Ty =
      Type::getInt32Ty(Ctx);

  Type *AddressTy =
      M.getDataLayout().getIntPtrType(Ctx);

  /*
   * Helper for attaching:
   *
   *   target_count = 0
   *
   * Semantics:
   *   function-pointer analysis for this callsite is
   *   unavailable or incomplete.
   */
  auto AttachUnresolved =
      [&](CallBase &CB) {
        Constant *Aux[] = {
            ConstantInt::get(I32Ty, 0),
        };

        addOrMergeDeferredPCSection(
            CB,
            ".chimera.function_pointer!A",
            Aux);
      };

  /*
   * Configure SVF's external API model.
   *
   * If extapi.bc is unavailable, we cannot trust function
   * pointer analysis. Do not abort compilation: explicitly
   * mark every indirect callsite as unresolved instead.
   */
  const std::string ExtAPIPath = getExtAPIPath();

  if (ExtAPIPath.empty() || !SVF::ExtAPI::setExtBcPath(ExtAPIPath)) {
    errs() << "[Chimera SVF] extapi.bc unavailable; "
              "all indirect calls unresolved\n";

    for (CallBase *CB : OriginalCallsites)
      AttachUnresolved(*CB);

    return PreservedAnalyses::none();
  }

  /*
   * Memory knob (measured pain point): a whole-program Andersen run on
   * a large C++ module (llama.cpp) needs many GB; field sensitivity is
   * the main PAG size multiplier. CHIMERA_SVF_FIELD_LIMIT overrides
   * SVF's field-limit (default 512) for this analysis, trading field
   * precision for memory. The variable is read from the link-process
   * environment (clang++ -> ld.lld inherit it), so it can be set per
   * build without rebuilding the plugin.
   */
  if (const char *EnvLimit =
          std::getenv("CHIMERA_SVF_FIELD_LIMIT")) {
    char *End = nullptr;
    unsigned long Value =
        std::strtoul(EnvLimit, &End, 10);

    if (End != EnvLimit && *End == '\0') {
      /*
       * SVF-3.3's Option<T> (Util/CommandLine.h) lives in the GLOBAL
       * namespace, not namespace SVF; only Options (Util/Options.h)
       * is namespaced. Do not qualify Option with SVF:: here.
       */
      const_cast<Option<SVF::u32_t> &>(
          SVF::Options::MaxFieldLimit)
          .setValue(
              static_cast<SVF::u32_t>(Value));
      errs() << "[Chimera SVF] field-limit="
             << Value << " (env override)\n";
    } else {
      errs() << "[Chimera SVF] ignoring invalid "
                "CHIMERA_SVF_FIELD_LIMIT='"
             << EnvLimit << "'\n";
    }
  }

  /*
   * Build SVF representation on the cloned module.
   */
  SVF::LLVMModuleSet::buildSVFModule(
      *AnalysisModule);

  SVF::SVFIRBuilder Builder;

  SVF::SVFIR *Pag =
      Builder.build();

  /*
   * Run Andersen WaveDiff manually rather than using
   * createAndersenWaveDiff().
   *
   * The factory immediately calls analyze(), which would
   * print SVF statistics before we had a chance to disable
   * them.
   */
  auto *Andersen =
      new SVF::AndersenWaveDiff(
          Pag,
          SVF::PointerAnalysis::AndersenWaveDiff_WPA,
          false);

  Andersen->disablePrintStat();
  Andersen->analyze();

  SVF::LLVMModuleSet *ModuleSet =
      SVF::LLVMModuleSet::
          getLLVMModuleSet();

  /*
   * Analyze each ORIGINAL indirect callsite.
   */
  for (CallBase *OriginalCB :
       OriginalCallsites) {

    bool Unresolved = false;

    SmallVector<Function *, 8>
        OriginalTargets;

    /*
     * original CallBase -> cloned CallBase
     */
    Value *Mapped =
        VMap.lookup(OriginalCB);

    auto *CloneCB =
        dyn_cast_or_null<CallBase>(Mapped);

    if (!CloneCB) {
      Unresolved = true;
    }

    /*
     * cloned CallBase -> SVF CallICFGNode
     */
    SVF::CallICFGNode *CallNode = nullptr;

    if (!Unresolved) {
      if (!ModuleSet->hasICFGNode(CloneCB)) {
        Unresolved = true;
      } else {
        CallNode =
            ModuleSet->getCallICFGNode(
                CloneCB);
      }
    }

    /*
     * Andersen must provide a non-empty target set.
     *
     * Empty means Chimera cannot obtain a useful complete
     * target set for this callsite, so encode count = 0.
     */
    if (!Unresolved) {
      if (!Andersen->hasIndCSCallees(
              CallNode)) {
        Unresolved = true;
      }
    }

    if (!Unresolved) {
      const auto &SVFTargets =
          Andersen->getIndCSCallees(
              CallNode);

      if (SVFTargets.empty()) {
        Unresolved = true;
      } else {

        /*
         * Map every SVF target:
         *
         *   SVF FunObjVar
         *       ->
         *   cloned LLVM Function
         *       ->
         *   original LLVM Function
         *
         * IMPORTANT:
         *
         * The result is usable only if ALL targets can be
         * represented. A partially recovered target set must
         * never be emitted as if it were complete.
         */
        for (const SVF::FunObjVar *Target :
             SVFTargets) {

          if (!ModuleSet->hasLLVMValue(
                  Target)) {
            Unresolved = true;
            break;
          }

          const Value *CloneValue =
              ModuleSet->getLLVMValue(
                  Target);

          const auto *CloneTarget =
              dyn_cast<Function>(
                  CloneValue);

          if (!CloneTarget) {
            Unresolved = true;
            break;
          }

          auto It =
              CloneToOriginalFunction.find(
                  CloneTarget);

          if (It ==
              CloneToOriginalFunction.end()) {
            Unresolved = true;
            break;
          }

          Function *OriginalTarget =
              It->second;

          /*
           * The current metadata ABI represents targets using
           * linked addresses inside the current ELF.
           *
           * An external declaration has no function body
           * address in this ELF, so the complete target set
           * cannot currently be represented.
           */
          if (OriginalTarget->
                  isDeclaration()) {
            Unresolved = true;
            break;
          }

          OriginalTargets.push_back(
              OriginalTarget);
        }
      }
    }

    /*
     * Never retain a partial result.
     */
    if (Unresolved)
      OriginalTargets.clear();

    SmallVector<Constant *, 8>
        AuxData;

    if (Unresolved) {
      /*
       * ABI:
       *
       * target_count == 0
       *
       * means function-pointer analysis is unavailable
       * or incomplete for this callsite.
       */
      AuxData.push_back(
          ConstantInt::get(
              I32Ty,
              0));

    } else {
      /*
       * Deterministic output.
       *
       * Do not let SVF set iteration order affect the
       * generated ELF metadata.
       */
      llvm::sort(
          OriginalTargets,
          [](const Function *A,
             const Function *B) {
            return A->getName() <
                   B->getName();
          });

      AuxData.push_back(
          ConstantInt::get(
              I32Ty,
              OriginalTargets.size()));

      for (Function *Target :
           OriginalTargets) {

        AuxData.push_back(
            ConstantExpr::getPtrToInt(
                Target,
                AddressTy));
      }
    }

    /*
     * Final record:
     *
     * successful:
     *
     *   pointer call_addr
     *   u32     target_count
     *   pointer targets[target_count]
     *
     * unresolved:
     *
     *   pointer call_addr
     *   u32     0
     */
    addOrMergeDeferredPCSection(
        *OriginalCB,
        ".chimera.function_pointer!A",
        AuxData);
  }

  /*
   * Clean up SVF global/singleton state.
   */
  delete Andersen;

  SVF::SVFIR::releaseSVFIR();

  SVF::LLVMModuleSet::
      releaseLLVMModuleSet();

  /*
   * Every indirect callsite received metadata.
   */
  return PreservedAnalyses::none();
}

} // namespace chimera