#include "StackObjectPass.h"

#include "llvm/Config/llvm-config.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

extern "C"
LLVM_ATTRIBUTE_WEAK
PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "ChimeraStackObject",
      LLVM_VERSION_STRING,

      [](PassBuilder &PB) {
        // EP registration lets plain `-fpass-plugin` schedule the pass at
        // the end of the per-TU optimization pipeline (equivalent to
        // appending it after default<O2>) — no `-mllvm -passes=...`
        // pipeline string, whose shell-hostile characters break CMake
        // compile rules and which leaks into the LTO link pipeline.
        PB.registerOptimizerLastEPCallback(
            [](ModulePassManager &MPM,
               OptimizationLevel,
               ThinOrFullLTOPhase) {
              MPM.addPass(
                  createModuleToFunctionPassAdaptor(
                      chimera::StackObjectPass()));
            });

        // Named-pipeline form is kept for opt-driven flows
        // (`opt -passes='...,function(chimera-stack-object)'`).
        PB.registerPipelineParsingCallback(
            [](StringRef Name,
               FunctionPassManager &FPM,
               ArrayRef<
                   PassBuilder::PipelineElement>) {

              if (Name !=
                  "chimera-stack-object")
                return false;

              FPM.addPass(
                  chimera::StackObjectPass());

              return true;
            });
      }};
}
