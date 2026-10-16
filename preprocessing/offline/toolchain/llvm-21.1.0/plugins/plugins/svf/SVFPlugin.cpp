#include "FunctionPointerPass.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

extern "C" LLVM_ATTRIBUTE_WEAK
PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION,
      "ChimeraFunctionPointer",
      LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerFullLinkTimeOptimizationLastEPCallback(
            [](ModulePassManager &MPM,
               OptimizationLevel) {
              MPM.addPass(
                  chimera::FunctionPointerPass());
            });
      }};
}