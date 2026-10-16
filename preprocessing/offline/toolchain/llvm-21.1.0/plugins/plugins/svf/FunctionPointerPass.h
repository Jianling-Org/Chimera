#pragma once

#include "llvm/IR/PassManager.h"

namespace chimera {

class FunctionPointerPass
    : public llvm::PassInfoMixin<FunctionPointerPass> {
public:
  llvm::PreservedAnalyses
  run(llvm::Module &M,
      llvm::ModuleAnalysisManager &MAM);
};

} // namespace chimera