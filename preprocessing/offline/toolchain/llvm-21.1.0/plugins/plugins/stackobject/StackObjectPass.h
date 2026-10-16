#pragma once

#include "llvm/IR/PassManager.h"

namespace chimera {

class StackObjectPass
    : public llvm::PassInfoMixin<StackObjectPass> {
public:
  llvm::PreservedAnalyses
  run(llvm::Function &F,
      llvm::FunctionAnalysisManager &AM);

  static bool isRequired() {
    return true;
  }
};

} // namespace chimera