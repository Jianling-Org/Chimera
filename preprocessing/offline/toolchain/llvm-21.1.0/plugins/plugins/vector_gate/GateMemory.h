#pragma once

#include "llvm/IR/PassManager.h"

namespace chimera {

// After the last IR optimizer, keep a memory intrinsic from becoming a
// native memset call across live explicit RVV state. Inlining stays unchanged.
class GateLocalMemsetPass : public llvm::PassInfoMixin<GateLocalMemsetPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &, llvm::ModuleAnalysisManager &);
};

} // namespace chimera
