#pragma once

#include "llvm/IR/PassManager.h"

namespace chimera {

// Keep explicit RVV leaf state out of the scalar control/callback frame.
// The outlined definition must retain the caller's Gate policy as well.
class GateRvvBoundaryPass : public llvm::PassInfoMixin<GateRvvBoundaryPass> {
public:
  llvm::PreservedAnalyses run(llvm::Module &, llvm::ModuleAnalysisManager &);
};

} // namespace chimera
