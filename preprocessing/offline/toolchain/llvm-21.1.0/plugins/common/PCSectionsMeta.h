#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"

namespace llvm {
class Constant;
class Instruction;
}

namespace chimera {

void addOrMergePCSection(
    llvm::Instruction &I,
    llvm::StringRef SectionName,
    llvm::ArrayRef<llvm::Constant *> AuxConstants);

void addOrMergeDeferredPCSection(
    llvm::Instruction &I,
    llvm::StringRef SectionName,
    llvm::ArrayRef<llvm::Constant *> AuxConstants);

} // namespace chimera