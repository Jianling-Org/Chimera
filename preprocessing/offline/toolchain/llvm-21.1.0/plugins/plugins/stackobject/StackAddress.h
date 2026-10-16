#pragma once

#include <cstdint>

namespace llvm {
class AllocaInst;
class DataLayout;
class Function;
class Value;
}

namespace chimera {

enum class StackAddrKind {
  // 唯一确定的当前函数栈位置。
  ExactStack,

  // 唯一确定的位置，且可以证明不是当前函数局部 alloca。
  ProvenNotCurrentLocalAlloca,

  // 可以确定该访问可能对应多个位置。
  MultipleLocations,

  // 没发现多个位置，但无法判断这个位置是否属于当前函数栈。
  UnknownProvenance,
};

struct StackAddr {
  StackAddrKind Kind;
  llvm::AllocaInst *Alloca = nullptr;
  int64_t Offset = 0;
};

StackAddr classifyStackAddress(
    llvm::Value *Ptr,
    int64_t ExtraOffset,
    const llvm::DataLayout &DL,
    llvm::Function &F);

} // namespace chimera