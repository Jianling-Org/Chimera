#pragma once

namespace llvm {
class CallBase;
class Value;
}

namespace chimera {

llvm::Value *
getRVVMemoryPointerOperand(llvm::CallBase &CB);

bool
isUnsupportedRVVMemoryIntrinsic(
    llvm::CallBase &CB);

// Indexed gather/scatter（vluxei/vloxei/vsuxei/vsoxei）：
// 多地址，无法映射单一 StackObjectID，永久静默忽略。
bool
isIndexedRVVMemoryIntrinsic(
    llvm::CallBase &CB);

} // namespace chimera