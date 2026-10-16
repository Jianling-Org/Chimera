#pragma once

#include <cstdint>
#include <string>

namespace llvm {
class CallBase;
class Value;
}

namespace chimera {

enum class InlineAsmAccessKind {
  NotInlineAsm,
  NoTarget,

  // 成功解析成：
  //
  //   CallBase argument + constant byte offset
  //
  ResolvedInput,

  // 例如从 zero/常量地址计算出来，可以证明不是当前
  // function 的 local alloca。
  ProvenNonStack,

  // 含目标 RVV memory instruction，但 asm block 不符合
  // Chimera 支持规则。
  UnsupportedRelevant,

  // 目标唯一，但地址表达式无法解析。
  UnknownAddress,
};

struct InlineAsmAccess {
  InlineAsmAccessKind Kind =
      InlineAsmAccessKind::NotInlineAsm;

  llvm::Value *Pointer = nullptr;

  // Pointer + ExtraOffset
  int64_t ExtraOffset = 0;

  // 目标 RVV memory instruction 在 asm block 中的
  // actual-instruction index，0-based。
  //
  // M4b/M4c 会用它。
  unsigned TargetInstructionIndex = 0;

  std::string Message;
};

InlineAsmAccess
analyzeInlineAsmMemoryAccess(llvm::CallBase &CB);

} // namespace chimera