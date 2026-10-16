#include "InlineAsm.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/Support/MathExtras.h"

#include <optional>
#include <string>

using namespace llvm;

namespace chimera {
namespace {

enum class ExprKind {
  Unknown,

  // CallBase argument + Offset
  Input,

  // Absolute constant + Offset
  Constant,
};

struct Expr {
  ExprKind Kind = ExprKind::Unknown;

  unsigned ArgIndex = 0;
  int64_t Offset = 0;
};

struct ParsedInstruction {
  StringRef Text;
  StringRef Mnemonic;
  StringRef Operands;
};

static Expr unknownExpr() {
  return {};
}

static Expr inputExpr(
    unsigned ArgIndex,
    int64_t Offset = 0) {

  Expr E;
  E.Kind = ExprKind::Input;
  E.ArgIndex = ArgIndex;
  E.Offset = Offset;
  return E;
}

static Expr constantExpr(int64_t Value) {
  Expr E;
  E.Kind = ExprKind::Constant;
  E.Offset = Value;
  return E;
}

static Expr addConstant(
    Expr E,
    int64_t Delta) {

  if (E.Kind == ExprKind::Unknown)
    return E;

  int64_t NewOffset = 0;

  if (AddOverflow(
          E.Offset,
          Delta,
          NewOffset))
    return unknownExpr();

  E.Offset = NewOffset;
  return E;
}


// ------------------------------------------------------------
// Basic asm parsing
// ------------------------------------------------------------

static StringRef stripComment(StringRef S) {
  size_t Pos = S.find('#');

  if (Pos != StringRef::npos)
    S = S.take_front(Pos);

  return S.trim();
}

static bool isDirective(StringRef S) {
  return S.starts_with(".");
}

static bool isAllowedDirective(StringRef S) {
  // .option does not emit an actual instruction.
  //
  // Do not generally accept arbitrary directives because things such
  // as .word / .insn may emit bytes and break TargetInstructionIndex.
  return S.starts_with(".option");
}

static bool isLabel(StringRef S) {
  return S.ends_with(":");
}

static std::optional<ParsedInstruction>
parseInstruction(StringRef S) {

  S = stripComment(S);

  if (S.empty())
    return std::nullopt;

  size_t Pos =
      S.find_first_of(" \t");

  if (Pos == StringRef::npos) {
    return ParsedInstruction{
        S,
        S,
        StringRef(),
    };
  }

  return ParsedInstruction{
      S,
      S.take_front(Pos),
      S.drop_front(Pos).trim(),
  };
}

static void splitStatements(
    StringRef Asm,
    SmallVectorImpl<StringRef> &Result) {

  SmallVector<StringRef, 16> Lines;
  Asm.split(
      Lines,
      '\n',
      /*MaxSplit=*/-1,
      /*KeepEmpty=*/false);

  for (StringRef Line : Lines) {
    SmallVector<StringRef, 8> Statements;

    Line.split(
        Statements,
        ';',
        /*MaxSplit=*/-1,
        /*KeepEmpty=*/false);

    for (StringRef Statement : Statements) {
      Statement = stripComment(Statement);

      if (!Statement.empty())
        Result.push_back(Statement);
    }
  }
}


// ------------------------------------------------------------
// RVV memory instruction recognition
// ------------------------------------------------------------

static bool startsWithDigitAfter(
    StringRef Mnemonic,
    StringRef Prefix) {

  if (!Mnemonic.consume_front(Prefix))
    return false;

  if (Mnemonic.empty())
    return false;

  return Mnemonic.front() >= '0' &&
         Mnemonic.front() <= '9';
}

static bool isRVVMemoryMnemonic(
    StringRef Mnemonic) {

  std::string LowerStorage =
      Mnemonic.lower();

  StringRef M(LowerStorage);

  // Unit-stride / fault-only-first.
  //
  // vle8.v
  // vle8ff.v
  // vse8.v
  if (startsWithDigitAfter(M, "vle") ||
      startsWithDigitAfter(M, "vse"))
    return true;

  // Strided.
  //
  // vlse8.v
  // vsse8.v
  if (startsWithDigitAfter(M, "vlse") ||
      startsWithDigitAfter(M, "vsse"))
    return true;

  // Indexed.
  //
  // vluxei32.v
  // vloxei32.v
  // vsuxei32.v
  // vsoxei32.v
  if (startsWithDigitAfter(M, "vluxei") ||
      startsWithDigitAfter(M, "vloxei") ||
      startsWithDigitAfter(M, "vsuxei") ||
      startsWithDigitAfter(M, "vsoxei"))
    return true;

  // Segment.
  //
  // vlseg2e8.v
  // vlsseg2e8.v
  // vluxseg2ei32.v
  // vloxseg2ei32.v
  //
  // stores similarly.
  if (startsWithDigitAfter(M, "vlseg") ||
      startsWithDigitAfter(M, "vlsseg") ||
      startsWithDigitAfter(M, "vluxseg") ||
      startsWithDigitAfter(M, "vloxseg") ||
      startsWithDigitAfter(M, "vsseg") ||
      startsWithDigitAfter(M, "vssseg") ||
      startsWithDigitAfter(M, "vsuxseg") ||
      startsWithDigitAfter(M, "vsoxseg"))
    return true;

  // Whole-register loads.
  //
  // vl1re8.v
  // vl2re8.v
  // vl4re8.v
  // vl8re8.v
  if (startsWithDigitAfter(M, "vl1re") ||
      startsWithDigitAfter(M, "vl2re") ||
      startsWithDigitAfter(M, "vl4re") ||
      startsWithDigitAfter(M, "vl8re"))
    return true;

  // Whole-register stores.
  if (M == "vs1r.v" ||
      M == "vs2r.v" ||
      M == "vs4r.v" ||
      M == "vs8r.v")
    return true;

  // Mask load/store.
  if (M == "vlm.v" ||
      M == "vsm.v")
    return true;

  return false;
}


// ------------------------------------------------------------
// LLVM inline-asm operand mapping
//
// asm:
//     "$1"
//
// constraint:
//     "=r,r"
//
// $1 means constraint #1, but CallBase argument #0.
// ------------------------------------------------------------

static bool parseAsmOperandNumber(
    StringRef Token,
    unsigned &OperandNumber) {

  Token = Token.trim();

  if (!Token.consume_front("$"))
    return false;

  // $0
  if (!Token.starts_with("{"))
    return !Token.getAsInteger(
        10,
        OperandNumber);

  // ${0}
  // ${0:modifier}
  Token = Token.drop_front();

  size_t End = Token.find('}');

  if (End == StringRef::npos)
    return false;

  StringRef Body =
      Token.take_front(End);

  size_t Colon = Body.find(':');

  if (Colon != StringRef::npos)
    Body = Body.take_front(Colon);

  return !Body.getAsInteger(
      10,
      OperandNumber);
}

static std::string operandKey(unsigned N) {
  return "operand:" + std::to_string(N);
}

static std::string registerKey(StringRef R) {
  return "register:" + R.lower();
}

static bool isSimpleDestination(
    StringRef Token) {

  Token = Token.trim();

  unsigned Dummy = 0;

  if (parseAsmOperandNumber(Token, Dummy))
    return true;

  if (Token.empty())
    return false;

  for (char C : Token) {
    if (!isalnum(
            static_cast<unsigned char>(C)) &&
        C != '_' &&
        C != '.')
      return false;
  }

  return true;
}

static std::string valueKey(StringRef Token) {
  unsigned OperandNumber = 0;

  if (parseAsmOperandNumber(
          Token,
          OperandNumber))
    return operandKey(OperandNumber);

  return registerKey(Token.trim());
}


// ------------------------------------------------------------
// Constraint -> CallBase argument map
// ------------------------------------------------------------

static bool buildOperandArgumentMap(
    CallBase &CB,
    InlineAsm &IA,
    SmallVectorImpl<int> &OperandToArg) {

  InlineAsm::ConstraintInfoVector Constraints =
      IA.ParseConstraints();

  if (Constraints.empty() &&
      !IA.getConstraintString().empty())
    return false;

  OperandToArg.assign(
      Constraints.size(),
      -1);

  unsigned ArgIndex = 0;

  for (unsigned I = 0;
       I < Constraints.size();
       ++I) {

    const InlineAsm::ConstraintInfo &C =
        Constraints[I];

    if (!C.hasArg())
      continue;

    if (ArgIndex >= CB.arg_size())
      return false;

    OperandToArg[I] =
        static_cast<int>(ArgIndex);

    ++ArgIndex;
  }

  return ArgIndex == CB.arg_size();
}


// ------------------------------------------------------------
// Expression state
// ------------------------------------------------------------

static Expr resolveToken(
    StringRef Token,
    const SmallVectorImpl<int> &OperandToArg,
    StringMap<Expr> &State) {

  Token = Token.trim();

  unsigned OperandNumber = 0;

  if (parseAsmOperandNumber(
          Token,
          OperandNumber)) {

    std::string Key =
        operandKey(OperandNumber);

    auto It = State.find(Key);

    if (It != State.end())
      return It->second;

    if (OperandNumber >=
        OperandToArg.size())
      return unknownExpr();

    int ArgIndex =
        OperandToArg[OperandNumber];

    if (ArgIndex < 0)
      return unknownExpr();

    return inputExpr(
        static_cast<unsigned>(ArgIndex));
  }

  std::string Lower =
      Token.lower();

  if (Lower == "zero" ||
      Lower == "x0")
    return constantExpr(0);

  int64_t Constant = 0;

  if (!Token.getAsInteger(
          0,
          Constant))
    return constantExpr(Constant);

  auto It =
      State.find(registerKey(Token));

  if (It == State.end())
    return unknownExpr();

  return It->second;
}

static bool setToken(
    StringRef Token,
    Expr E,
    StringMap<Expr> &State) {

  if (!isSimpleDestination(Token))
    return false;

  State[valueKey(Token)] = E;
  return true;
}

static void splitOperands(
    StringRef Operands,
    SmallVectorImpl<StringRef> &Result) {

  Operands.split(
      Result,
      ',',
      /*MaxSplit=*/-1,
      /*KeepEmpty=*/false);

  for (StringRef &Op : Result)
    Op = Op.trim();
}


// ------------------------------------------------------------
// Scalar whitelist
// ------------------------------------------------------------

static bool applyScalarInstruction(
    const ParsedInstruction &PI,
    const SmallVectorImpl<int> &OperandToArg,
    StringMap<Expr> &State) {

  std::string LowerStorage =
      PI.Mnemonic.lower();

  StringRef Mnemonic(LowerStorage);

  SmallVector<StringRef, 4> Ops;
  splitOperands(
      PI.Operands,
      Ops);

  if (Mnemonic == "nop")
    return Ops.empty();

  if (Mnemonic == "mv") {
    if (Ops.size() != 2)
      return false;

    Expr Src =
        resolveToken(
            Ops[1],
            OperandToArg,
            State);

    return setToken(
        Ops[0],
        Src,
        State);
  }

  if (Mnemonic == "addi") {
    if (Ops.size() != 3)
      return false;

    Expr Src =
        resolveToken(
            Ops[1],
            OperandToArg,
            State);

    int64_t Immediate = 0;

    if (Ops[2].getAsInteger(
            0,
            Immediate))
      return false;

    Expr Result =
        addConstant(
            Src,
            Immediate);

    return setToken(
        Ops[0],
        Result,
        State);
  }

  return false;
}


// ------------------------------------------------------------
// Parse target memory operand:
//     (a0)
//     32(a0)
//     ($0)
//     16($1)
// ------------------------------------------------------------

static bool parseMemoryAddress(
    StringRef Operands,
    StringRef &Base,
    int64_t &Offset) {

  size_t LParen =
      Operands.find('(');

  if (LParen == StringRef::npos)
    return false;

  size_t RParen =
      Operands.find(')', LParen + 1);

  if (RParen == StringRef::npos)
    return false;

  // Do not accept another memory-style operand.
  if (Operands.find(
          '(',
          RParen + 1) !=
      StringRef::npos)
    return false;

  Base =
      Operands.slice(
          LParen + 1,
          RParen).trim();

  if (Base.empty())
    return false;

  StringRef Before =
      Operands.take_front(LParen);

  size_t Comma =
      Before.rfind(',');

  StringRef OffsetToken;

  if (Comma == StringRef::npos)
    OffsetToken = Before.trim();
  else
    OffsetToken =
        Before.drop_front(
            Comma + 1).trim();

  if (OffsetToken.empty()) {
    Offset = 0;
    return true;
  }

  return !OffsetToken.getAsInteger(
      0,
      Offset);
}

} // namespace


InlineAsmAccess
analyzeInlineAsmMemoryAccess(CallBase &CB) {

  auto *IA =
      dyn_cast<InlineAsm>(
          CB.getCalledOperand());

  if (!IA)
    return {
        InlineAsmAccessKind::NotInlineAsm,
    };

  SmallVector<StringRef, 16> Statements;

  splitStatements(
      IA->getAsmString(),
      Statements);

  // ----------------------------------------------------------
  // Phase 1:
  // scan the whole block first.
  // ----------------------------------------------------------

  unsigned TargetCount = 0;

  for (StringRef Statement : Statements) {
    if (Statement.empty() ||
        isDirective(Statement) ||
        isLabel(Statement))
      continue;

    auto PI =
        parseInstruction(Statement);

    if (!PI)
      continue;

    if (isRVVMemoryMnemonic(
            PI->Mnemonic))
      ++TargetCount;
  }

  if (TargetCount == 0) {
    return {
        InlineAsmAccessKind::NoTarget,
    };
  }

  if (TargetCount != 1) {
    return {
        InlineAsmAccessKind::UnsupportedRelevant,
        nullptr,
        0,
        0,
        "inline asm contains multiple RVV memory instructions",
    };
  }


  // ----------------------------------------------------------
  // Build $N -> CallBase argument map.
  // ----------------------------------------------------------

  SmallVector<int, 8> OperandToArg;

  if (!buildOperandArgumentMap(
          CB,
          *IA,
          OperandToArg)) {

    return {
        InlineAsmAccessKind::UnsupportedRelevant,
        nullptr,
        0,
        0,
        "cannot map inline-asm constraints to call arguments",
    };
  }


  // ----------------------------------------------------------
  // Phase 2:
  // strict parsing of a relevant asm block.
  // ----------------------------------------------------------

  StringMap<Expr> State;

  unsigned ActualInstructionIndex = 0;

  // Do not return when the unique target is found. A relevant asm block is
  // accepted only after every later statement has passed the whitelist.
  std::optional<InlineAsmAccess> TargetAccess;

  for (StringRef Statement : Statements) {
    if (Statement.empty())
      continue;

    if (isDirective(Statement)) {
      if (!isAllowedDirective(
              Statement)) {
        return {
            InlineAsmAccessKind::UnsupportedRelevant,
            nullptr,
            0,
            ActualInstructionIndex,
            "unsupported assembler directive in relevant inline asm",
        };
      }

      continue;
    }

    if (isLabel(Statement))
      continue;

    auto PI =
        parseInstruction(Statement);

    if (!PI)
      continue;

    if (isRVVMemoryMnemonic(
            PI->Mnemonic)) {

      StringRef BaseToken;
      int64_t MemoryOffset = 0;

      if (!parseMemoryAddress(
              PI->Operands,
              BaseToken,
              MemoryOffset)) {

        return {
            InlineAsmAccessKind::UnknownAddress,
            nullptr,
            0,
            ActualInstructionIndex,
            "cannot parse RVV memory operand",
        };
      }

      Expr Base =
          resolveToken(
              BaseToken,
              OperandToArg,
              State);

      const unsigned TargetIndex =
          ActualInstructionIndex;

      if (Base.Kind ==
          ExprKind::Unknown) {

        return {
            InlineAsmAccessKind::UnknownAddress,
            nullptr,
            0,
            TargetIndex,
            "cannot resolve inline-asm memory base",
        };
      }

      Expr Address =
          addConstant(
              Base,
              MemoryOffset);

      if (Address.Kind ==
          ExprKind::Unknown) {

        return {
            InlineAsmAccessKind::UnknownAddress,
            nullptr,
            0,
            TargetIndex,
            "inline-asm address offset overflow",
        };
      }

      if (Address.Kind ==
          ExprKind::Constant) {

        TargetAccess = InlineAsmAccess{
            InlineAsmAccessKind::ProvenNonStack,
            nullptr,
            Address.Offset,
            TargetIndex,
        };
      } else if (Address.ArgIndex >=
                 CB.arg_size()) {

        return {
            InlineAsmAccessKind::UnknownAddress,
            nullptr,
            0,
            TargetIndex,
            "invalid inline-asm argument index",
        };
      } else {
        TargetAccess = InlineAsmAccess{
            InlineAsmAccessKind::ResolvedInput,
            CB.getArgOperand(
                Address.ArgIndex),
            Address.Offset,
            TargetIndex,
        };
      }

    } else if (!applyScalarInstruction(
                   *PI,
                   OperandToArg,
                   State)) {

      return {
          InlineAsmAccessKind::UnsupportedRelevant,
          nullptr,
          0,
          ActualInstructionIndex,
          "unsupported instruction in relevant inline asm: " +
              PI->Mnemonic.str(),
      };
    }

    ++ActualInstructionIndex;
  }

  if (TargetAccess)
    return *TargetAccess;

  return {
      InlineAsmAccessKind::UnknownAddress,
      nullptr,
      0,
      0,
      "RVV memory instruction disappeared during inline-asm parsing",
  };
}

} // namespace chimera
