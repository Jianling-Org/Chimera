#include "StackAddress.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/Support/MathExtras.h"

using namespace llvm;

namespace chimera {
namespace {

enum class LocationKind {
  LocalAlloca,
  ProvenNonLocal,
  Unknown,
};

struct Location {
  LocationKind Kind;
  Value *Base;
  AllocaInst *Alloca;
  int64_t Offset;
};

struct LocationSet {
  bool Multiple = false;
  SmallVector<Location, 2> Locations;
};

static bool isOrdinaryPointerArgument(const Argument &A) {
  return A.getType()->isPointerTy() &&
         !A.hasByValAttr() &&
         !A.hasByRefAttr() &&
         !A.hasInAllocaAttr() &&
         !A.hasPreallocatedAttr() &&
         !A.hasStructRetAttr();
}

static bool sameLocation(
    const Location &A,
    const Location &B) {
  return A.Kind == B.Kind &&
         A.Base == B.Base &&
         A.Alloca == B.Alloca &&
         A.Offset == B.Offset;
}

static void addLocation(
    LocationSet &Set,
    const Location &Loc) {
  if (Set.Multiple)
    return;

  for (const Location &Existing : Set.Locations) {
    if (sameLocation(Existing, Loc))
      return;
  }

  Set.Locations.push_back(Loc);

  // 我们实际上只关心 0 / 1 / >1。
  if (Set.Locations.size() > 1) {
    Set.Multiple = true;
    Set.Locations.clear();
  }
}

static void mergeLocations(
    LocationSet &Dst,
    const LocationSet &Src) {
  if (Dst.Multiple)
    return;

  if (Src.Multiple) {
    Dst.Multiple = true;
    Dst.Locations.clear();
    return;
  }

  for (const Location &Loc : Src.Locations)
    addLocation(Dst, Loc);
}

static bool addOffset(
    Location &Loc,
    int64_t Delta) {
  int64_t NewOffset = 0;

  if (AddOverflow(Loc.Offset, Delta, NewOffset))
    return false;

  Loc.Offset = NewOffset;
  return true;
}

static LocationSet unknownLocation(Value *V) {
  LocationSet Result;

  addLocation(
      Result,
      {
          LocationKind::Unknown,
          V,
          nullptr,
          0,
      });

  return Result;
}

static LocationSet resolvePossibleLocations(
    Value *Ptr,
    const DataLayout &DL,
    Function &F,
    SmallPtrSetImpl<Value *> &Active,
    unsigned Depth) {

  constexpr unsigned MaxDepth = 32;

  if (!Ptr || Depth >= MaxDepth)
    return unknownLocation(Ptr);

  /*
   * First peel pointer casts and constant address adjustments.
   *
   * LLVM 21's GetPointerBaseWithConstantOffset() uses
   * stripAndAccumulateConstantOffsets(), so expressions such as
   *
   *   gep %buf, 32
   *
   * become:
   *
   *   Base   = %buf
   *   Offset = 32
   */
  int64_t ConstantOffset = 0;
  Value *Base =
      GetPointerBaseWithConstantOffset(
          Ptr,
          ConstantOffset,
          DL);

  if (Base != Ptr || ConstantOffset != 0) {
    LocationSet Result =
        resolvePossibleLocations(
            Base,
            DL,
            F,
            Active,
            Depth + 1);

    if (Result.Multiple)
      return Result;

    for (Location &Loc : Result.Locations) {
      if (!addOffset(Loc, ConstantOffset))
        return unknownLocation(Ptr);
    }

    return Result;
  }

  // Current invocation's local stack object.
  if (auto *AI = dyn_cast<AllocaInst>(Ptr)) {
    if (AI->getFunction() != &F)
      return unknownLocation(Ptr);

    LocationSet Result;
    addLocation(
        Result,
        {
            LocationKind::LocalAlloca,
            AI,
            AI,
            0,
        });
    return Result;
  }

  // Global object can never be an alloca belonging to this invocation.
  if (isa<GlobalValue>(Ptr)) {
    LocationSet Result;
    addLocation(
        Result,
        {
            LocationKind::ProvenNonLocal,
            Ptr,
            nullptr,
            0,
        });
    return Result;
  }

  if (auto *A = dyn_cast<Argument>(Ptr)) {
    LocationSet Result;

    if (A->getParent() == &F &&
        isOrdinaryPointerArgument(*A)) {
      addLocation(
          Result,
          {
              LocationKind::ProvenNonLocal,
              A,
              nullptr,
              0,
          });
    } else {
      addLocation(
          Result,
          {
              LocationKind::Unknown,
              A,
              nullptr,
              0,
          });
    }

    return Result;
  }

  /*
   * If a GEP survived GetPointerBaseWithConstantOffset(), it has an address
   * component that we cannot reduce to one compile-time constant offset.
   *
   * Example:
   *
   *   gep %buf, %idx
   *
   * This may address multiple positions, so ignore the access later.
   */
  if (isa<GEPOperator>(Ptr)) {
    LocationSet Result;
    Result.Multiple = true;
    return Result;
  }

  /*
   * PHI/select explicitly represent alternative pointer values.
   *
   * Resolve every alternative and form their union. Equal abstract
   * locations collapse to one; once two distinct locations appear, we
   * already know this access is MultipleLocations.
   */
  if (auto *PN = dyn_cast<PHINode>(Ptr)) {
    if (!Active.insert(Ptr).second)
      return unknownLocation(Ptr);

    LocationSet Result;

    for (Value *Incoming : PN->incoming_values()) {
      // Common loop PHI self-reference adds no new location.
      if (Incoming == PN)
        continue;

      LocationSet IncomingSet =
          resolvePossibleLocations(
              Incoming,
              DL,
              F,
              Active,
              Depth + 1);

      mergeLocations(Result, IncomingSet);

      if (Result.Multiple)
        break;
    }

    Active.erase(Ptr);

    if (!Result.Multiple &&
        Result.Locations.empty())
      return unknownLocation(Ptr);

    return Result;
  }

  if (auto *SI = dyn_cast<SelectInst>(Ptr)) {
    if (!Active.insert(Ptr).second)
      return unknownLocation(Ptr);

    LocationSet Result;

    mergeLocations(
        Result,
        resolvePossibleLocations(
            SI->getTrueValue(),
            DL,
            F,
            Active,
            Depth + 1));

    if (!Result.Multiple) {
      mergeLocations(
          Result,
          resolvePossibleLocations(
              SI->getFalseValue(),
              DL,
              F,
              Active,
              Depth + 1));
    }

    Active.erase(Ptr);
    return Result;
  }

  /*
   * load/call/inttoptr/etc.:
   *
   * We have not established multiple alternatives, but neither can we prove
   * whether this pointer belongs to the current function's stack.
   */
  return unknownLocation(Ptr);
}

} // namespace

StackAddr classifyStackAddress(
    Value *Ptr,
    int64_t ExtraOffset,
    const DataLayout &DL,
    Function &F) {

  SmallPtrSet<Value *, 16> Active;

  LocationSet Locations =
      resolvePossibleLocations(
          Ptr,
          DL,
          F,
          Active,
          0);

  if (Locations.Multiple)
    return {StackAddrKind::MultipleLocations};

  if (Locations.Locations.size() != 1)
    return {StackAddrKind::UnknownProvenance};

  Location Loc = Locations.Locations.front();

  if (!addOffset(Loc, ExtraOffset))
    return {StackAddrKind::UnknownProvenance};

  switch (Loc.Kind) {
  case LocationKind::LocalAlloca:
    return {
        StackAddrKind::ExactStack,
        Loc.Alloca,
        Loc.Offset,
    };

  case LocationKind::ProvenNonLocal:
    return {
        StackAddrKind::ProvenNotCurrentLocalAlloca,
    };

  case LocationKind::Unknown:
    return {
        StackAddrKind::UnknownProvenance,
    };
  }

  llvm_unreachable("unknown Chimera location kind");
}

} // namespace chimera