#include "PCSectionsMeta.h"

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;

namespace chimera {

namespace {

static constexpr StringLiteral DeferredPCSectionsName =
    "chimera.pcsections";


static MDNode *makeDistinctPCSections(
    LLVMContext &Ctx,
    const MDNode &MD) {

  SmallVector<Metadata *, 8> Ops;

  for (const MDOperand &Op : MD.operands())
    Ops.push_back(Op.get());

  return MDNode::getDistinct(Ctx, Ops);
}


static StringRef getBaseSectionName(
    StringRef Name) {

  size_t Pos = Name.find('!');

  if (Pos == StringRef::npos)
    return Name;

  return Name.substr(0, Pos);
}


static void checkExistingPCSections(
    const MDNode &MD,
    StringRef NewSectionName) {

  const StringRef NewBase =
      getBaseSectionName(NewSectionName);

  unsigned I = 0;

  while (I < MD.getNumOperands()) {
    auto *Section =
        dyn_cast<MDString>(
            MD.getOperand(I).get());

    if (!Section)
      report_fatal_error(
          "malformed existing PCSections metadata");

    if (getBaseSectionName(
            Section->getString()) ==
        NewBase)
      report_fatal_error(
          "duplicate Chimera PC section "
          "on one instruction");

    ++I;

    /*
     * PCSections representation:
     *
     *   !"section"
     *   !{aux...}       optional
     *   !"next section"
     *   !{aux...}
     */
    if (I < MD.getNumOperands() &&
        isa<MDNode>(
            MD.getOperand(I).get()))
      ++I;
  }
}


static MDNode *createPCSection(
    LLVMContext &Ctx,
    StringRef SectionName,
    ArrayRef<Constant *> AuxConstants) {

  MDBuilder MDB(Ctx);

  SmallVector<Constant *, 4> Aux(
      AuxConstants.begin(),
      AuxConstants.end());

  SmallVector<
      MDBuilder::PCSection,
      1> Sections;

  Sections.push_back({
      SectionName,
      std::move(Aux),
  });

  return MDB.createPCSections(
      Sections);
}


static void addOrMergePCSectionImpl(
    Instruction &I,
    unsigned MetadataKind,
    StringRef SectionName,
    ArrayRef<Constant *> AuxConstants) {

  LLVMContext &Ctx =
      I.getContext();

  MDNode *NewMD =
      createPCSection(
          Ctx,
          SectionName,
          AuxConstants);

  MDNode *OldMD =
      I.getMetadata(
          MetadataKind);

  if (!OldMD) {
    I.setMetadata(
        MetadataKind,
        makeDistinctPCSections(
            Ctx,
            *NewMD));

    return;
  }

  /*
   * Never overwrite an existing PCSections entry.
   * Merge with it instead, but reject another entry
   * using the same base section name.
   */
  checkExistingPCSections(
      *OldMD,
      SectionName);

  SmallVector<Metadata *, 8> Ops;

  for (const MDOperand &Op :
       OldMD->operands())
    Ops.push_back(Op.get());

  for (const MDOperand &Op :
       NewMD->operands())
    Ops.push_back(Op.get());

  /*
   * The top-level node must remain distinct.
   *
   * Otherwise identical PCSections metadata on different
   * instructions may be uniqued to the same MDNode*, which
   * can cause AsmPrinter to group their records.
   */
  I.setMetadata(
      MetadataKind,
      MDNode::getDistinct(
          Ctx,
          Ops));
}

} // namespace


void addOrMergePCSection(
    Instruction &I,
    StringRef SectionName,
    ArrayRef<Constant *> AuxConstants) {

  addOrMergePCSectionImpl(
      I,
      LLVMContext::MD_pcsections,
      SectionName,
      AuxConstants);
}


void addOrMergeDeferredPCSection(
    Instruction &I,
    StringRef SectionName,
    ArrayRef<Constant *> AuxConstants) {

  unsigned Kind =
      I.getContext().getMDKindID(
          DeferredPCSectionsName);

  addOrMergePCSectionImpl(
      I,
      Kind,
      SectionName,
      AuxConstants);
}


} // namespace chimera