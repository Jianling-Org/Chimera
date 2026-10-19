//===----------------------------------------------------------------------===//
// vlen_escape.h — vlen (vsetvl/vlenb) escape analysis for svf-vlenesc
//===----------------------------------------------------------------------===//

#ifndef RVI_RVV_VLEN_ESCAPE_H
#define RVI_RVV_VLEN_ESCAPE_H

#include "Graphs/CallGraph.h"
#include "SVFIR/SVFIR.h"
#include "WPA/Andersen.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace llvm {
class Value;
class Function;
class CallBase;
class StoreInst;
} // namespace llvm

namespace rvirvv {

/// EscapeKind categories for a tainted vlen value.
enum class VlenEscapeKind : uint8_t {
    RETURN,        // returned by the root function
    PARAM,         // stored into argument-reachable memory
    GLOBAL,        // stored into a global/static object
    HEAP,          // stored into a heap object
    UNKNOWN_CALL,  // passed to an unknown external / unresolved indirect call
    UNKNOWN,       // store target unclassifiable
};

/// VlenEscape: one escape event of a tainted vlen value.
struct VlenEscape {
    std::string kind;        // RETURN|PARAM|GLOBAL|HEAP|UNKNOWN_CALL|UNKNOWN
    std::string function;    // function containing the escape instruction
    std::string file;
    unsigned line = 0;
    unsigned column = 0;
    std::string target;      // GLOBAL::g | ARG::out | HEAP::<site> | UNKNOWN::obj@id | <ret> | CALL::<callee>
    bool derived = false;    // value passed through a computing op (binop/cast/gep/...)
    std::string confidence;  // exact | may | unknown
};

/// VlenRead: one vsetvl/vlenb call site inside a root function.
struct VlenRead {
    std::string callee;
    unsigned line = 0;
    unsigned column = 0;
    std::string note;    // optional, e.g. untrackable inline asm (omitted when empty)
};

/// VlenRootResult: analysis result for one vlen-reading root function.
struct VlenRootResult {
    std::string name;
    std::string file;
    unsigned line = 0;
    std::vector<VlenRead> vlen_reads;
    std::vector<VlenEscape> escapes;
    std::string verdict;     // ESCAPES | LOCAL_ONLY
    bool uncertain = false;  // any UNKNOWN kind or UNKNOWN_CALL escape
};

/// VlenEscapeResult: whole-module result plus statistics.
struct VlenEscapeResult {
    std::string module;
    std::vector<VlenRootResult> functions;
    unsigned function_count = 0;
    bool truncated_depth = false;
    long unresolved_indirect_calls = 0;
};

/// VlenEscapeAnalyzer: module-level scan for vlen readers plus a small
/// Andersen-assisted taint analysis per reader (rules documented in the .cpp).
class VlenEscapeAnalyzer {
public:
    VlenEscapeAnalyzer(SVF::SVFIR *pag, SVF::Andersen *ander);

    void setMaxDepth(unsigned d) { max_depth_ = d; }

    VlenEscapeResult analyze(const std::string &moduleName);

private:
    SVF::SVFIR *pag_;
    SVF::Andersen *ander_;
    unsigned max_depth_ = 30;

    bool isVlenSourceName(const std::string &name) const;

    /// Read-point classification of one call site.
    enum class VlenSrcKind {
        None,           // not a vlen read point
        VsetvlLike,     // direct callee name contains vsetvl/vlenb
        ReadRegister,   // llvm.read_register.* with a "vlen*" register metadata
        AsmVlenb,       // inline asm containing vlenb with an integer result
        AsmUntrackable, // inline asm with vsetvl/vlenb but no SSA-visible value
    };
    struct VlenCallInfo {
        VlenSrcKind kind = VlenSrcKind::None;
        std::string display; // callee label for vlen_reads
    };
    VlenCallInfo classifyVlenCall(const llvm::CallBase *cb) const;
    void analyzeRoot(const llvm::Function *root, VlenRootResult &out,
                     bool &truncatedOut);
    long countModuleUnresolvedIndirect();
};

} // namespace rvirvv

#endif // RVI_RVV_VLEN_ESCAPE_H
