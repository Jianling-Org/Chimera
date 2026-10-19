//===----------------------------------------------------------------------===//
// global_read_tracker.h — Track reads of a named global variable
//===----------------------------------------------------------------------===//

#ifndef RVI_RVV_GLOBAL_READ_TRACKER_H
#define RVI_RVV_GLOBAL_READ_TRACKER_H

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
class GlobalVariable;
} // namespace llvm

namespace rvirvv {

/// FlowEvent: one consumption of a value read from the tracked global.
struct FlowEvent {
    std::string kind;     // CMP_BRANCH | CALL | CALL_EXTERNAL | RETURNED | STORE
    std::string detail;   // e.g. "icmp sgt 0", callee name, "GLOBAL::g", "STACK::fn::x"
    std::string function; // function containing the event instruction
    std::string file;
    unsigned line = 0;
};

/// GlobalRead: one detected read of the tracked global (or a field of it).
struct GlobalRead {
    std::string function;
    std::string file;
    unsigned line = 0;
    unsigned column = 0;
    int64_t field_offset = 0;  // byte offset into the object; -1 = non-constant
    std::string confidence;    // exact | may
    std::vector<FlowEvent> flows; // forward dataflow consumption of the value
};

/// GlobalFieldStat: per-field read counts (constant offsets only).
struct GlobalFieldStat {
    int64_t offset = 0;
    unsigned reads = 0;
};

/// GlobalReadTrackResult: whole analysis result plus statistics.
struct GlobalReadTrackResult {
    std::string module;
    std::string requested;                  // the -track-global argument
    std::vector<std::string> matched_globals; // actually matched global names
    std::vector<GlobalFieldStat> fields;
    std::vector<GlobalRead> reads;
    unsigned flow_count = 0;
    bool truncated_depth = false;
    long unresolved_indirect_calls = 0;
};

/// GlobalReadTracker: finds every read of a named global variable (loads and
/// memcpy/memmove sources whose Andersen pts intersects the target object
/// set) and forward-tracks each read value's use chain with a small fixpoint
/// dataflow analysis (rules documented in the .cpp).
class GlobalReadTracker {
public:
    GlobalReadTracker(SVF::SVFIR *pag, SVF::Andersen *ander);

    void setMaxDepth(unsigned d) { max_depth_ = d; }

    GlobalReadTrackResult analyze(const std::string &targetName);

private:
    SVF::SVFIR *pag_;
    SVF::Andersen *ander_;
    unsigned max_depth_ = 30;
};

} // namespace rvirvv

#endif // RVI_RVV_GLOBAL_READ_TRACKER_H
