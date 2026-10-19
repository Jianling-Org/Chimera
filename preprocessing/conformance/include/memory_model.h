//===----------------------------------------------------------------------===//
// memory_model.h — Abstract memory object types for RVI/RVV comparison
//===----------------------------------------------------------------------===//

#ifndef RVI_RVV_MEMORY_MODEL_H
#define RVI_RVV_MEMORY_MODEL_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>

namespace rvirvv {

/// ObjectKind: classification of an abstract memory object
enum class ObjectKind : uint8_t {
    ARG,            // function argument (pointer parameter)
    GLOBAL,         // global variable / TLS
    STACK,          // stack allocated (alloca)
    HEAP,           // heap allocated (malloc/calloc/realloc)
    CSR,            // RISC-V control/status register pseudo-object
    UNKNOWN,        // external / unresolvable memory
};

/// EscapeKind: how an object may escape its allocation scope
enum class EscapeKind : uint8_t {
    NONE,           // does not escape
    RETURN,         // returned to caller
    ARG_STORE,      // stored into argument-reachable memory
    GLOBAL_STORE,   // stored into global/TLS
    UNKNOWN_CALL,   // passed to unknown external function
    ALIAS,          // stored into another escaping object
};

/// FieldPath: decomposed struct field access path
struct FieldPath {
    int64_t base_offset;          // byte offset from object base
    std::vector<int> field_indices; // struct field indices (empty = whole object)
    std::string field_name;       // optional DWARF-derived field name

    std::string toString() const;
    bool isWholeObject() const { return field_indices.empty() && base_offset == 0; }
};

/// AbstractObject: represents a memory allocation or object in the analysis
struct AbstractObject {
    uint64_t id;                  // unique identifier
    ObjectKind kind;
    std::string origin;           // source location or allocation site label
    std::string logical_type;     // optional DWARF type name
    EscapeKind escape;            // escape classification
    uint64_t size;                // known size (0 = unknown)

    // Points-to set size within this object
    uint32_t pts_count;

    // For field-sensitive: list of accessed sub-fields
    std::vector<FieldPath> accessed_fields;

    std::string kindName() const;
    std::string escapeName() const;
    std::string toString() const;
};

/// AbstractObjectSet: collection of abstract objects from an analysis
struct AbstractObjectSet {
    std::string entry_function;
    std::vector<AbstractObject> objects;

    // Count by kind
    std::map<ObjectKind, size_t> countByKind() const;

    // Compare with another set, returning objects only in this set
    std::vector<AbstractObject> diffObjects(const AbstractObjectSet &other) const;

    // Find objects by kind
    std::vector<const AbstractObject*> findByKind(ObjectKind kind) const;
};

} // namespace rvirvv

#endif // RVI_RVV_MEMORY_MODEL_H
