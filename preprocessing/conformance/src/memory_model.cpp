//===----------------------------------------------------------------------===//
// memory_model.cpp — Implementation of abstract memory object types
//===----------------------------------------------------------------------===//

#include "memory_model.h"
#include <sstream>
#include <algorithm>

namespace rvirvv {

std::string FieldPath::toString() const {
    std::ostringstream oss;
    oss << "offset=" << base_offset;
    if (!field_indices.empty()) {
        oss << " fields=[";
        for (size_t i = 0; i < field_indices.size(); ++i) {
            if (i > 0) oss << ".";
            oss << field_indices[i];
        }
        oss << "]";
    }
    if (!field_name.empty())
        oss << " (" << field_name << ")";
    return oss.str();
}

std::string AbstractObject::kindName() const {
    switch (kind) {
        case ObjectKind::ARG:     return "ARG";
        case ObjectKind::GLOBAL:  return "GLOBAL";
        case ObjectKind::STACK:   return "STACK";
        case ObjectKind::HEAP:    return "HEAP";
        case ObjectKind::CSR:     return "CSR";
        case ObjectKind::UNKNOWN: return "UNKNOWN";
    }
    return "?";
}

std::string AbstractObject::escapeName() const {
    switch (escape) {
        case EscapeKind::NONE:         return "NONE";
        case EscapeKind::RETURN:       return "RETURN";
        case EscapeKind::ARG_STORE:    return "ARG_STORE";
        case EscapeKind::GLOBAL_STORE: return "GLOBAL_STORE";
        case EscapeKind::UNKNOWN_CALL: return "UNKNOWN_CALL";
        case EscapeKind::ALIAS:        return "ALIAS";
    }
    return "?";
}

std::string AbstractObject::toString() const {
    std::ostringstream oss;
    oss << kindName() << "::" << origin;
    if (!logical_type.empty())
        oss << " [" << logical_type << "]";
    oss << " size=" << size << " pts=" << pts_count
        << " escape=" << escapeName();
    if (!accessed_fields.empty())
        oss << " fields=" << accessed_fields.size();
    return oss.str();
}

std::map<ObjectKind, size_t> AbstractObjectSet::countByKind() const {
    std::map<ObjectKind, size_t> counts;
    for (auto &obj : objects)
        counts[obj.kind]++;
    return counts;
}

std::vector<AbstractObject> AbstractObjectSet::diffObjects(
    const AbstractObjectSet &other) const
{
    std::vector<AbstractObject> result;
    for (auto &obj : objects) {
        bool found = false;
        for (auto &o : other.objects) {
            if (o.origin == obj.origin && o.kind == obj.kind) {
                found = true;
                break;
            }
        }
        if (!found)
            result.push_back(obj);
    }
    return result;
}

std::vector<const AbstractObject*> AbstractObjectSet::findByKind(
    ObjectKind kind) const
{
    std::vector<const AbstractObject*> result;
    for (auto &obj : objects) {
        if (obj.kind == kind)
            result.push_back(&obj);
    }
    return result;
}

} // namespace rvirvv
