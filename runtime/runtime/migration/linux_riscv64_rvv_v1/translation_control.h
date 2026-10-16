#ifndef CHIMERA_TRANSLATION_CONTROL_V1_H
#define CHIMERA_TRANSLATION_CONTROL_V1_H

#include <stdint.h>

#include "chimera_runtime.h"
#include "runtime_v1.h"

struct chimera_migration_decision {
    enum chimera_direction direction;
    chimera_code_body target_type;
    uint64_t route_id;
};

int chimera_decide_migration(
    const struct chimera_registry *registry,
    uint64_t original_pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out);
uint64_t query_original_translated_map(int target_type, uint64_t addr_in);

#endif
