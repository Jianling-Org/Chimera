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

enum chimera_migration_decision_status {
    CHIMERA_MIGRATION_READY = 0,
    CHIMERA_MIGRATION_TRANSLATED,
    CHIMERA_MIGRATION_MISSING_ROUTE,
    CHIMERA_MIGRATION_NOT_MIGRATABLE,
    CHIMERA_MIGRATION_PREPARE_FAILED,
};

enum chimera_migration_decision_status chimera_decide_migration_status(
    const struct chimera_registry *registry,
    uint64_t current_pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out);

int chimera_decide_migration(
    const struct chimera_registry *registry,
    uint64_t original_pc,
    uint64_t source_vlen_bits,
    struct chimera_migration_decision *out);
uint64_t query_original_translated_map(int target_type, uint64_t addr_in);

#endif
