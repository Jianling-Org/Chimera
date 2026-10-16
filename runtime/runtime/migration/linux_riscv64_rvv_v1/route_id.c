/* Single definition point of the RVV route_id derivation. The manifest load
 * path (capabilities.c) and the migration decision path
 * (translation_control.c) both call chimera_rvv_route_id so the value stored
 * in a loaded variant and the value used to select it can never drift. */

#include "runtime_v1.h"

uint64_t chimera_rvv_route_id(uint64_t source_vlen_bits, uint64_t target_vlen_bits) {
    return (source_vlen_bits << 32) | target_vlen_bits;
}
