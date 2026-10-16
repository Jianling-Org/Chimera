#ifndef CHIMERA_UPROBE_UAPI_H
#define CHIMERA_UPROBE_UAPI_H

#include <stdint.h>

#define CHIMERA_UPROBE_MAX_OFFSETS 20

struct chimera_uprobe_info {
    uint64_t inode;
    uint64_t offsets[CHIMERA_UPROBE_MAX_OFFSETS];
    int32_t offset_count;
    uint8_t is_attached;
    uint8_t reserved[3];
};

_Static_assert(sizeof(struct chimera_uprobe_info) == 176,
               "chimera_uprobe_info ABI must be 176 bytes");
_Static_assert(sizeof(((struct chimera_uprobe_info *)0)->offsets) == 160,
               "chimera_uprobe_info must contain twenty 64-bit offsets");

#endif
