#ifndef CHIMERA_SCENE_MANIFEST_H
#define CHIMERA_SCENE_MANIFEST_H

#include <stddef.h>
#include <stdint.h>

#define CHIMERA_MANIFEST_TEXT_SIZE 256
#define CHIMERA_SHA256_TEXT_SIZE 65

struct chimera_manifest_module {
    char module_id[CHIMERA_MANIFEST_TEXT_SIZE];
    char role[16];
    char runtime_name[CHIMERA_MANIFEST_TEXT_SIZE];
    char selected_kind[16];
    /* "package" -- the file ships inside the Workspace -- or "target", where
       the target machine resolves it from the application's installation.
       Recorded, never derived: the application is always "target". */
    char delivery[16];
    /* SHA-256 of the file every artifact here was derived from. */
    char sha256[CHIMERA_SHA256_TEXT_SIZE];
};

struct chimera_manifest_variant {
    char variant_id[CHIMERA_MANIFEST_TEXT_SIZE];
    char module_id[CHIMERA_MANIFEST_TEXT_SIZE];
};

struct chimera_manifest_variant_property {
    char variant_id[CHIMERA_MANIFEST_TEXT_SIZE];
    char side[16];
    char name[CHIMERA_MANIFEST_TEXT_SIZE];
    char value_kind[16];
    char value[CHIMERA_MANIFEST_TEXT_SIZE];
};

struct chimera_manifest_artifact {
    char artifact_id[CHIMERA_MANIFEST_TEXT_SIZE];
    char owner_kind[16];
    char owner_id[CHIMERA_MANIFEST_TEXT_SIZE];
    char capability[CHIMERA_MANIFEST_TEXT_SIZE];
    char representation[32];
    uint64_t abi;
    char required_by[CHIMERA_MANIFEST_TEXT_SIZE];
    char path[CHIMERA_MANIFEST_TEXT_SIZE];
    char sha256[CHIMERA_SHA256_TEXT_SIZE];
};

struct chimera_manifest {
    uint64_t runtime_abi;
    char target_os[32];
    char target_arch[32];
    char target_arch_extension[32];
    char runtime_scene[CHIMERA_MANIFEST_TEXT_SIZE];
    struct chimera_manifest_module *modules;
    size_t module_count;
    struct chimera_manifest_variant *variants;
    size_t variant_count;
    struct chimera_manifest_variant_property *variant_properties;
    size_t variant_property_count;
    struct chimera_manifest_artifact *artifacts;
    size_t artifact_count;
};

#endif
