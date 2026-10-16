#ifndef CHIMERA_LINUX_RISCV64_RVV_V1_SCENE_LIFECYCLE_H
#define CHIMERA_LINUX_RISCV64_RVV_V1_SCENE_LIFECYCLE_H

/* Internal composition point.  It is deliberately absent from the public
 * Runtime ABI headers: the constructor only knows this scene lifecycle
 * contract, while the scene owns platform preparation and signal policy. */
int chimera_scene_initialize_runtime(const char *workspace);

#endif
