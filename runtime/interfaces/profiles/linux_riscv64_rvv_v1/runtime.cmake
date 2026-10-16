if(NOT CHIMERA_TARGET_OS STREQUAL "linux"
   OR NOT CHIMERA_TARGET_ARCH STREQUAL "riscv64"
   OR NOT CHIMERA_TARGET_EXTENSION STREQUAL "rvv")
    message(FATAL_ERROR
        "Scene ${CHIMERA_SCENE} requires linux/riscv64/rvv, got "
        "${CHIMERA_TARGET_OS}/${CHIMERA_TARGET_ARCH}/${CHIMERA_TARGET_EXTENSION}")
endif()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The linux target requires CMAKE_SYSTEM_NAME=Linux")
endif()
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(riscv64|riscv)$")
    message(FATAL_ERROR "The riscv64 target requires a RISC-V CMake toolchain")
endif()

set(CHIMERA_SCENE_SOURCES
    artifacts/manifest/linux_riscv64_rvv_v1/reader.c
    artifacts/manifest/linux_riscv64_rvv_v1/manifest_v1.c
    artifacts/manifest/linux_riscv64_rvv_v1/capabilities.c
    artifacts/manifest/linux_riscv64_rvv_v1/capability_registry.c
    artifacts/manifest/linux_riscv64_rvv_v1/capability_loaders.c
    artifacts/manifest/linux_riscv64_rvv_v1/integrity.c
    interfaces/uapi/linux/chimera_dynamic_loader.c
    interfaces/uapi/linux/chimera_environment.c
    interfaces/uapi/linux/chimera_signal.c
    runtime/inject/inject.c
    runtime/mapping/module_registry.c
    runtime/migration/linux_riscv64_rvv_v1/route_id.c
    runtime/migration/linux_riscv64_rvv_v1/translation_control.c
    runtime/migration/linux_riscv64_rvv_v1/signal_handlers.c
    runtime/migration/linux_riscv64_rvv_v1/scene_lifecycle.c
    runtime/migration/linux_riscv64_rvv_v1/scene_marker.c
    runtime/state/linux_riscv64_rvv_v1/translator_state.c
    runtime/state/linux_riscv64_rvv_v1/vector_state.c
)
set(CHIMERA_SCENE_DEBUG_SOURCES interfaces/uapi/linux/chimera_debug.c)
set(CHIMERA_SCENE_INCLUDE_DIRECTORIES
    interfaces/abi
    interfaces/abi/linux_riscv64_rvv_v1
    interfaces/uapi/linux
    runtime/mapping
    runtime/migration/linux_riscv64_rvv_v1
    runtime/state/linux_riscv64_rvv_v1
    artifacts/manifest/linux_riscv64_rvv_v1
)
set(CHIMERA_SCENE_LINK_LIBRARIES dl)
set(CHIMERA_SCENE_COMPILE_DEFINITIONS)
