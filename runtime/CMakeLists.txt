cmake_minimum_required(VERSION 3.20)

project(chimera_runtime LANGUAGES NONE)

option(CHIMERA_BUILD_RUNTIME "Build the selected runtime DSO" OFF)
option(CHIMERA_INSTALL_RUNTIME_SOURCE "Install runtime sources for offline builds" OFF)
option(CHIMERA_INSTALL_TOOLCHAIN_SOURCE "Install LLVM patch/plugin sources for developer toolchain builds" OFF)
option(CHIMERA_INSTALL_THIRD_PARTY "Install third_party sources (llvm/SVF; very large, opt-in)" OFF)
option(CHIMERA_INSTALL_EXAMPLES "Install bundled example scripts and profiles" OFF)
set(CHIMERA_RELEASE_ARTIFACT_ROOT "" CACHE PATH "Validated release artifacts to embed in the wheel")
option(CHIMERA_BUILD_TESTS "Build portable C contract tests" OFF)
option(CHIMERA_DEBUG "Compile Runtime debug diagnostics" OFF)
set(CHIMERA_TARGET_OS "" CACHE STRING "Runtime target operating system")
set(CHIMERA_TARGET_ARCH "" CACHE STRING "Runtime target architecture")
set(CHIMERA_TARGET_EXTENSION "" CACHE STRING "Runtime target extension")
set(CHIMERA_SCENE "" CACHE STRING "Runtime implementation scene")

if(CHIMERA_BUILD_RUNTIME OR CHIMERA_BUILD_TESTS)
    enable_language(C)
endif()

if(CHIMERA_BUILD_RUNTIME)
    foreach(variable IN ITEMS
            CHIMERA_SCENE CHIMERA_TARGET_OS CHIMERA_TARGET_ARCH CHIMERA_TARGET_EXTENSION)
        if("${${variable}}" STREQUAL "")
            message(FATAL_ERROR "${variable} is required when CHIMERA_BUILD_RUNTIME=ON")
        endif()
    endforeach()

    if(NOT CHIMERA_SCENE MATCHES "^[A-Za-z_][A-Za-z0-9_.-]*$")
        message(FATAL_ERROR "Invalid CHIMERA_SCENE identifier: ${CHIMERA_SCENE}")
    endif()
    set(CHIMERA_SCENE_FRAGMENT
        "${CMAKE_CURRENT_SOURCE_DIR}/interfaces/profiles/${CHIMERA_SCENE}/runtime.cmake")
    if(NOT EXISTS "${CHIMERA_SCENE_FRAGMENT}")
        message(FATAL_ERROR "Unsupported Chimera runtime scene: ${CHIMERA_SCENE}")
    endif()
    include("${CHIMERA_SCENE_FRAGMENT}")

    add_library(chimera_inject SHARED ${CHIMERA_SCENE_SOURCES})
    target_compile_features(chimera_inject PRIVATE c_std_11)
    if(CHIMERA_DEBUG)
        target_sources(chimera_inject PRIVATE ${CHIMERA_SCENE_DEBUG_SOURCES})
        target_compile_definitions(chimera_inject PRIVATE CHIMERA_DEBUG=1)
    endif()
    target_compile_options(chimera_inject PRIVATE
        -Wall -Wextra -Werror -fvisibility=hidden)
    target_include_directories(chimera_inject PRIVATE
        ${CHIMERA_SCENE_INCLUDE_DIRECTORIES})
    target_link_libraries(chimera_inject PRIVATE ${CHIMERA_SCENE_LINK_LIBRARIES})
    target_compile_definitions(chimera_inject PRIVATE
        ${CHIMERA_SCENE_COMPILE_DEFINITIONS})
    set_target_properties(chimera_inject PROPERTIES OUTPUT_NAME "chimera_inject")
    install(TARGETS chimera_inject LIBRARY DESTINATION "artifacts/runtime")
endif()

if(CHIMERA_INSTALL_RUNTIME_SOURCE)
    install(FILES CMakeLists.txt DESTINATION "chimera/runtime_source")
    install(DIRECTORY runtime interfaces
        DESTINATION "chimera/runtime_source"
        FILES_MATCHING PATTERN "*.c" PATTERN "*.h")
    install(DIRECTORY interfaces/profiles
        DESTINATION "chimera/runtime_source/interfaces"
        FILES_MATCHING PATTERN "*.cmake")
    install(DIRECTORY artifacts/manifest
        DESTINATION "chimera/runtime_source/artifacts"
        FILES_MATCHING PATTERN "*.c" PATTERN "*.h")
endif()

# Developer toolchain builds need the LLVM patch/plugin tree even when installed as a
# wheel. The source lives outside this CMake project (repo root), so only
# bundle it when the checkout is present (sdist builds lack it by design).
set(CHIMERA_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")
if(CHIMERA_INSTALL_TOOLCHAIN_SOURCE)
    set(_CHIMERA_TOOLCHAIN_SOURCE
        "${CHIMERA_REPO_ROOT}/preprocessing/offline/toolchain/llvm-21.1.0")
    if(EXISTS "${_CHIMERA_TOOLCHAIN_SOURCE}/plugins/CMakeLists.txt")
        install(DIRECTORY "${_CHIMERA_TOOLCHAIN_SOURCE}/patches/"
            DESTINATION "chimera/toolchain_source/patches")
        install(DIRECTORY "${_CHIMERA_TOOLCHAIN_SOURCE}/svf-patches/"
            DESTINATION "chimera/toolchain_source/svf-patches")
        install(DIRECTORY "${_CHIMERA_TOOLCHAIN_SOURCE}/plugins/"
            DESTINATION "chimera/toolchain_source/plugins")
    else()
        message(WARNING "toolchain source not present in this build context; "
            "skipping CHIMERA_INSTALL_TOOLCHAIN_SOURCE bundle")
    endif()
endif()

if(CHIMERA_INSTALL_THIRD_PARTY)
    if(EXISTS "${CHIMERA_REPO_ROOT}/third_party/llvm")
        install(DIRECTORY "${CHIMERA_REPO_ROOT}/third_party"
            DESTINATION "chimera/third_party"
            PATTERN ".git" EXCLUDE)
    else()
        message(WARNING "third_party not present in this build context; "
            "skipping CHIMERA_INSTALL_THIRD_PARTY bundle")
    endif()
endif()

# Example dispatch is shipped as package data so a wheel can run its bundled
# scripts without a Chimera source checkout.  Large third-party checkouts are
# intentionally excluded; release binaries are installed separately below.
if(CHIMERA_INSTALL_EXAMPLES)
    if(EXISTS "${CHIMERA_REPO_ROOT}/examples")
        install(DIRECTORY "${CHIMERA_REPO_ROOT}/examples/"
            DESTINATION "chimera/examples"
            USE_SOURCE_PERMISSIONS
            PATTERN ".git" EXCLUDE
            PATTERN "llama.cpp" EXCLUDE
            PATTERN "model" EXCLUDE
            PATTERN "*.gguf" EXCLUDE
            PATTERN "build-*" EXCLUDE)
    endif()
endif()

if(NOT "${CHIMERA_RELEASE_ARTIFACT_ROOT}" STREQUAL "")
    install(DIRECTORY "${CHIMERA_RELEASE_ARTIFACT_ROOT}/"
        DESTINATION "chimera/release"
        USE_SOURCE_PERMISSIONS
        PATTERN "manifest.json" EXCLUDE
        PATTERN "*.tmp" EXCLUDE)
endif()

if(CHIMERA_BUILD_TESTS)
    enable_testing()
    find_package(Threads REQUIRED)
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/build/tests")

    add_executable(test_uprobe_layout tests/runtime/test_uprobe_layout.c)
    target_include_directories(test_uprobe_layout PRIVATE interfaces/uapi)

    add_executable(test_module_registry
        tests/runtime/test_module_registry.c
        runtime/mapping/module_registry.c
        runtime/migration/linux_riscv64_rvv_v1/route_id.c
        artifacts/manifest/linux_riscv64_rvv_v1/manifest_v1.c
        artifacts/manifest/linux_riscv64_rvv_v1/capabilities.c
        artifacts/manifest/linux_riscv64_rvv_v1/capability_registry.c
        artifacts/manifest/linux_riscv64_rvv_v1/capability_loaders.c)
    target_include_directories(test_module_registry PRIVATE
        interfaces/abi interfaces/abi/linux_riscv64_rvv_v1
        interfaces/uapi/linux runtime/mapping
        runtime/migration/linux_riscv64_rvv_v1
        artifacts/manifest/linux_riscv64_rvv_v1)

    add_executable(test_translation_control
        tests/runtime/test_translation_control.c
        runtime/mapping/module_registry.c
        runtime/migration/linux_riscv64_rvv_v1/route_id.c
        runtime/migration/linux_riscv64_rvv_v1/translation_control.c)
    target_include_directories(test_translation_control PRIVATE
        interfaces/abi
        interfaces/abi/linux_riscv64_rvv_v1
        runtime/mapping
        runtime/migration/linux_riscv64_rvv_v1)

    add_executable(test_module_manifest_v1
        tests/runtime/test_module_manifest_v1.c
        artifacts/manifest/linux_riscv64_rvv_v1/manifest_v1.c
        artifacts/manifest/linux_riscv64_rvv_v1/integrity.c)
    target_include_directories(test_module_manifest_v1 PRIVATE
        interfaces/abi artifacts/manifest/linux_riscv64_rvv_v1)

    add_executable(test_translator_state
        tests/runtime/test_translator_state.c
        runtime/state/linux_riscv64_rvv_v1/translator_state.c
        runtime/state/linux_riscv64_rvv_v1/vector_state.c)
    target_include_directories(test_translator_state PRIVATE
        interfaces/abi
        interfaces/abi/linux_riscv64_rvv_v1
        interfaces/uapi/linux
        runtime/state/linux_riscv64_rvv_v1)
    target_compile_definitions(test_translator_state PRIVATE
        CHIMERA_PORTABLE_TEST_CONTEXT=1)
    target_link_libraries(test_translator_state PRIVATE Threads::Threads)

    add_executable(test_chimera_signal
        tests/runtime/test_chimera_signal.c
        interfaces/uapi/linux/chimera_signal.c
        runtime/migration/linux_riscv64_rvv_v1/signal_handlers.c)
    target_include_directories(test_chimera_signal PRIVATE
        interfaces/abi
        interfaces/abi/linux_riscv64_rvv_v1
        interfaces/uapi/linux
        runtime/mapping
        runtime/migration/linux_riscv64_rvv_v1
        runtime/state/linux_riscv64_rvv_v1)
    target_compile_definitions(test_chimera_signal PRIVATE
        CHIMERA_PORTABLE_SIGNAL_TEST=1)
    add_test(NAME test_chimera_signal_unmapped_exit
        COMMAND test_chimera_signal --unmapped-exit)
    set_tests_properties(test_chimera_signal_unmapped_exit PROPERTIES WILL_FAIL TRUE)

    add_executable(test_scene_lifecycle
        tests/runtime/test_scene_lifecycle.c
        runtime/migration/linux_riscv64_rvv_v1/scene_lifecycle.c)
    target_include_directories(test_scene_lifecycle PRIVATE
        interfaces/abi
        interfaces/abi/linux_riscv64_rvv_v1
        interfaces/uapi/linux
        runtime/migration/linux_riscv64_rvv_v1)
    target_compile_definitions(test_scene_lifecycle PRIVATE
        CHIMERA_PORTABLE_SIGNAL_TEST=1)

    add_executable(test_capability_registry
        tests/runtime/test_capability_registry.c
        artifacts/manifest/linux_riscv64_rvv_v1/capability_registry.c)
    target_include_directories(test_capability_registry PRIVATE
        interfaces/abi artifacts/manifest/linux_riscv64_rvv_v1)

    foreach(target IN ITEMS test_uprobe_layout test_module_registry test_translation_control
            test_module_manifest_v1 test_translator_state test_chimera_signal
            test_scene_lifecycle test_capability_registry)
        target_compile_features(${target} PRIVATE c_std_11)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
        endif()
        add_test(NAME ${target} COMMAND ${target})
    endforeach()

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(test_debug_log
            tests/runtime/test_debug_log.c
            interfaces/uapi/linux/chimera_debug.c)
        target_compile_features(test_debug_log PRIVATE c_std_11)
        target_compile_definitions(test_debug_log PRIVATE CHIMERA_DEBUG=1)
        target_compile_options(test_debug_log PRIVATE -Wall -Wextra -Werror)
        target_include_directories(test_debug_log PRIVATE interfaces/uapi/linux)
        add_test(NAME test_debug_log COMMAND test_debug_log)
    endif()

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux"
       AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(riscv64|riscv)$")
        enable_language(ASM)
        # CMake's ASM language does not supply a MODULE rule on every target.
        # These fixtures use the same compiler driver/linker as C DSOs.
        if(NOT CMAKE_ASM_CREATE_SHARED_MODULE)
            set(CMAKE_ASM_CREATE_SHARED_MODULE "${CMAKE_C_CREATE_SHARED_MODULE}")
        endif()
        add_executable(test_signal_vector_layout
            tests/runtime/test_signal_vector_layout.c
            tests/runtime/fixtures/signal_vector_layout.S
            runtime/state/linux_riscv64_rvv_v1/translator_state.c
            runtime/state/linux_riscv64_rvv_v1/vector_state.c)
        target_compile_features(test_signal_vector_layout PRIVATE c_std_11)
        target_compile_options(test_signal_vector_layout PRIVATE
            -Wall -Wextra -Werror -fno-tree-vectorize -fno-tree-slp-vectorize)
        target_include_directories(test_signal_vector_layout PRIVATE
            interfaces/abi interfaces/abi/linux_riscv64_rvv_v1
            interfaces/uapi/linux runtime/state/linux_riscv64_rvv_v1)
        add_test(NAME test_signal_vector_layout COMMAND test_signal_vector_layout)
    endif()

    if(CHIMERA_BUILD_RUNTIME
       AND CMAKE_SYSTEM_NAME STREQUAL "Linux"
       AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(riscv64|riscv)$")
        enable_language(ASM)

        add_library(translator_contract_1024_to_256 MODULE
            tests/runtime/fixtures/translator_contract_1024_to_256.S)
        add_library(translator_contract_256_to_1024 MODULE
            tests/runtime/fixtures/translator_contract_256_to_1024.S)
        set_target_properties(
            translator_contract_1024_to_256
            translator_contract_256_to_1024
            PROPERTIES PREFIX "")

        add_executable(test_translator_contract_dlopen
            tests/runtime/test_translator_contract_dlopen.c)
        target_compile_features(test_translator_contract_dlopen PRIVATE c_std_11)
        target_compile_options(test_translator_contract_dlopen PRIVATE
            -Wall -Wextra -Werror)
        target_include_directories(test_translator_contract_dlopen PRIVATE
            interfaces/abi interfaces/abi/linux_riscv64_rvv_v1)
        target_link_libraries(test_translator_contract_dlopen PRIVATE
            chimera_inject dl)
        add_dependencies(test_translator_contract_dlopen
            translator_contract_1024_to_256
            translator_contract_256_to_1024)
        add_test(NAME translator_contract_dlopen
            COMMAND test_translator_contract_dlopen
                $<TARGET_FILE:translator_contract_1024_to_256>
                $<TARGET_FILE:translator_contract_256_to_1024>)
    endif()
endif()

message(STATUS "CHIMERA_BUILD_RUNTIME=${CHIMERA_BUILD_RUNTIME}")
message(STATUS "CHIMERA_INSTALL_RUNTIME_SOURCE=${CHIMERA_INSTALL_RUNTIME_SOURCE}")
message(STATUS "CHIMERA_INSTALL_TOOLCHAIN_SOURCE=${CHIMERA_INSTALL_TOOLCHAIN_SOURCE}")
message(STATUS "CHIMERA_INSTALL_THIRD_PARTY=${CHIMERA_INSTALL_THIRD_PARTY}")
message(STATUS "CHIMERA_BUILD_TESTS=${CHIMERA_BUILD_TESTS}")
message(STATUS "CHIMERA_DEBUG=${CHIMERA_DEBUG}")
