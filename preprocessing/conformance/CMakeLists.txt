cmake_minimum_required(VERSION 3.22)
project(vlen_escape VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# Build SVF from in-tree source (svf_src/, self-contained copy with the RVV
# scalable-vector patches applied)
# ============================================================================
# LLVM_DIR and Z3_DIR must be passed via -D or environment.
# Save the LLVM install root before add_subdirectory -- SVF's
# find_package(LLVM) will overwrite the LLVM_DIR cache entry with the cmake
# config directory (.../lib/cmake/llvm), so re-configures must tolerate both.
if(EXISTS "${LLVM_DIR}/include/llvm/IR/Instructions.h")
    set(_ORIG_LLVM_DIR "${LLVM_DIR}")
elseif(EXISTS "${LLVM_DIR}/../../../include/llvm/IR/Instructions.h")
    # LLVM_DIR is the cmake config dir (.../lib/cmake/llvm); install root is 3 up.
    get_filename_component(_ORIG_LLVM_DIR "${LLVM_DIR}/../../.." ABSOLUTE)
else()
    get_filename_component(_ORIG_LLVM_DIR "${LLVM_DIR}/../../../.." ABSOLUTE)
endif()
add_subdirectory(svf_src)

# ============================================================================
# svf-vlenesc: module-wide vlen-escape analysis (no entry func needed)
# ============================================================================
add_executable(svf-vlenesc
    src/vlen_escape_main.cpp
    src/vlen_escape.cpp
    src/global_read_tracker.cpp
    src/memory_model.cpp
)

target_link_libraries(svf-vlenesc PRIVATE SvfCore SvfLLVM)

target_include_directories(svf-vlenesc PRIVATE
    ${_ORIG_LLVM_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(svf-vlenesc PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
