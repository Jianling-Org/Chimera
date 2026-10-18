cmake_minimum_required(VERSION 3.20)

project(ChimeraLLVM LANGUAGES CXX)

include(GNUInstallDirs)

find_package(LLVM 21.1.0 EXACT REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM_DIR = ${LLVM_DIR}")
message(STATUS "LLVM_INCLUDE_DIRS = ${LLVM_INCLUDE_DIRS}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

# standalone LLVM plugin 必须显式加入 LLVM headers / definitions
separate_arguments(
  LLVM_DEFINITIONS_LIST
  NATIVE_COMMAND
  ${LLVM_DEFINITIONS}
)

add_definitions(${LLVM_DEFINITIONS_LIST})

include_directories(SYSTEM
  ${LLVM_INCLUDE_DIRS}
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(
  CHIMERA_ENABLE_STACKOBJECT
  "Build the LLVM-only Chimera StackObject plugin"
  OFF
)

option(
  CHIMERA_ENABLE_SVF
  "Build the SVF-backed Chimera function-pointer plugin"
  OFF
)

option(
  CHIMERA_ENABLE_VECTOR_GATE
  "Build the LLVM-only Chimera vector gate plugin (auto-vectorization disablement)"
  OFF
)

option(
  BUILD_TESTING
  "Build and register Chimera tests"
  OFF
)

include(CTest)

message(STATUS "Chimera StackObject plugin: ${CHIMERA_ENABLE_STACKOBJECT}")
message(STATUS "Chimera SVF plugin: ${CHIMERA_ENABLE_SVF}")
message(STATUS "Chimera VectorGate plugin: ${CHIMERA_ENABLE_VECTOR_GATE}")
message(STATUS "Chimera tests: ${BUILD_TESTING}")

if(CHIMERA_ENABLE_STACKOBJECT OR CHIMERA_ENABLE_SVF)
  add_subdirectory(common)
endif()

if(CHIMERA_ENABLE_STACKOBJECT)
  add_subdirectory(plugins/stackobject)

  if(BUILD_TESTING)
    add_subdirectory(tests/stackobject)
  endif()
endif()

if(CHIMERA_ENABLE_SVF)
  add_subdirectory(plugins/svf)

  if(BUILD_TESTING)
    add_subdirectory(tests/svf)
  endif()
endif()

if(CHIMERA_ENABLE_VECTOR_GATE)
  add_subdirectory(plugins/vector_gate)

  if(BUILD_TESTING)
    add_subdirectory(tests/vector_gate)
  endif()
endif()
