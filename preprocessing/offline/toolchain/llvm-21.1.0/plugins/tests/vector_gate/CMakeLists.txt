set(CHIMERA_BASH_HINTS)

if(WIN32)
  find_program(
    CHIMERA_GIT_EXECUTABLE
    NAMES git
  )

  if(CHIMERA_GIT_EXECUTABLE)
    cmake_path(
      GET CHIMERA_GIT_EXECUTABLE
      PARENT_PATH CHIMERA_GIT_COMMAND_DIR
    )
    cmake_path(
      GET CHIMERA_GIT_COMMAND_DIR
      PARENT_PATH CHIMERA_GIT_ROOT
    )

    list(
      APPEND CHIMERA_BASH_HINTS
      "${CHIMERA_GIT_ROOT}/bin"
      "${CHIMERA_GIT_ROOT}/usr/bin"
    )
  endif()
endif()

find_program(
  CHIMERA_BASH_EXECUTABLE
  NAMES bash
  HINTS ${CHIMERA_BASH_HINTS}
  REQUIRED
)

find_package(
  Python3
  COMPONENTS Interpreter
  REQUIRED
)

execute_process(
  COMMAND "${CHIMERA_BASH_EXECUTABLE}" --version
  RESULT_VARIABLE CHIMERA_BASH_RESULT
  OUTPUT_QUIET
  ERROR_QUIET
)

if(NOT CHIMERA_BASH_RESULT EQUAL 0)
  message(
    FATAL_ERROR
    "Bash is required for VectorGate tests but is not runnable: "
    "${CHIMERA_BASH_EXECUTABLE}"
  )
endif()

cmake_path(
  GET LLVM_TOOLS_BINARY_DIR
  PARENT_PATH CHIMERA_LLVM_ROOT
)

# clang++ lives in LLVM_TOOLS_BINARY_DIR itself in both the build tree and
# the installed prefix; CHIMERA_LLVM_ROOT (its parent) only hosts bin/ in
# the installed layout, which is where the 2026-08-29 ctest run failed.
if(EXISTS "${LLVM_TOOLS_BINARY_DIR}/clang++")
  set(CHIMERA_VG_CLANG "${LLVM_TOOLS_BINARY_DIR}/clang++")
elseif(EXISTS "${CHIMERA_LLVM_ROOT}/bin/clang++")
  set(CHIMERA_VG_CLANG "${CHIMERA_LLVM_ROOT}/bin/clang++")
else()
  set(CHIMERA_VG_CLANG "${CHIMERA_LLVM_ROOT}/clang++")
endif()

add_test(
  NAME ChimeraVectorGate
  COMMAND
    ${CMAKE_COMMAND} -E env
    "CLANG=${CHIMERA_VG_CLANG}"
    "PLUGIN=$<TARGET_FILE:ChimeraVectorGate>"
    "PYTHON=${Python3_EXECUTABLE}"
    "${CHIMERA_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run.sh"
)

set_tests_properties(
  ChimeraVectorGate
  PROPERTIES LABELS "chimera;vector-gate"
)
