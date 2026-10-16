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
    "Bash is required for StackObject tests but is not runnable: "
    "${CHIMERA_BASH_EXECUTABLE}"
  )
endif()

cmake_path(
  GET LLVM_TOOLS_BINARY_DIR
  PARENT_PATH CHIMERA_LLVM_ROOT
)

add_test(
  NAME ChimeraStackObject
  COMMAND
    ${CMAKE_COMMAND} -E env
    "LLVM=${CHIMERA_LLVM_ROOT}"
    "PLUGIN=$<TARGET_FILE:ChimeraStackObject>"
    "PYTHON=${Python3_EXECUTABLE}"
    "${CHIMERA_BASH_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/run.sh"
)

set_tests_properties(
  ChimeraStackObject
  PROPERTIES LABELS "chimera;stackobject"
)

add_test(
  NAME ChimeraStackObjectMapChecker
  COMMAND
    "${Python3_EXECUTABLE}"
    -m unittest
    -v
    tests/tools/test_check_stackobj_map.py
)

set_tests_properties(
  ChimeraStackObjectMapChecker
  PROPERTIES
    LABELS "chimera;stackobject;unit"
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
)
