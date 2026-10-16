find_package(
  Python3
  REQUIRED
  COMPONENTS Interpreter
)

add_test(
  NAME ChimeraFunctionPointer
  COMMAND
    ${Python3_EXECUTABLE}
    "${CMAKE_CURRENT_SOURCE_DIR}/test_function_pointer.py"
    --llvm-bin "${LLVM_TOOLS_BINARY_DIR}"
    --plugin "$<TARGET_FILE:ChimeraFunctionPointer>"
)

set_tests_properties(
  ChimeraFunctionPointer
  PROPERTIES LABELS "chimera;svf"
)
