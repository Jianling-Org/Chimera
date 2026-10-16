add_llvm_pass_plugin(ChimeraStackObject
  BUILDTREE_ONLY
  StackObjectPlugin.cpp
  StackObjectPass.cpp
  StackAddress.cpp
  RVVIntrinsic.cpp
  InlineAsm.cpp
)

target_include_directories(
  ChimeraStackObject
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/common
)

target_link_libraries(
  ChimeraStackObject
  PRIVATE
    ChimeraCommon
)

install(
  TARGETS ChimeraStackObject
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  COMPONENT ChimeraStackObject
)
