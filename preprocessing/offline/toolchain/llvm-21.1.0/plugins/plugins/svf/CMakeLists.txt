#
# SVF
#
# Do not hard-code the SVF installation path here.
#
# Configure with one of:
#
#   cmake -S . -B build \
#     -DSVF_DIR=/path/to/lib/cmake/SVF
#
# or:
#
#   cmake -S . -B build \
#     -DCMAKE_PREFIX_PATH=/path/to/svf/install
#
find_package(
  SVF REQUIRED CONFIG
)

if(NOT TARGET SVF::SvfLLVM)
  message(FATAL_ERROR
    "SVF package does not provide required target SVF::SvfLLVM")
endif()

# SVF::SvfLLVM is the intentionally retained upstream imported target.
# In this static-SVF plugin configuration, libSvfLLVM.a and libSvfCore.a
# are linked into ChimeraFunctionPointer through that target. LLVM itself
# must instead come from the LLVM 21.1.0 selected by this Chimera build.
#
# SVF's exported target also carries a transitive LLVM dependency. Remove
# that dependency entirely to avoid duplicate/circular LLVM linkage inside
# an LLVM pass plugin. Do not change the SVF libraries to shared linkage and
# do not replace SVF::SvfLLVM with a Chimera-owned imported target.
#
# The transitive entries depend on how the consuming LLVM was built:
# against an LLVM dylib install llvm_map_components_to_libnames() yields the
# single name "LLVM"; against a static-only LLVM install it yields component
# names ("LLVMCore", "LLVMSupport", ...). Filtering by prefix "^LLVM" covers
# both. Missing this for the static case links a full second copy of LLVM
# into the plugin, and dlopen'ing it into ld.lld (--load-pass-plugin) aborts
# with "Option 'print-pipeline-passes' registered more than once".
get_target_property(
  SVF_LLVM_LINK_LIBS
  SVF::SvfLLVM
  INTERFACE_LINK_LIBRARIES
)

if(SVF_LLVM_LINK_LIBS)
  list(
    FILTER
    SVF_LLVM_LINK_LIBS
    EXCLUDE REGEX
    "^LLVM"
  )
endif()

set_property(
  TARGET SVF::SvfLLVM
  PROPERTY INTERFACE_LINK_LIBRARIES
  "${SVF_LLVM_LINK_LIBS}"
)

#
# Chimera function-pointer pass
#
add_llvm_pass_plugin(
  ChimeraFunctionPointer
  BUILDTREE_ONLY
  FunctionPointerPass.cpp
  SVFPlugin.cpp
)

target_link_libraries(
  ChimeraFunctionPointer
  PRIVATE
  ChimeraCommon
  SVF::SvfLLVM
  ${CMAKE_DL_LIBS}
)

#
# Bundled SVF extapi.bc
#
# This file belongs to the Chimera source tree and is pinned together
# with the LLVM/SVF versions used by Chimera.
#
set(
  CHIMERA_EXTAPI_BC
  "${CMAKE_CURRENT_LIST_DIR}/resources/extapi.bc"
)

if(NOT EXISTS "${CHIMERA_EXTAPI_BC}")
  message(
    FATAL_ERROR
    "Bundled extapi.bc not found: ${CHIMERA_EXTAPI_BC}"
  )
endif()

#
# Runtime layout:
#
#   ChimeraFunctionPointer.so
#   extapi.bc
#
add_custom_command(
  TARGET ChimeraFunctionPointer
  POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different
    "${CHIMERA_EXTAPI_BC}"
    "$<TARGET_FILE_DIR:ChimeraFunctionPointer>/extapi.bc"
  COMMENT
    "Copying bundled SVF extapi.bc next to ChimeraFunctionPointer"
)

install(
  TARGETS ChimeraFunctionPointer
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  COMPONENT ChimeraFunctionPointer
)

install(
  FILES "${CHIMERA_EXTAPI_BC}"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  COMPONENT ChimeraFunctionPointer
)
