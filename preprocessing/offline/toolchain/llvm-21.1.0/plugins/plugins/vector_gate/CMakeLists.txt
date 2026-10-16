#
# ChimeraVectorGate
#
# LLVM-only plugin: no SVF dependency.  See VectorGatePlugin.cpp for the
# pass semantics (gate-list driven auto-vectorization disablement plus
# build-time statistics).
#

add_llvm_pass_plugin(
  ChimeraVectorGate
  BUILDTREE_ONLY
  VectorGatePlugin.cpp
)

# The plugin only uses the LLVM C API surface exposed through headers plus
# llvm::errs / raw_ostream; the pass-plugin machinery links those from the
# host tool (clang/lld), so no explicit LLVM libraries are required here.

install(
  TARGETS ChimeraVectorGate
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/chimera/llvm"
  COMPONENT ChimeraVectorGate
)
