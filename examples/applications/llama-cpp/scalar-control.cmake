# Include after the llama.cpp targets have been created.
# Keep the ggml targets' explicit RVV kernels enabled.
include_guard(GLOBAL)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "scalar-control.cmake requires the patched Clang toolchain")
endif()

foreach(chimera_required_target llama llama-perplexity)
    if(NOT TARGET ${chimera_required_target})
        message(FATAL_ERROR "Include scalar-control.cmake after target creation")
    endif()
endforeach()

set(chimera_scalar_control_targets "")
foreach(chimera_control_target
        llama llama-common llama-common-base cpp-httplib
        llama-perplexity-impl llama-perplexity)
    if(TARGET ${chimera_control_target})
        target_compile_options(${chimera_control_target} PRIVATE
            "$<$<COMPILE_LANGUAGE:C,CXX>:-march=rv64gc;-fno-vectorize;-fno-slp-vectorize>")
        list(APPEND chimera_scalar_control_targets ${chimera_control_target})
    endif()
endforeach()
message(STATUS "Chimera scalar control targets: ${chimera_scalar_control_targets}")
