add_library(ChimeraCommon STATIC
  PCSectionsMeta.cpp
)

set_target_properties(ChimeraCommon PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)

target_include_directories(ChimeraCommon
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
