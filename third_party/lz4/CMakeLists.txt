cmake_minimum_required(VERSION 3.18)

project(lz4 C)

add_library(lz4 STATIC
  lib/lz4.c
)

target_include_directories(lz4 PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

set_target_properties(lz4 PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)
