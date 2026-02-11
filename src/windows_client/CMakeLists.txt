cmake_minimum_required(VERSION 3.18)

project(r3_windows_client LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/imgui)
set(CAPSTONE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/capstone)

set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_LEGACY_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_AARCH64_SUPPORT ON CACHE BOOL "" FORCE)

if (NOT TARGET capstone_static)
  add_subdirectory(${CAPSTONE_DIR} ${CMAKE_BINARY_DIR}/capstone_build)
endif()

add_executable(r3_windows_client
  main.cpp
  NetClient.cpp
  ClientUI.cpp
  ${IMGUI_DIR}/imgui.cpp
  ${IMGUI_DIR}/imgui_draw.cpp
  ${IMGUI_DIR}/imgui_tables.cpp
  ${IMGUI_DIR}/imgui_widgets.cpp
  ${IMGUI_DIR}/backends/imgui_impl_win32.cpp
  ${IMGUI_DIR}/backends/imgui_impl_dx11.cpp
)

target_include_directories(r3_windows_client PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${IMGUI_DIR}
  ${IMGUI_DIR}/backends
  ${CAPSTONE_DIR}/include
)

target_link_libraries(r3_windows_client PRIVATE d3d11 d3dcompiler dwmapi ws2_32 capstone_static lz4)

find_package(Python3 COMPONENTS Interpreter QUIET)
set(SVG_ICON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../assets/icons)
set(SVG_PACKER ${CMAKE_CURRENT_SOURCE_DIR}/../../tools/svg_packer/pack_svg.py)
if (Python3_Interpreter_FOUND AND EXISTS ${SVG_PACKER} AND EXISTS ${SVG_ICON_DIR}/manifest.json)
  file(GLOB SVG_ICON_FILES CONFIGURE_DEPENDS ${SVG_ICON_DIR}/*.svg)
  set(SVG_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated/icons)
  set(SVG_OUT_BIN ${SVG_OUT_DIR}/IconAtlas.bin)
  set(SVG_OUT_HEADER ${SVG_OUT_DIR}/IconAtlasMeta.h)
  add_custom_command(
    OUTPUT ${SVG_OUT_BIN} ${SVG_OUT_HEADER}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${SVG_OUT_DIR}
    COMMAND ${Python3_EXECUTABLE}
            ${SVG_PACKER}
            --manifest ${SVG_ICON_DIR}/manifest.json
            --icons ${SVG_ICON_DIR}
            --out-bin ${SVG_OUT_BIN}
            --out-header ${SVG_OUT_HEADER}
            --tile 48
            --padding 6
    DEPENDS ${SVG_PACKER} ${SVG_ICON_DIR}/manifest.json ${SVG_ICON_FILES}
    VERBATIM
  )
  add_custom_target(r3_svg_icons DEPENDS ${SVG_OUT_BIN} ${SVG_OUT_HEADER})
  add_dependencies(r3_windows_client r3_svg_icons)
  target_include_directories(r3_windows_client PRIVATE ${SVG_OUT_DIR})
  target_compile_definitions(r3_windows_client PRIVATE R3_HAVE_SVG_ATLAS=1)
endif()

target_compile_definitions(r3_windows_client PRIVATE UNICODE _UNICODE)
target_compile_options(r3_windows_client PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
  $<$<CXX_COMPILER_ID:GNU>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
  $<$<CXX_COMPILER_ID:Clang>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
)
