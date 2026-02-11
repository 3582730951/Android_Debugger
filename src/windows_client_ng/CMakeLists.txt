cmake_minimum_required(VERSION 3.18)

add_executable(r3_windows_client_ng
  main.cpp
  services/ClientService.cpp
  ui/AddAddressDialog.cpp
  ui/CeLayoutWindow.cpp
  ui/SettingsWindow.cpp
  ui/PointerToolsWindow.cpp
  memory_view/MemoryViewWindow.cpp
  ../windows_client/NetClient.cpp
)

target_include_directories(r3_windows_client_ng PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../windows_client
  ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/capstone/include
)

target_link_libraries(r3_windows_client_ng PRIVATE
  d2d1
  dwrite
  dwmapi
  windowscodecs
  ws2_32
  ole32
  comctl32
  capstone_static
  lz4
)

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
  add_custom_target(r3_svg_icons_ng DEPENDS ${SVG_OUT_BIN} ${SVG_OUT_HEADER})
  add_dependencies(r3_windows_client_ng r3_svg_icons_ng)
endif()

target_compile_definitions(r3_windows_client_ng PRIVATE UNICODE _UNICODE)
target_compile_options(r3_windows_client_ng PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
  $<$<CXX_COMPILER_ID:GNU>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
  $<$<CXX_COMPILER_ID:Clang>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
)
