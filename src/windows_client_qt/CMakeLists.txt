cmake_minimum_required(VERSION 3.18)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Concurrent)

set(CAPSTONE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/capstone)
if (NOT TARGET capstone_static)
  set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_BUILD_LEGACY_TESTS OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
  set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
  set(CAPSTONE_AARCH64_SUPPORT ON CACHE BOOL "" FORCE)
  add_subdirectory(${CAPSTONE_DIR} ${CMAKE_BINARY_DIR}/capstone_build)
endif()

add_executable(r3_windows_client_qt WIN32
  main.cpp
  ui/MainWindow.cpp
  ui/ProcessDialog.cpp
  ui/MemoryViewWindow.cpp
  ui/ModuleRangeDialog.cpp
  ui/SettingsDialog.cpp
  ui/PointerToolsDialog.cpp
  ui/PluginDevWindow.cpp
  ui/PluginFailureWindow.cpp
  ui/PluginProviderWindow.cpp
  ui/PluginRuntimeWindow.cpp
  plugins/PluginCatalog.cpp
  plugins/PluginRuntime.cpp
  ../windows_client_ng/services/ClientService.cpp
  ../windows_client/NetClient.cpp
)

target_include_directories(r3_windows_client_qt PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../windows_client_ng
  ${CMAKE_CURRENT_SOURCE_DIR}/../windows_client
  ${CAPSTONE_DIR}/include
)

target_link_libraries(r3_windows_client_qt PRIVATE
  Qt6::Core
  Qt6::Gui
  Qt6::Widgets
  Qt6::Concurrent
  ws2_32
  ole32
  capstone_static
  lz4
)

target_compile_definitions(r3_windows_client_qt PRIVATE
  UNICODE
  _UNICODE
  NOMINMAX
  WIN32_LEAN_AND_MEAN
)
target_compile_options(r3_windows_client_qt PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
  $<$<CXX_COMPILER_ID:GNU>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
  $<$<CXX_COMPILER_ID:Clang>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
)

add_library(r3_plugin_override_e2e SHARED
  tests/OverrideE2EPlugin.cpp
)
target_compile_definitions(r3_plugin_override_e2e PRIVATE R3_PLUGIN_EXPORTS)
target_include_directories(r3_plugin_override_e2e PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_compile_options(r3_plugin_override_e2e PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
  $<$<CXX_COMPILER_ID:GNU>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
  $<$<CXX_COMPILER_ID:Clang>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
)
set_target_properties(r3_plugin_override_e2e PROPERTIES
  PREFIX ""
  OUTPUT_NAME "r3_plugin_override_e2e"
)

add_executable(r3_plugin_override_e2e_runner
  tests/PluginOverrideE2ERunner.cpp
  plugins/PluginRuntime.cpp
  ../windows_client_ng/services/ClientService.cpp
  ../windows_client/NetClient.cpp
)
target_include_directories(r3_plugin_override_e2e_runner PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../windows_client_ng
  ${CMAKE_CURRENT_SOURCE_DIR}/../windows_client
)
target_link_libraries(r3_plugin_override_e2e_runner PRIVATE
  Qt6::Core
  ws2_32
  lz4
)
target_compile_definitions(r3_plugin_override_e2e_runner PRIVATE
  UNICODE
  _UNICODE
  NOMINMAX
  WIN32_LEAN_AND_MEAN
)
target_compile_options(r3_plugin_override_e2e_runner PRIVATE
  $<$<CXX_COMPILER_ID:MSVC>:/utf-8>
  $<$<CXX_COMPILER_ID:GNU>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
  $<$<CXX_COMPILER_ID:Clang>:-finput-charset=UTF-8 -fexec-charset=UTF-8>
)
