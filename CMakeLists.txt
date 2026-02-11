cmake_minimum_required(VERSION 3.18)

project(r3_android_agent LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(protocol_headers INTERFACE)
target_include_directories(protocol_headers INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lz4/lib
)

add_subdirectory(third_party/lz4)

if (ANDROID)
  add_subdirectory(src/android_agent)
endif()

if (WIN32 AND NOT ANDROID)
  option(R3_BUILD_LEGACY_WIN32_UI "Build legacy Win32 clients (ImGui + Win32 NG)" OFF)
  add_subdirectory(src/windows_client_qt)
  if (R3_BUILD_LEGACY_WIN32_UI)
    add_subdirectory(src/windows_client)
    add_subdirectory(src/windows_client_ng)
  endif()
endif()
