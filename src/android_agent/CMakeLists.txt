add_executable(r3_android_agent
  main.cpp
  MemoryScanner.cpp
  SafeMemoryReader.cpp
)

target_include_directories(r3_android_agent PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(r3_android_agent PRIVATE protocol_headers lz4)
if(ANDROID)
  target_link_libraries(r3_android_agent PRIVATE log z)
endif()

target_compile_definitions(r3_android_agent PRIVATE _GNU_SOURCE)

target_compile_options(r3_android_agent PRIVATE
  -fno-exceptions
  -fno-rtti
)

target_link_options(r3_android_agent PRIVATE
  -static-libstdc++
  -static-libgcc
)
