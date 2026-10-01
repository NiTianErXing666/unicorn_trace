cmake_minimum_required(VERSION 3.22.1)
project("testtrace")

# ---- capstone disassembler (AArch64 only) ----
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
add_subdirectory(capstone)

# ---- unicorn engine (aarch64 only, static) ----
set(UNICORN_ARCH "aarch64" CACHE STRING "Enabled unicorn architectures")
set(UNICORN_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UNICORN_INSTALL OFF CACHE BOOL "" FORCE)
set(UNICORN_FUZZ OFF CACHE BOOL "" FORCE)
set(UNICORN_LOGGING OFF CACHE BOOL "" FORCE)
add_subdirectory(unicorn)

# ---- trace target library: functions we point unicorn at ----
add_library(testtarget SHARED testtarget/testtarget.c)
target_link_libraries(testtarget log)
target_compile_options(testtarget PRIVATE -fno-omit-frame-pointer -O2)

# ---- main app library: JNI bridge + unicorn trace engine ----
add_library(${CMAKE_PROJECT_NAME} SHARED
        native-lib.cpp
        unitrace/uni_trace.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unitrace
        ${CMAKE_CURRENT_SOURCE_DIR}/testtarget)
target_link_libraries(${CMAKE_PROJECT_NAME}
        unicorn
        capstone
        android
        log)

# ---- standalone CLI harness for on-device debugging (push & run via adb) ----
add_executable(unitrace_cli
        cli/cli_main.cpp
        unitrace/uni_trace.cpp
        testtarget/testtarget.c)
target_include_directories(unitrace_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unitrace
        ${CMAKE_CURRENT_SOURCE_DIR}/testtarget)
target_link_libraries(unitrace_cli unicorn capstone log)
target_compile_options(unitrace_cli PRIVATE -fno-omit-frame-pointer -O0 -g)
