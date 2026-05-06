cmake_minimum_required(VERSION 3.16)

project(main VERSION 1.0)

set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build.")
endif()

# 使项目源目录与生成目录优先于系统路径，确保 cryptoTools/gsl/span 优先于 vcpkg 的 gsl/span
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_ROOT}/libOTe/cryptoTools/cryptoTools ${PROJECT_ROOT}/libOTe/cryptoTools)

# 若存在 vcpkg 安装目录，提前暴露其 include 路径以满足 nonstd/span 等依赖
if(EXISTS "${PROJECT_ROOT}/vcpkg/installed/x64-linux/include")
        include_directories(BEFORE ${PROJECT_ROOT}/vcpkg/installed/x64-linux/include)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND EXISTS "${PROJECT_ROOT}/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "${PROJECT_ROOT}/vcpkg/scripts/buildsystems/vcpkg.cmake"
                        CACHE STRING "Vcpkg toolchain file")
        message(STATUS "Using vcpkg toolchain: ${CMAKE_TOOLCHAIN_FILE}")
endif()

find_package(SEAL CONFIG QUIET)
find_package(OpenMP)

# 配置 cryptoTools/libOTe 构建选项
set(CRYPTO_TOOLS_STD_VER 17 CACHE STRING "cryptoTools C++ standard")
set(ENABLE_SSE ON CACHE BOOL "Enable SSE instruction set for cryptoTools")
set(ENABLE_AVX OFF CACHE BOOL "Enable AVX instruction set for cryptoTools")
set(ENABLE_PIC ON CACHE BOOL "Enable -fPIC for cryptoTools")
set(ENABLE_SODIUM ON CACHE BOOL "Enable libsodium for base OT" FORCE)
set(ENABLE_SIMPLESTOT ON CACHE BOOL "Enable Simplest base OT" FORCE)
set(ENABLE_IKNP ON CACHE BOOL "Enable IKNP OT extension" FORCE)
set(ENABLE_SILENTOT ON CACHE BOOL "Enable Silent OT extension" FORCE)
set(ENABLE_KOS ON CACHE BOOL "Enable KOS OT extension" FORCE)
set(SODIUM_MONTGOMERY OFF CACHE BOOL "Disable Montgomery noclamp requirement" FORCE)
set(ENABLE_CPP_14 ON CACHE BOOL "Enable C++14 features in cryptoTools" FORCE)

# 提供 libdivide 头文件目标满足 cryptoTools 依赖
add_library(libdivide INTERFACE)
target_include_directories(libdivide INTERFACE ${PROJECT_ROOT}/libOTe/cryptoTools/Common)

if(EXISTS "${PROJECT_ROOT}/vcpkg/installed/x64-linux/include/nonstd/span.hpp")
        set(ENABLE_SPAN_LITE ON CACHE BOOL "Enable span-lite for cryptoTools")
else()
        set(ENABLE_SPAN_LITE OFF CACHE BOOL "Enable span-lite for cryptoTools")
endif()

set(LIBOTE_SOURCE_DIR ${PROJECT_ROOT}/libOTe)
set(OSN_SOURCE_DIR ${PROJECT_ROOT}/osn)

add_subdirectory(${LIBOTE_SOURCE_DIR} ${CMAKE_BINARY_DIR}/libOTe)

add_library(osn STATIC
        ${OSN_SOURCE_DIR}/benes.cpp
        ${OSN_SOURCE_DIR}/OSNSender.cpp
        ${OSN_SOURCE_DIR}/OSNReceiver.cpp)
target_link_libraries(osn PUBLIC libOTe cryptoTools)
target_include_directories(osn PUBLIC ${OSN_SOURCE_DIR})

if(NOT TARGET nonstd::span-lite)
        add_library(nonstd_span_lite INTERFACE)
        if(EXISTS "${PROJECT_ROOT}/vcpkg/installed/x64-linux/include/nonstd/span.hpp")
                target_include_directories(nonstd_span_lite INTERFACE ${PROJECT_ROOT}/vcpkg/installed/x64-linux/include)
        endif()
        add_library(nonstd::span-lite ALIAS nonstd_span_lite)
endif()

if(TARGET SEAL::seal)
        add_executable(main
                main.cpp
                utils.cpp
                client.cpp
                server.cpp
                bcs.cpp
                bcs_osn.cpp
                ${LIBOTE_SOURCE_DIR}/libOTe/TwoChooseOne/IknpOtExtSender.cpp
                ${LIBOTE_SOURCE_DIR}/libOTe/TwoChooseOne/IknpOtExtReceiver.cpp)
        target_link_libraries(main PRIVATE SEAL::seal OpenMP::OpenMP_CXX osn cryptoTools libOTe)
        target_include_directories(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_options(main PRIVATE -Wl,--allow-multiple-definition)

        add_executable(main2
                main2.cpp
                utils.cpp
                client.cpp
                server.cpp
                bcs.cpp
                bcs_osn.cpp
                ${LIBOTE_SOURCE_DIR}/libOTe/TwoChooseOne/IknpOtExtSender.cpp
                ${LIBOTE_SOURCE_DIR}/libOTe/TwoChooseOne/IknpOtExtReceiver.cpp)
        target_link_libraries(main2 PRIVATE SEAL::seal OpenMP::OpenMP_CXX osn cryptoTools libOTe)
        target_include_directories(main2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_options(main2 PRIVATE -Wl,--allow-multiple-definition)
else()
        message(STATUS "SEAL not found; skipping main executables")
endif()

add_executable(test test.cpp)
target_link_libraries(test PRIVATE SEAL::seal)

if(CMAKE_CONFIGURATION_TYPES)
        add_compile_options($<$<CONFIG:Debug>:-g>)
elseif(CMAKE_BUILD_TYPE MATCHES "^[Dd]ebug$")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")
endif()
