cmake_minimum_required(VERSION 3.16)

project(main VERSION 1.0)

set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build.")
endif()

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_ROOT}/libOTe/cryptoTools/cryptoTools ${PROJECT_ROOT}/libOTe/cryptoTools)

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
        set(FEUPSU_PROTOCOL_SOURCES
                utils.cpp
                client.cpp
                server.cpp
                bcs.cpp
                bcs_osn.cpp
                circuit_ot.cpp
                ${LIBOTE_SOURCE_DIR}/libOTe/TwoChooseOne/IknpOtExtSender.cpp
                ${LIBOTE_SOURCE_DIR}/libOTe/TwoChooseOne/IknpOtExtReceiver.cpp)

        add_executable(main
                main.cpp
                ${FEUPSU_PROTOCOL_SOURCES})
        target_link_libraries(main PRIVATE SEAL::seal OpenMP::OpenMP_CXX osn cryptoTools libOTe)
        target_include_directories(main PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_options(main PRIVATE -Wl,--allow-multiple-definition)

        add_executable(main2
                main2.cpp
                ${FEUPSU_PROTOCOL_SOURCES})
        target_link_libraries(main2 PRIVATE SEAL::seal OpenMP::OpenMP_CXX osn cryptoTools libOTe)
        target_include_directories(main2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_link_options(main2 PRIVATE -Wl,--allow-multiple-definition)

        foreach(target_name IN ITEMS feupsu_client feupsu_server)
                if(target_name STREQUAL "feupsu_client")
                        set(entry_source client_main.cpp)
                else()
                        set(entry_source server_main.cpp)
                endif()
                add_executable(${target_name} ${entry_source} ${FEUPSU_PROTOCOL_SOURCES})
                target_link_libraries(${target_name} PRIVATE SEAL::seal OpenMP::OpenMP_CXX osn cryptoTools libOTe)
                target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
                target_link_options(${target_name} PRIVATE -Wl,--allow-multiple-definition)
        endforeach()
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
