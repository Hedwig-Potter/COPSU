cmake_minimum_required(VERSION 3.10)

project (main VERSION 1.0)

set(PROJECT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build.")
endif()

# Ensure generated headers from cryptoTools (in the build tree) are visible
# to top-level targets that directly include cryptoTools headers (e.g., server.cpp).
# Use BEFORE so the project's cryptoTools headers are preferred over system installs
# Prefer project source headers and any bundled vcpkg includes before system paths
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${PROJECT_ROOT}/libOTe/cryptoTools)

# If vcpkg is present in the repo, expose its include dir so nonstd/span.hpp
# and other vcpkg headers can be found during compilation.
if(EXISTS "${CMAKE_SOURCE_DIR}/../vcpkg/installed/x64-linux/include")
  include_directories(BEFORE ${CMAKE_SOURCE_DIR}/../vcpkg/installed/x64-linux/include)
endif()

# Use a compatible C++ standard for the installed compiler. Older GCC may not
# support the CMake canonical '20' token, so default to C++17 for now.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optionally use vcpkg toolchain if present beside this CMakeLists
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE AND EXISTS "${PROJECT_ROOT}/vcpkg/scripts/buildsystems/vcpkg.cmake")
  set(CMAKE_TOOLCHAIN_FILE "${PROJECT_ROOT}/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")
  message(STATUS "Using vcpkg toolchain: ${CMAKE_TOOLCHAIN_FILE}")
else()
  message(STATUS "vcpkg toolchain not found under src; proceeding without it")
endif()

find_package(SEAL CONFIG QUIET)
find_package(OpenMP)

# Only add SEAL-dependent executables when SEAL is available. When SEAL is
# missing, skip adding these targets so the project can configure and build
# cryptoTools and other components in environments without SEAL.
if(TARGET SEAL::seal)
  add_executable(main-base main-base.cpp server.cpp client.cpp utils.cpp bcs.cpp bcs_osn.cpp)
  add_executable(main2 main2.cpp server.cpp client.cpp utils.cpp bcs.cpp bcs_osn.cpp)
  target_compile_features(main-base PRIVATE cxx_std_17)
  target_compile_features(main2 PRIVATE cxx_std_17)
  # main-psi targets are omitted because the corresponding sources are not part of this tree
else()
  message(STATUS "SEAL not found; skipping building main executables that require SEAL")
endif()

# Build cryptoTools as a static library (use C++ standard compatible with compiler)
set(CRYPTO_TOOLS_STD_VER 17 CACHE STRING "cryptoTools C++ standard")

# If vcpkg's nonstd/span.hpp is present, enable span-lite so cryptoTools
# uses the header-only nonstd span implementation instead of requiring C++20.
if(EXISTS "${CMAKE_SOURCE_DIR}/../vcpkg/installed/x64-linux/include/nonstd/span.hpp")
  set(ENABLE_SPAN_LITE ON CACHE BOOL "Enable span-lite for cryptoTools")
  message(STATUS "Found nonstd/span.hpp in vcpkg; enabling ENABLE_SPAN_LITE")
else()
  set(ENABLE_SPAN_LITE OFF CACHE BOOL "Enable span-lite for cryptoTools")
endif()

# Enable SSE optimizations required by cryptoTools blake2 sse implementation
set(ENABLE_SSE ON CACHE BOOL "Enable SSE instruction set for cryptoTools")
set(ENABLE_AVX OFF CACHE BOOL "Enable AVX instruction set for cryptoTools")
set(ENABLE_PIC ON CACHE BOOL "Enable -fPIC for cryptoTools")

set(ENABLE_SODIUM ON CACHE BOOL "Enable libsodium for base OT" FORCE)
set(ENABLE_SIMPLESTOT ON CACHE BOOL "Enable Simplest base OT" FORCE)
set(ENABLE_IKNP ON CACHE BOOL "Enable IKNP OT extension" FORCE)
set(ENABLE_SILENTOT ON CACHE BOOL "Enable Silent OT extension" FORCE)
set(ENABLE_KOS ON CACHE BOOL "Enable KOS OT extension for SilentOT" FORCE)
set(SODIUM_MONTGOMERY OFF CACHE BOOL "Disable Montgomery noclamp requirement for standard libsodium" FORCE)

# Provide a header-only libdivide target to satisfy cryptoTools link dependency
add_library(libdivide INTERFACE)
target_include_directories(libdivide INTERFACE ${PROJECT_ROOT}/libOTe/cryptoTools/Common)

# Provide header-only span-lite target if available via vcpkg
set(LIBOTE_SOURCE_DIR ${PROJECT_ROOT}/libOTe)
set(OSN_SOURCE_DIR ${PROJECT_ROOT}/osn)

add_subdirectory(${LIBOTE_SOURCE_DIR} ${CMAKE_BINARY_DIR}/libOTe)

add_library(osn STATIC
  ${OSN_SOURCE_DIR}/benes.cpp
  ${OSN_SOURCE_DIR}/OSNSender.cpp
  ${OSN_SOURCE_DIR}/OSNReceiver.cpp)
target_link_libraries(osn PUBLIC libOTe cryptoTools)
target_include_directories(osn PUBLIC ${OSN_SOURCE_DIR})

add_executable(osn_demo osn_demo/main.cpp)
target_link_libraries(osn_demo PRIVATE osn libOTe cryptoTools)
target_compile_definitions(osn_demo PRIVATE ENABLE_BOOST)

# If nonstd::span-lite isn't available on the system, provide a no-op INTERFACE
# target so existing cryptoTools CMake logic that links to nonstd::span-lite
# won't break the top-level build. This keeps builds working without vcpkg.
if(NOT TARGET nonstd::span-lite)
  # Create a valid CMake target name and then provide an alias with the
  # namespaced name used in cryptoTools. Some CMake versions reject '::' in
  # add_library() target names, so we create a safe name and alias it.
  add_library(nonstd_span_lite INTERFACE)
  # If vcpkg installed span-lite is present, add its include directory so the
  # header <nonstd/span.hpp> can be found. This makes ENABLE_SPAN_LITE optional
  # without requiring vcpkg to be present.
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/installed/x64-linux/include/nonstd/span.hpp")
    target_include_directories(nonstd_span_lite INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/installed/x64-linux/include)
  endif()
  add_library(nonstd::span-lite ALIAS nonstd_span_lite)
endif()

# cwPSU executable (restore executable target) - only when SEAL is available
if(TARGET SEAL::seal)
  add_executable(main-cwpsu main-cwpsu.cpp server.cpp client.cpp utils.cpp bcs.cpp bcs_osn.cpp)
  add_executable(cwpsu-client client_main.cpp server.cpp client.cpp utils.cpp bcs.cpp bcs_osn.cpp)
  add_executable(cwpsu-server server_main.cpp server.cpp client.cpp utils.cpp bcs.cpp bcs_osn.cpp)
  target_compile_features(main-cwpsu PRIVATE cxx_std_17)
  target_compile_features(cwpsu-client PRIVATE cxx_std_17)
  target_compile_features(cwpsu-server PRIVATE cxx_std_17)
  set(SEAL_LIB SEAL::seal)
  add_compile_definitions(HAVE_SEAL=1)
  target_link_libraries(main-cwpsu ${SEAL_LIB} OpenMP::OpenMP_CXX osn cryptoTools)
  target_link_libraries(cwpsu-client ${SEAL_LIB} OpenMP::OpenMP_CXX osn cryptoTools)
  target_link_libraries(cwpsu-server ${SEAL_LIB} OpenMP::OpenMP_CXX osn cryptoTools)
else()
  set(SEAL_LIB )
  message(STATUS "SEAL not found; SEAL-dependent targets will be skipped or built without SEAL linkage")
endif()

foreach(cwpsu_target cwpsu-client cwpsu-server)
  if(TARGET ${cwpsu_target})
    target_include_directories(${cwpsu_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_options(${cwpsu_target} PRIVATE -Wl,--allow-multiple-definition)
  endif()
endforeach()

# Only link and set include dirs for the main-* executables if they were created.
if(TARGET main-base)
  target_link_libraries(main-base ${SEAL_LIB} OpenMP::OpenMP_CXX osn cryptoTools)
  target_include_directories(main-base PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_options(main-base PRIVATE -Wl,--allow-multiple-definition)
endif()

if(TARGET main2)
  target_link_libraries(main2 ${SEAL_LIB} OpenMP::OpenMP_CXX osn cryptoTools)
  target_include_directories(main2 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_options(main2 PRIVATE -Wl,--allow-multiple-definition)
endif()

# Ensure headers in this source directory (e.g., utils.h, server.h, client.h) are found
if(TARGET main-cwpsu)
  target_include_directories(main-cwpsu PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_options(main-cwpsu PRIVATE -Wl,--allow-multiple-definition)
endif()
