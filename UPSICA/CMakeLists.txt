cmake_minimum_required(VERSION 3.16)

project(UPSICA VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(UPSICA_ENABLE_SEAL "Enable Microsoft SEAL integration" OFF)
option(UPSICA_ENABLE_APSI "Build the optional, unused bundled APSI library" OFF)
set(UPSICA_APSI_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/APSI-main" CACHE PATH "Path to APSI source tree")
set(UPSICA_ENABLE_SEAL ON CACHE BOOL "Enable Microsoft SEAL integration" FORCE)

if(UPSICA_ENABLE_SEAL)
  if(DEFINED SEAL_DIR AND EXISTS "${SEAL_DIR}")
    list(PREPEND CMAKE_PREFIX_PATH "${SEAL_DIR}")
  endif()

  find_package(SEAL 4.1 CONFIG QUIET)
  if(NOT SEAL_FOUND AND TARGET SEAL::seal)
    set(SEAL_FOUND TRUE)
  endif()

  if(NOT SEAL_FOUND)
    message(FATAL_ERROR
      "UPSICA_ENABLE_SEAL=ON but Microsoft SEAL was not found. "
      "Please set SEAL_DIR (e.g. <vcpkg>/installed/x64-linux/share/seal) "
      "or provide CMAKE_TOOLCHAIN_FILE for vcpkg.")
  endif()
endif()

if(UPSICA_ENABLE_APSI)
  if(NOT EXISTS "${UPSICA_APSI_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
      "UPSICA_ENABLE_APSI=ON but APSI source was not found at ${UPSICA_APSI_SOURCE_DIR}. "
      "Set UPSICA_APSI_SOURCE_DIR to your APSI source root.")
  endif()

  # Build only APSI core library as a dependency of UPSICA.
  set(APSI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(APSI_BUILD_CLI OFF CACHE BOOL "" FORCE)
  set(APSI_USE_LOG4CPLUS OFF CACHE BOOL "" FORCE)
  set(APSI_USE_ZMQ OFF CACHE BOOL "" FORCE)

  add_subdirectory(${UPSICA_APSI_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/apsi-build EXCLUDE_FROM_ALL)
endif()

add_library(upsica_core
  src/CryptoPrimitives/dh_oprf.cpp
  src/CryptoPrimitives/fhe_wrapper.cpp
  src/DataStructure/vbf.cpp
  src/DataStructure/hashing.cpp
  src/DataStructure/polynomial_links.cpp
  src/Protocol/vbf_psi_ca.cpp
)

target_include_directories(upsica_core
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(upsica_core
  PUBLIC
    UPSICA_ENABLE_SEAL=$<BOOL:${UPSICA_ENABLE_SEAL}>
    UPSICA_ENABLE_APSI=$<BOOL:${UPSICA_ENABLE_APSI}>
)

target_link_libraries(upsica_core PUBLIC OpenSSL::Crypto)

if(UPSICA_ENABLE_SEAL)
  target_link_libraries(upsica_core PUBLIC SEAL::seal)
endif()

if(UPSICA_ENABLE_APSI)
  target_link_libraries(upsica_core PUBLIC apsi)
endif()

add_executable(upsica-vbf src/vbf_network_main.cpp)
target_link_libraries(upsica-vbf PRIVATE upsica_core)

if(BUILD_TESTING)
  add_executable(upsica_unit_tests tests/protocol_minimal_test.cpp)
  target_link_libraries(upsica_unit_tests PRIVATE upsica_core)
  add_test(NAME upsica_unit_tests COMMAND upsica_unit_tests)
endif()

install(TARGETS upsica_core upsica-vbf
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)
