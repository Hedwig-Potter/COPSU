#----------------------------------------------------------------
# Generated CMake target import file.
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "oc::libOTe" for configuration ""
set_property(TARGET oc::libOTe APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(oc::libOTe PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CXX"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/liblibOTe.a"
  )

list(APPEND _cmake_import_check_targets oc::libOTe )
list(APPEND _cmake_import_check_files_for_oc::libOTe "${_IMPORT_PREFIX}/lib/liblibOTe.a" )

# Import target "oc::libOTe_Tests" for configuration ""
set_property(TARGET oc::libOTe_Tests APPEND PROPERTY IMPORTED_CONFIGURATIONS NOCONFIG)
set_target_properties(oc::libOTe_Tests PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_NOCONFIG "CXX"
  IMPORTED_LOCATION_NOCONFIG "${_IMPORT_PREFIX}/lib/liblibOTe_Tests.a"
  )

list(APPEND _cmake_import_check_targets oc::libOTe_Tests )
list(APPEND _cmake_import_check_files_for_oc::libOTe_Tests "${_IMPORT_PREFIX}/lib/liblibOTe_Tests.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
