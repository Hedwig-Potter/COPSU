#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "APSI::apsi" for configuration "Release"
set_property(TARGET APSI::apsi APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(APSI::apsi PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "ASM;C;CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libapsi-0.12.a"
  )

list(APPEND _cmake_import_check_targets APSI::apsi )
list(APPEND _cmake_import_check_files_for_APSI::apsi "${_IMPORT_PREFIX}/lib/libapsi-0.12.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
