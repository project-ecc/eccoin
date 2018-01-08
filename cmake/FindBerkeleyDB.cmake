# Copyright 2010, Dimitri Kaparis <kaparis.dimitri at gmail dot com>

# CMake module to find Berkeley DB

# For MSVC, only static libraries are used (with 's' suffix)

# This module uses:
#
# DB_ROOT_DIR - set to BerkeleyDB's root directory
# DB_VERSION - set to required BerkeleyDB version, e.g. 47

# This module defines:
# DB_FOUND - True if BerkleyDB is found
# DB_INCLUDE_DIR - BerkeleyDB's include directory
# DB_LIBRARIES - Libraries needed to use Berkeley DB

find_path(DB_INCLUDE_DIR db.h db_cxx.h
          PATHS ${DB_ROOT_DIR} $ENV{DBROOTDIR}
          PATH_SUFFIXES include db${DB_VERSION}
          )
if (MSVC)
    if (CMAKE_CL_64)
        set(_db_lib_path_SUFFIXES_DEBUG Debug_AMD64)
        set(_db_lib_path_SUFFIXES_RELEASE Release_AMD64)
    else (CMAKE_CL_64)
        set(_db_lib_path_SUFFIXES_DEBUG Debug)
        set(_db_lib_path_SUFFIXES_RELEASE Release)
    endif (CMAKE_CL_64)
    find_library(DBLIB_STATIC_RELEASE libdb${DB_VERSION}s
                 PATHS ${DB_ROOT_DIR} $ENV{DBROOTDIR} ${DB_INCLUDE_DIR}
                 PATH_SUFFIXES ${_db_lib_path_SUFFIXES_RELEASE} lib)
    find_library(DBLIB_STATIC_DEBUG libdb${DB_VERSION}sd
                 PATHS ${DB_ROOT_DIR} $ENV{DBROOTDIR} ${DB_INCLUDE_DIR}
                 PATH_SUFFIXES ${_db_lib_path_SUFFIXES_DEBUG} lib)
    set(DB_LIBRARIES optimized ${DBLIB_STATIC_RELEASE}
                     debug ${DBLIB_STATIC_DEBUG})

else(MSVC)
    find_library(DB_LIB db
                 PATHS ${DB_ROOT_DIR} $ENV{DBROOTDIR} ${DB_INCLUDE_DIR}
                       /usr/local/lib
                 PATH_SUFFIXES lib
                               db${DB_VERSION})
    find_library(DB_LIBCXX db_cxx
                 PATHS ${DB_ROOT_DIR} $ENV{DBROOTDIR} ${DB_INCLUDE_DIR}
                       /usr/local/lib
                 PATH_SUFFIXES lib db${DB_VERSION})
    set(DB_LIBRARIES ${DB_LIB})
    if (DB_LIBCXX)
        list(APPEND DB_LIBRARIES ${DB_LIBCXX})
    endif (DB_LIBCXX)
endif (MSVC)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DB DEFAULT_MSG DB_INCLUDE_DIR DB_LIBRARIES)