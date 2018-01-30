# ECC Build System
#
# This CMakeLists.txt is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# Fixes
set(CONTRIB_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
string(REGEX REPLACE "/contrib/cmake" "" CMAKE_CURRENT_SOURCE_DIR
       ${CMAKE_CURRENT_SOURCE_DIR})

# CMake version
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

# Include CMake Modules
list(APPEND CMAKE_MODULE_PATH "${CONTRIB_CURRENT_SOURCE_DIR}/modules")

include(Custom)

# Set policies
set_policy(CMP0028 NEW) # ENABLE CMP0028: Double colon in target name means ALIAS or IMPORTED target.
set_policy(CMP0054 NEW) # ENABLE CMP0054: Only interpret if() arguments as variables or keywords when unquoted.
set_policy(CMP0042 NEW) # ENABLE CMP0042: MACOSX_RPATH is enabled by default.
set_policy(CMP0063 NEW) # ENABLE CMP0063: Honor visibility properties for all target types.

include(GetGitRevisionDescription)
include(HealthCheck)
include(cotire)
include(ucm)

#
# Generate Project Information
#
# Get git revision
get_git_head_revision(GIT_REFSPEC GIT_SHA1)
string(SUBSTRING "${GIT_SHA1}" 0 12 GIT_REV)
if(NOT GIT_SHA1)
    set(GIT_REV "0")
endif()

# Meta information about the project
set(META_PROJECT_NAME        "ECC")
set(META_PROJECT_DESCRIPTION "ECC Descentralized Coin")
set(META_AUTHOR_ORGANIZATION "ECC Project")
set(META_AUTHOR_DOMAIN       "https://github.com/brunoalano/eccoin/")
set(META_AUTHOR_MAINTAINER   "opensource@ecc.network")
set(META_VERSION_MAJOR       "1")
set(META_VERSION_MINOR       "0")
set(META_VERSION_PATCH       "0")
set(META_VERSION_REVISION    "${GIT_REV}")
set(META_VERSION             "${META_VERSION_MAJOR}.${META_VERSION_MINOR}.${META_VERSION_PATCH}")
set(META_NAME_VERSION        "${META_PROJECT_NAME} v${META_VERSION} (${META_VERSION_REVISION})")
set(META_CMAKE_INIT_SHA      "${GIT_SHA1}")
string(MAKE_C_IDENTIFIER ${META_PROJECT_NAME} META_PROJECT_ID)
string(TOUPPER ${META_PROJECT_ID} META_PROJECT_ID)

#
# Project configuration options
#

# Project options
option(OPTION_BUILD_TESTS    "Build tests."                       ON)
option(OPTION_BUILD_DOCS     "Build documentation."              OFF)

#
# Declare project
#

# Generate folders for IDE targets (e.g., VisualStudio solutions)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
set(IDE_FOLDER "")

# Declare project
project(${META_PROJECT_NAME} C CXX)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR})

# Create version file
file(WRITE "${PROJECT_BINARY_DIR}/VERSION" "${META_NAME_VERSION}")

#
# Compiler settings and options
#
include(CompileOptions)
ucm_add_flags(CXX ${DEFAULT_COMPILE_OPTIONS})
ucm_add_linker_flags(${DEFAULT_LINKER_OPTIONS})

# Configure health check tools
enable_cppcheck(On)
enable_clang_tidy(On)

# Check for C++11/14 support
project_check_cpp_version()
check_cxx_compiler_flag( "-std=c++11"   COMPILER_SUPPORTS_CXX11 )
check_cxx_compiler_flag( "-std=c++0x"   COMPILER_SUPPORTS_CXX0X )
if( COMPILER_SUPPORTS_CXX11 )
    if( CMAKE_COMPILER_IS_GNUCXX )
        ucm_add_flags( CXX -std=gnu++11 )
    else()
        ucm_add_flags( CXX -std=c++11 )
    endif()
elseif( COMPILER_SUPPORTS_CXX0X)
    ucm_add_flags( -std=c++0x )
else()
    # MSVC, On by default (if available)
endif()

# Append the `src`
add_subdirectory(src)