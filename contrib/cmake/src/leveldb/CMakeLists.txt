# Copyright 2017 The LEVELDB Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file. See the AUTHORS file for names of contributors.

# Fixes
set(CONTRIB_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
string(REGEX REPLACE "/contrib/cmake" "" CMAKE_CURRENT_SOURCE_DIR
       ${CMAKE_CURRENT_SOURCE_DIR})

cmake_minimum_required(VERSION 3.1)
project(Leveldb VERSION 0.1.0 LANGUAGES C CXX)

# This project can take advantage of C++11.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED OFF)
# TODO(pwnall): See if setting this to ON gives us the *_unlocked functions.
set(CMAKE_CXX_EXTENSIONS OFF)

include(TestBigEndian)
test_big_endian(LEVELDB_IS_BIG_ENDIAN)

include(CheckIncludeFile)
check_include_file("unistd.h" HAVE_UNISTD_H)

include(CheckIncludeFileCXX)
check_include_file_cxx("atomic" LEVELDB_ATOMIC_PRESENT)

include(CheckLibraryExists)
check_library_exists(crc32c crc32c_value "" HAVE_CRC32C)
check_library_exists(snappy snappy_compress "" HAVE_SNAPPY)

include(CheckSymbolExists)
check_symbol_exists(fdatasync "unistd.h" HAVE_FDATASYNC)


# Check Operating System
# CMake does not distinguish Linux from other Unices.
STRING (REGEX MATCH "Linux" PROJECT_OS_LINUX ${CMAKE_SYSTEM_NAME})
# Nor *BSD
STRING (REGEX MATCH "BSD" PROJECT_OS_BSD ${CMAKE_SYSTEM_NAME})
# Or Solaris. I'm seeing a trend, here
STRING (REGEX MATCH "SunOS" PROJECT_OS_SOLARIS ${CMAKE_SYSTEM_NAME})

# Windows is easy (for once)
IF (WIN32)
    SET (PROJECT_OS_WIN TRUE BOOL INTERNAL)
ENDIF (WIN32)

# Check if it's an Apple OS
IF (APPLE)
    # Check if it's OS X or another MacOS (that's got to be pretty unlikely)
    STRING (REGEX MATCH "Darwin" PROJECT_OS_OSX ${CMAKE_SYSTEM_NAME})
    IF (NOT PROJECT_OS_OSX)
        SET (PROJECT_OS_MACOS TRUE BOOL INTERNAL)
    ENDIF (NOT PROJECT_OS_OSX)
ENDIF (APPLE)
add_definitions(-DLEVELDB_ATOMIC_PRESENT)
IF (PROJECT_OS_LINUX)
  SET(OS_LINUX 1)
  add_definitions(-DOS_LINUX)
  add_definitions(-DLEVELDB_PLATFORM_POSIX)
ELSEIF (PROJECT_OS_BSD)
  SET(OS_FREEBSD 1)
  add_definitions(-DOS_FREEBSD)
  add_definitions(-DLEVELDB_PLATFORM_POSIX)
ELSEIF (PROJECT_OS_WIN)
  SET(OS_WINDOWS 1)
  add_definitions(-DOS_WINDOWS)
ELSEIF (PROJECT_OS_OSX)
  SET(OS_MACOSX 1)
  add_definitions(-DOS_MACOSX)
  add_definitions(-DLEVELDB_PLATFORM_POSIX)
ELSEIF (PROJECT_OS_MACOS)
  SET(OS_MACOSX 1)
  add_definitions(-DOS_MACOSX)
  add_definitions(-DLEVELDB_PLATFORM_POSIX)
ELSEIF (PROJECT_OS_SOLARIS)
  SET(OS_SOLARIS 1)
  add_definitions(-DOS_SOLARIS)
ELSE (PROJECT_OS_LINUX)
  SET(OS_LINUX 1)
  add_definitions(-DOS_LINUX)
  add_definitions(-DLEVELDB_PLATFORM_POSIX)
ENDIF (PROJECT_OS_LINUX)

configure_file(
  "${CONTRIB_CURRENT_SOURCE_DIR}/include/port/port_config.h.in"
  "${PROJECT_BINARY_DIR}/include/port/port_config.h"
)

include_directories(
  "${PROJECT_BINARY_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# POSIX code is specified separately so we can leave it out in the future.
add_library(leveldb_port_posix OBJECT "")
target_sources(leveldb_port_posix
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/port/port_posix.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/port/port_posix_sse.cc"

  PUBLIC
    # The headers below are dependencies for leveldb, but aren't needed by users
    # that link to the installed version of leveldb and rely on its public API.
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include/port/port_config.h>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/port/atomic_pointer.h>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/port/port_posix.h>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/port/port.h>
)

add_library(leveldb ""
  # TODO(pwnall): Move the TARGET_OBJECTS generator expressions to the PRIVATE
  # section of target_sources when cmake_minimum_required becomes 3.9 or above.
  $<TARGET_OBJECTS:leveldb_port_posix>
)
target_sources(leveldb
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/db/builder.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/builder.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/c.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/db_impl.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/db_impl.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/db_iter.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/db_iter.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/dbformat.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/dbformat.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/dumpfile.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/filename.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/filename.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/log_format.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/log_reader.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/log_reader.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/log_writer.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/log_writer.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/memtable.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/memtable.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/repair.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/skiplist.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/snapshot.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/table_cache.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/table_cache.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/version_edit.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/version_edit.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/version_set.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/version_set.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/write_batch_internal.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/db/write_batch.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/port/port.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/port/thread_annotations.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/block_builder.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/block_builder.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/block.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/block.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/filter_block.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/filter_block.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/format.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/format.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/iterator_wrapper.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/iterator.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/merger.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/merger.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/table_builder.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/table.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/two_level_iterator.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/table/two_level_iterator.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/arena.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/arena.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/bloom.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/cache.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/coding.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/coding.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/comparator.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/crc32c.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/crc32c.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/env_posix.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/env.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/filter_policy.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/hash.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/hash.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/logging.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/logging.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/mutexlock.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/options.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/posix_logger.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/random.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/util/status.cc"
    "${CMAKE_CURRENT_SOURCE_DIR}/helpers/memenv/memenv.cc"

  # Only CMake 3.3+ supports PUBLIC sources in targets exported by "install".
  $<$<VERSION_GREATER:CMAKE_VERSION,3.2>:PUBLIC>
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/c.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/cache.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/comparator.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/db.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/dumpfile.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/env.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/filter_policy.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/iterator.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/options.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/slice.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/status.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/table_builder.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/table.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/leveldb/write_batch.h"
)
target_include_directories(leveldb
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(leveldb
  PRIVATE
    LEVELDB_PLATFORM_POSIX
)

# TODO(pwnall): This is only needed for port_posix.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(leveldb Threads::Threads)

if (HAVE_CRC32C)
  target_link_libraries(leveldb crc32c)
endif (HAVE_CRC32C)
if (HAVE_SNAPPY)
  target_link_libraries(leveldb snappy)
endif (HAVE_SNAPPY)
