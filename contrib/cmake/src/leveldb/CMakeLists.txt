# Copyright 2017 The LEVELDB Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file. See the AUTHORS file for names of contributors.

cmake_minimum_required(VERSION 3.1)
project(Leveldb VERSION 0.1.0 LANGUAGES C CXX)

# This project can take advantage of C++11.
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED OFF)
# TODO(pwnall): See if setting this to ON gives us the *_unlocked functions.
set(CMAKE_CXX_EXTENSIONS OFF)

set(LEVELDB_PATH "${CMAKE_SOURCE_DIR}/../../src/leveldb")

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
  "${CMAKE_CURRENT_SOURCE_DIR}/include/port/port_config.h.in"
  "${PROJECT_BINARY_DIR}/include/port/port_config.h"
)

include_directories(
  "${PROJECT_BINARY_DIR}/include"
  "${LEVELDB_PATH}"
  "${LEVELDB_PATH}/include"
)

# POSIX code is specified separately so we can leave it out in the future.
add_library(leveldb_port_posix OBJECT "")
target_sources(leveldb_port_posix
  PRIVATE
    "${LEVELDB_PATH}/port/port_posix.cc"
    "${LEVELDB_PATH}/port/port_posix_sse.cc"

  PUBLIC
    # The headers below are dependencies for leveldb, but aren't needed by users
    # that link to the installed version of leveldb and rely on its public API.
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/include/port/port_config.h>
    $<BUILD_INTERFACE:${LEVELDB_PATH}/port/atomic_pointer.h>
    $<BUILD_INTERFACE:${LEVELDB_PATH}/port/port_posix.h>
    $<BUILD_INTERFACE:${LEVELDB_PATH}/port/port.h>
)

add_library(leveldb ""
  # TODO(pwnall): Move the TARGET_OBJECTS generator expressions to the PRIVATE
  # section of target_sources when cmake_minimum_required becomes 3.9 or above.
  $<TARGET_OBJECTS:leveldb_port_posix>
)
target_sources(leveldb
  PRIVATE
    "${LEVELDB_PATH}/db/builder.cc"
    "${LEVELDB_PATH}/db/builder.h"
    "${LEVELDB_PATH}/db/c.cc"
    "${LEVELDB_PATH}/db/db_impl.cc"
    "${LEVELDB_PATH}/db/db_impl.h"
    "${LEVELDB_PATH}/db/db_iter.cc"
    "${LEVELDB_PATH}/db/db_iter.h"
    "${LEVELDB_PATH}/db/dbformat.cc"
    "${LEVELDB_PATH}/db/dbformat.h"
    "${LEVELDB_PATH}/db/dumpfile.cc"
    "${LEVELDB_PATH}/db/filename.cc"
    "${LEVELDB_PATH}/db/filename.h"
    "${LEVELDB_PATH}/db/log_format.h"
    "${LEVELDB_PATH}/db/log_reader.cc"
    "${LEVELDB_PATH}/db/log_reader.h"
    "${LEVELDB_PATH}/db/log_writer.cc"
    "${LEVELDB_PATH}/db/log_writer.h"
    "${LEVELDB_PATH}/db/memtable.cc"
    "${LEVELDB_PATH}/db/memtable.h"
    "${LEVELDB_PATH}/db/repair.cc"
    "${LEVELDB_PATH}/db/skiplist.h"
    "${LEVELDB_PATH}/db/snapshot.h"
    "${LEVELDB_PATH}/db/table_cache.cc"
    "${LEVELDB_PATH}/db/table_cache.h"
    "${LEVELDB_PATH}/db/version_edit.cc"
    "${LEVELDB_PATH}/db/version_edit.h"
    "${LEVELDB_PATH}/db/version_set.cc"
    "${LEVELDB_PATH}/db/version_set.h"
    "${LEVELDB_PATH}/db/write_batch_internal.h"
    "${LEVELDB_PATH}/db/write_batch.cc"
    "${LEVELDB_PATH}/port/port.h"
    "${LEVELDB_PATH}/port/thread_annotations.h"
    "${LEVELDB_PATH}/table/block_builder.cc"
    "${LEVELDB_PATH}/table/block_builder.h"
    "${LEVELDB_PATH}/table/block.cc"
    "${LEVELDB_PATH}/table/block.h"
    "${LEVELDB_PATH}/table/filter_block.cc"
    "${LEVELDB_PATH}/table/filter_block.h"
    "${LEVELDB_PATH}/table/format.cc"
    "${LEVELDB_PATH}/table/format.h"
    "${LEVELDB_PATH}/table/iterator_wrapper.h"
    "${LEVELDB_PATH}/table/iterator.cc"
    "${LEVELDB_PATH}/table/merger.cc"
    "${LEVELDB_PATH}/table/merger.h"
    "${LEVELDB_PATH}/table/table_builder.cc"
    "${LEVELDB_PATH}/table/table.cc"
    "${LEVELDB_PATH}/table/two_level_iterator.cc"
    "${LEVELDB_PATH}/table/two_level_iterator.h"
    "${LEVELDB_PATH}/util/arena.cc"
    "${LEVELDB_PATH}/util/arena.h"
    "${LEVELDB_PATH}/util/bloom.cc"
    "${LEVELDB_PATH}/util/cache.cc"
    "${LEVELDB_PATH}/util/coding.cc"
    "${LEVELDB_PATH}/util/coding.h"
    "${LEVELDB_PATH}/util/comparator.cc"
    "${LEVELDB_PATH}/util/crc32c.cc"
    "${LEVELDB_PATH}/util/crc32c.h"
    "${LEVELDB_PATH}/util/env_posix.cc"
    "${LEVELDB_PATH}/util/env.cc"
    "${LEVELDB_PATH}/util/filter_policy.cc"
    "${LEVELDB_PATH}/util/hash.cc"
    "${LEVELDB_PATH}/util/hash.h"
    "${LEVELDB_PATH}/util/logging.cc"
    "${LEVELDB_PATH}/util/logging.h"
    "${LEVELDB_PATH}/util/mutexlock.h"
    "${LEVELDB_PATH}/util/options.cc"
    "${LEVELDB_PATH}/util/posix_logger.h"
    "${LEVELDB_PATH}/util/random.h"
    "${LEVELDB_PATH}/util/status.cc"

  # Only CMake 3.3+ supports PUBLIC sources in targets exported by "install".
  $<$<VERSION_GREATER:CMAKE_VERSION,3.2>:PUBLIC>
    "${LEVELDB_PATH}/include/leveldb/c.h"
    "${LEVELDB_PATH}/include/leveldb/cache.h"
    "${LEVELDB_PATH}/include/leveldb/comparator.h"
    "${LEVELDB_PATH}/include/leveldb/db.h"
    "${LEVELDB_PATH}/include/leveldb/dumpfile.h"
    "${LEVELDB_PATH}/include/leveldb/env.h"
    "${LEVELDB_PATH}/include/leveldb/filter_policy.h"
    "${LEVELDB_PATH}/include/leveldb/iterator.h"
    "${LEVELDB_PATH}/include/leveldb/options.h"
    "${LEVELDB_PATH}/include/leveldb/slice.h"
    "${LEVELDB_PATH}/include/leveldb/status.h"
    "${LEVELDB_PATH}/include/leveldb/table_builder.h"
    "${LEVELDB_PATH}/include/leveldb/table.h"
    "${LEVELDB_PATH}/include/leveldb/write_batch.h"
)
target_include_directories(leveldb
  PUBLIC
    $<BUILD_INTERFACE:${LEVELDB_PATH}/include>
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
