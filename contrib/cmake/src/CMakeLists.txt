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

# Compile the `build.h` Header
string(TIMESTAMP BUILD_DATETIME UTC)
configure_file(build.h.in build.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Setup Sources
set(DIR_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/addrdb.h
  ${CMAKE_CURRENT_SOURCE_DIR}/addrman.h
  ${CMAKE_CURRENT_SOURCE_DIR}/amount.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ans/ansrecord.h
  ${CMAKE_CURRENT_SOURCE_DIR}/args.h
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/base58.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chain.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chainman.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/blockindex.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/checkpoints.h
  ${CMAKE_CURRENT_SOURCE_DIR}/checkqueue.h
  ${CMAKE_CURRENT_SOURCE_DIR}/clientversion.h
  ${CMAKE_CURRENT_SOURCE_DIR}/coincontrol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/coins.h
  ${CMAKE_CURRENT_SOURCE_DIR}/compat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/byteswap.h
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/sanity.h
  ${CMAKE_CURRENT_SOURCE_DIR}/compressor.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/consensus.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/merkle.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/params.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/validation.h
  ${CMAKE_CURRENT_SOURCE_DIR}/core_io.h
  ${CMAKE_CURRENT_SOURCE_DIR}/core_memusage.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dbwrapper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/httprpc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/httpserver.h
  ${CMAKE_CURRENT_SOURCE_DIR}/init.h
  ${CMAKE_CURRENT_SOURCE_DIR}/kernel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/key.h
  ${CMAKE_CURRENT_SOURCE_DIR}/keystore.h
  ${CMAKE_CURRENT_SOURCE_DIR}/limitedmap.h
  ${CMAKE_CURRENT_SOURCE_DIR}/main.h
  ${CMAKE_CURRENT_SOURCE_DIR}/messages.h
  ${CMAKE_CURRENT_SOURCE_DIR}/memusage.h
  ${CMAKE_CURRENT_SOURCE_DIR}/merkleblock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/miner.h
  ${CMAKE_CURRENT_SOURCE_DIR}/net.h
  ${CMAKE_CURRENT_SOURCE_DIR}/netaddress.h
  ${CMAKE_CURRENT_SOURCE_DIR}/netbase.h
  ${CMAKE_CURRENT_SOURCE_DIR}/netmessagemaker.h
  ${CMAKE_CURRENT_SOURCE_DIR}/networks/netman.h
  ${CMAKE_CURRENT_SOURCE_DIR}/networks/network.h
  ${CMAKE_CURRENT_SOURCE_DIR}/networks/networktemplate.h
  ${CMAKE_CURRENT_SOURCE_DIR}/noui.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/fees.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/rbf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pow.h
  ${CMAKE_CURRENT_SOURCE_DIR}/prevector.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/block.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tx/tx.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2.h
  ${CMAKE_CURRENT_SOURCE_DIR}/processblock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/processheader.h
  ${CMAKE_CURRENT_SOURCE_DIR}/processtx.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pubkey.h
  ${CMAKE_CURRENT_SOURCE_DIR}/random.h
  ${CMAKE_CURRENT_SOURCE_DIR}/reverselock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcclient.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcprotocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcserver.h
  ${CMAKE_CURRENT_SOURCE_DIR}/scheduler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/interpreter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script_error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sigcache.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sign.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/stakescript.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/standard.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/scrypt.h
  ${CMAKE_CURRENT_SOURCE_DIR}/serialize.h
  ${CMAKE_CURRENT_SOURCE_DIR}/streams.h
  ${CMAKE_CURRENT_SOURCE_DIR}/support/allocators/secure.h
  ${CMAKE_CURRENT_SOURCE_DIR}/support/allocators/zeroafterfree.h
  ${CMAKE_CURRENT_SOURCE_DIR}/support/cleanse.h
  ${CMAKE_CURRENT_SOURCE_DIR}/support/pagelocker.h
  ${CMAKE_CURRENT_SOURCE_DIR}/sync.h
  ${CMAKE_CURRENT_SOURCE_DIR}/threadinterrupt.h
  ${CMAKE_CURRENT_SOURCE_DIR}/threadsafety.h
  ${CMAKE_CURRENT_SOURCE_DIR}/timedata.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tinyformat.h
  ${CMAKE_CURRENT_SOURCE_DIR}/torcontrol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/txdb.h
  ${CMAKE_CURRENT_SOURCE_DIR}/txmempool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/ui_interface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/undo.h
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue.h
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue_escapes.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/util.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilmoneystr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilstrencodings.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utiltime.h
  ${CMAKE_CURRENT_SOURCE_DIR}/validationinterface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/verifydb.h
  ${CMAKE_CURRENT_SOURCE_DIR}/version.h
  ${CMAKE_CURRENT_SOURCE_DIR}/versionbits.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/crypter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/db.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet_ismine.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/walletdb.h
)

set(DIR_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/addrdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/addrman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/ans/ansrecord.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/checkpoints.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/httprpc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/httpserver.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/init.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dbwrapper.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/kernel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/merkleblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/miner.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/net.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netaddress.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/noui.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/fees.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pow.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rest.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcblockchain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcmining.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcmisc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcnet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcrawtransaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcserver.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sigcache.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/timedata.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/torcontrol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txmempool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/validationinterface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/versionbits.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/amount.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/base58.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chainman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coins.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compressor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/merkle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core_read.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core_write.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hash.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/key.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/keystore.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netbase.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/block.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/blockindex.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/processblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/processheader.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/processtx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/tx/tx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pubkey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/scheduler.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/interpreter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script_error.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sign.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/standard.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/stakescript.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/args.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/support/pagelocker.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chainman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/clientversion.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibc_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibcxx_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/strnlen.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/networks/netman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/messages.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/random.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcprotocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/support/cleanse.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue_read.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue_write.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/util.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilmoneystr.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilstrencodings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utiltime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/verifydb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/chacha20.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/chacha20.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/common.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha512.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha512.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ripemd160.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ripemd160.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha1.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha1.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha512.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha512.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/scrypt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/crypter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/db.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcdump.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcwallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet_ismine.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/walletdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/rbf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcclient.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/threadinterrupt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/eccoind.cpp
)

#
# Boost Dependencies
#
set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package( Boost REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options )
include_directories( ${Boost_INCLUDE_DIR} )

#
# OpenSSL Dependencies
#
set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

#
# LibEvent Dependencies
#
find_package(LibEvent REQUIRED)
include_directories(${LIBEVENT_INCLUDE_DIR})

#
# BerkeleyDB
#
set(DB_VERSION 47)
find_package(BerkeleyDB REQUIRED)
include_directories(${BERKELEY_DB_INCLUDE_DIR})

#
# LevelDB
#
add_subdirectory(leveldb)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/leveldb/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/helpers
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/helpers/memenv)

#
# GMP
#
find_package(GMP REQUIRED)
include_directories(${GMP_INCLUDE_DIR})

#
# univalue
#
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/univalue)

#
# ECCoin
#
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(eccoin ${DIR_HEADERS} ${DIR_SOURCES})

#
# secp256k1 - uses the original autotools
#
include(ExternalProject)
ExternalProject_Add(secp256k1
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/deps/secp256k1
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1
  BUILD_IN_SOURCE 0
  CONFIGURE_COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/configure
    --prefix=<INSTALL_DIR>
  BUILD_COMMAND ${MAKE}
  INSTALL_COMMAND ""
)
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/src
  ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include
)

#
# setup all the libraries
#
set(ECC_LIBS
  ${Boost_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${LIBEVENT_LIB}
  ${LIBEVENT_PTHREADS_LIB}
  ${BERKELEY_DB_LIBRARIES}
  ${CMAKE_CURRENT_BINARY_DIR}/deps/secp256k1/src/secp256k1-build/.libs/libsecp256k1.a
  ${GMP_LIBRARIES}
  leveldb
)

#
# send definition headers
#
if(APPLE)
  add_definitions(-DMAC_OSX)
elseif(WIN32)
  add_definitions(-DWIN32)
else()
  add_definitions(-DUNIX)
endif()

#--------------------------------------------------------------------------------
#  CMake's way of creating an executable
add_executable(Eccoind MACOSX_BUNDLE WIN32
  ${DIR_HEADERS}
  ${DIR_SOURCES}
)
add_dependencies(Eccoind secp256k1)

# Link the libraries into the binary
target_link_libraries(Eccoind ${ECC_LIBS})

#--------------------------------------------------------------------------------
# Now the installation stuff below
#--------------------------------------------------------------------------------
SET(plugin_dest_dir bin)
SET(qtconf_dest_dir bin)
SET(APPS "\${CMAKE_INSTALL_PREFIX}/bin/Eccoind")
IF(APPLE)
  SET(plugin_dest_dir Eccoind.app/Contents/MacOS)
  SET(qtconf_dest_dir Eccoind.app/Contents/Resources)
  SET(APPS "\${CMAKE_INSTALL_PREFIX}/Eccoind.app")
ENDIF(APPLE)
IF(WIN32)
  SET(APPS "\${CMAKE_INSTALL_PREFIX}/bin/Eccoind.exe")
ENDIF(WIN32)

#--------------------------------------------------------------------------------
# Install the Eccoind application, on Apple, the bundle is at the root of the
# install tree, and on other platforms it'll go into the bin directory.
INSTALL(TARGETS Eccoind
  BUNDLE DESTINATION . COMPONENT Runtime
  RUNTIME DESTINATION bin COMPONENT Runtime
)

#--------------------------------------------------------------------------------
# Use BundleUtilities to get all other dependencies for the application to work.
# It takes a bundle or executable along with possible plugins and inspects it
# for dependencies.  If they are not system dependencies, they are copied.

# directories to look for dependencies
SET(DIRS ${ECC_LIBS})

# Now the work of copying dependencies into the bundle/package
# The quotes are escaped and variables to use at install time have their $ escaped
# An alternative is the do a configure_file() on a script and use install(SCRIPT  ...).
# Note that the image plugins depend on QtSvg and QtXml, and it got those copied
# over.
INSTALL(CODE "
    include(BundleUtilities)
    fixup_bundle(\"${APPS}\" \"\" \"${DIRS}\")
    " COMPONENT Runtime
)

# To Create a package, one can run "cpack -G DragNDrop CPackConfig.cmake" on Mac OS X
# where CPackConfig.cmake is created by including CPack
# And then there's ways to customize this as well
set(CPACK_BINARY_DRAGNDROP ON)
include(CPack)
