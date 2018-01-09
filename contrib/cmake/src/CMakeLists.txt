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
  ${CMAKE_CURRENT_SOURCE_DIR}/txdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/key.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/addrman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/amount.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/base58.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/blockindex.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chainman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/networks/netman.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/checkpoints.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/clientversion.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coins.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compressor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core_read.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/core_write.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/dbwrapper.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hash.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/keystore.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/merkleblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/messages.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/miner.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/net.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/netbase.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/noui.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pow.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/processblock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/processheader.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pubkey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/random.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/scheduler.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/timedata.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/torcontrol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/txmempool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/util.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/fs.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/args.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilmoneystr.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilstrencodings.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utiltime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/validationinterface.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/versionbits.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/crypter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/db.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet_ismine.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/walletdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/support/cleanse.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/support/pagelocker.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/bitcoinconsensus.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/interpreter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script_error.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sigcache.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sign.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/standard.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/block.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/tx/tx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/fees.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/rbf.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha512.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ripemd160.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha1.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha512.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/chacha20.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/merkle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibc_compat.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibc_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/glibcxx_sanity.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/compat/strnlen.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/init.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/eccoind.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/scrypt.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/kernel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/httprpc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/httpserver.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rest.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcblockchain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcclient.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcdump.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcmining.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcmisc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcnet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcprotocol.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcrawtransaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcserver.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcwallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue_read.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue_write.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/script/stakescript.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/signals.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/processtx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/verifydb.cpp )

set(DIR_HEADERS
  ${CMAKE_CURRENT_SOURCE_DIR}/txdb.h
  ${CMAKE_CURRENT_SOURCE_DIR}/key.h
  ${CMAKE_CURRENT_SOURCE_DIR}/addrman.h
  ${CMAKE_CURRENT_SOURCE_DIR}/amount.h
  ${CMAKE_CURRENT_SOURCE_DIR}/arith_uint256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/base58.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/blockindex.h
  ${CMAKE_CURRENT_SOURCE_DIR}/bloom.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chain.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/chainman.h
  ${CMAKE_CURRENT_SOURCE_DIR}/networks/netman.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/checkpoints.h
  ${CMAKE_CURRENT_SOURCE_DIR}/clientversion.h
  ${CMAKE_CURRENT_SOURCE_DIR}/coins.h
  ${CMAKE_CURRENT_SOURCE_DIR}/compressor.h
  ${CMAKE_CURRENT_SOURCE_DIR}/dbwrapper.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hash.h
  ${CMAKE_CURRENT_SOURCE_DIR}/keystore.h
  ${CMAKE_CURRENT_SOURCE_DIR}/main.h
  ${CMAKE_CURRENT_SOURCE_DIR}/merkleblock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/messages.h
  ${CMAKE_CURRENT_SOURCE_DIR}/miner.h
  ${CMAKE_CURRENT_SOURCE_DIR}/net.h
  ${CMAKE_CURRENT_SOURCE_DIR}/netbase.h
  ${CMAKE_CURRENT_SOURCE_DIR}/noui.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pow.h
  ${CMAKE_CURRENT_SOURCE_DIR}/processblock.h
  ${CMAKE_CURRENT_SOURCE_DIR}/processheader.h
  ${CMAKE_CURRENT_SOURCE_DIR}/protocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pubkey.h
  ${CMAKE_CURRENT_SOURCE_DIR}/random.h
  ${CMAKE_CURRENT_SOURCE_DIR}/scheduler.h
  ${CMAKE_CURRENT_SOURCE_DIR}/sync.h
  ${CMAKE_CURRENT_SOURCE_DIR}/timedata.h
  ${CMAKE_CURRENT_SOURCE_DIR}/torcontrol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/txmempool.h
  ${CMAKE_CURRENT_SOURCE_DIR}/uint256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/util.h
  ${CMAKE_CURRENT_SOURCE_DIR}/fs.h
  ${CMAKE_CURRENT_SOURCE_DIR}/args.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilmoneystr.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utilstrencodings.h
  ${CMAKE_CURRENT_SOURCE_DIR}/util/utiltime.h
  ${CMAKE_CURRENT_SOURCE_DIR}/validationinterface.h
  ${CMAKE_CURRENT_SOURCE_DIR}/versionbits.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/crypter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/db.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/wallet_ismine.h
  ${CMAKE_CURRENT_SOURCE_DIR}/wallet/walletdb.h
  ${CMAKE_CURRENT_SOURCE_DIR}/support/cleanse.h
  ${CMAKE_CURRENT_SOURCE_DIR}/support/pagelocker.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/bitcoinconsensus.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/interpreter.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/script_error.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sigcache.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/sign.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/standard.h
  ${CMAKE_CURRENT_SOURCE_DIR}/chain/block.h
  ${CMAKE_CURRENT_SOURCE_DIR}/tx/tx.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/fees.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/policy.h
  ${CMAKE_CURRENT_SOURCE_DIR}/policy/rbf.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/hmac_sha512.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/ripemd160.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha1.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha256.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha512.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/chacha20.h
  ${CMAKE_CURRENT_SOURCE_DIR}/consensus/merkle.h
  ${CMAKE_CURRENT_SOURCE_DIR}/init.h
  ${CMAKE_CURRENT_SOURCE_DIR}/crypto/scrypt.h
  ${CMAKE_CURRENT_SOURCE_DIR}/kernel.h
  ${CMAKE_CURRENT_SOURCE_DIR}/httprpc.h
  ${CMAKE_CURRENT_SOURCE_DIR}/httpserver.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcclient.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcprotocol.h
  ${CMAKE_CURRENT_SOURCE_DIR}/rpc/rpcserver.h
  ${CMAKE_CURRENT_SOURCE_DIR}/univalue/univalue.h
  ${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2.h
  ${CMAKE_CURRENT_SOURCE_DIR}/script/stakescript.h
  ${CMAKE_CURRENT_SOURCE_DIR}/signals.h
  ${CMAKE_CURRENT_SOURCE_DIR}/processtx.h
  ${CMAKE_CURRENT_SOURCE_DIR}/verifydb.h )

#
# Boost Dependencies
# 
set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)  
set(Boost_USE_STATIC_RUNTIME OFF)
find_package( Boost REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options )
include_directories( ${Boost_INCLUDE_DIR} )
# ucm_add_linker_flags(SHARED ${Boost_LIBRARY_DIRS})

# 
# OpenSSL Dependencies
# 
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
# ucm_add_linker_flags(SHARED ${OPENSSL_LIBRARIES})

#
# LibEvent Dependencies
# 
find_package(LibEvent REQUIRED)
include_directories(${LIBEVENT_INCLUDE_DIR})
# ucm_add_linker_flags(SHARED ${LIBEVENT_LIB})

#
# BerkeleyDB
# 
set(DB_VERSION 47)
find_package(BerkeleyDB REQUIRED)
include_directories(${BERKELEY_DB_INCLUDE_DIR})
# ucm_add_linker_flags(SHARED ${BERKELEY_DB_LIBRARIES})

# 
# LevelDB
# 
add_subdirectory(leveldb)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/leveldb/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/helpers
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/helpers/memenv)



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
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include)
ExternalProject_Add(SECP_EXTERNAL
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1
  CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/configure
  BUILD_COMMAND ${MAKE}
  INSTALL_COMMAND "")

ExternalProject_Get_Property(SECP_EXTERNAL INSTALL_DIR)
set(SECKP_DIR ${INSTALL_DIR})
add_dependencies(eccoin SECP_EXTERNAL)

target_link_libraries(eccoin
                      ${SECKP_DIR}/src/SECP_EXTERNAL-build
                      ${Boost_LIBRARIES}
                      ${OPENSSL_LIBRARIES}
                      ${LIBEVENT_LIB}
                      ${BERKELEY_DB_LIBRARIES}
                      event_pthreads
                      secp256k1
                      leveldb
                      
)

# add_library(SECP_LIB STATIC IMPORTED GLOBAL)
# set_property(TARGET SECP_LIB PROPERTY IMPORTED_LOCATION ${SECKP_DIR}/src/secp256k1-build/libsecp256k1.la)
# add_dependencies(SECP_LIB secp256k1)


add_executable(eccoind ${DIR_HEADERS} ${DIR_SOURCES})
target_link_libraries(eccoind eccoin)

# include_directories(${CMAKE_CURRENT_SOURCE_DIR})
# add_executable(eccoind ${DIR_HEADERS} ${DIR_SOURCES})
# target_link_libraries(eccoin
#                       leveldb
#                       -L${SECKP_DIR}/src/secp256k1-build
#                       ${Boost_LIBRARY_DIRS}
#                       ${OPENSSL_LIBRARIES}
#                       ${LIBEVENT_LIB}
#                       ${BERKELEY_DB_LIBRARIES}
# )

# ucm_print_flags()