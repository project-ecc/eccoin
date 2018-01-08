# The name of our project is "ECCOIN". CMakeLists files in this project can
# refer to the root source directory of the project as ${ECCOIN_SOURCE_DIR} and
# to the root binary directory of the project as ${ECCOIN_BINARY_DIR}.
cmake_minimum_required(VERSION 2.8.11)
project (ECCOIN)

# CMake Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../cmake")

# Setup Sources
set(DIR_SOURCES
  txdb.cpp
  key.cpp
  addrman.cpp
  amount.cpp
  arith_uint256.cpp
  base58.cpp
  chain/blockindex.cpp
  bloom.cpp
  chain/chain.cpp
  chain/chainman.cpp
  networks/netman.cpp
  chain/checkpoints.cpp
  clientversion.cpp
  coins.cpp
  compressor.cpp
  core_read.cpp
  core_write.cpp
  dbwrapper.cpp
  crypto/hash.cpp
  keystore.cpp
  main.cpp
  merkleblock.cpp
  messages.cpp
  miner.cpp
  net.cpp
  netbase.cpp
  noui.cpp
  pow.cpp
  processblock.cpp
  processheader.cpp
  protocol.cpp
  pubkey.cpp
  random.cpp
  scheduler.cpp
  sync.cpp
  timedata.cpp
  torcontrol.cpp
  txmempool.cpp
  uint256.cpp
  util/util.cpp
  fs.cpp
  args.cpp
  util/utilmoneystr.cpp
  util/utilstrencodings.cpp
  util/utiltime.cpp
  validationinterface.cpp
  versionbits.cpp
  wallet/crypter.cpp
  wallet/db.cpp
  wallet/wallet.cpp
  wallet/wallet_ismine.cpp
  wallet/walletdb.cpp
  support/cleanse.cpp
  support/pagelocker.cpp
  script/bitcoinconsensus.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  script/sigcache.cpp
  script/sign.cpp
  script/standard.cpp
  chain/block.cpp
  tx/tx.cpp
  policy/fees.cpp
  policy/policy.cpp
  policy/rbf.cpp
  crypto/hmac_sha256.cpp
  crypto/hmac_sha512.cpp
  crypto/ripemd160.cpp
  crypto/sha1.cpp
  crypto/sha256.cpp
  crypto/sha512.cpp
  crypto/chacha20.cpp
  consensus/merkle.cpp
  compat/glibc_compat.cpp
  compat/glibc_sanity.cpp
  compat/glibcxx_sanity.cpp
  compat/strnlen.cpp
  init.cpp
  eccoind.cpp
  crypto/scrypt.cpp
  kernel.cpp
  httprpc.cpp
  httpserver.cpp
  rest.cpp
  rpc/rpcblockchain.cpp
  rpc/rpcclient.cpp
  rpc/rpcdump.cpp
  rpc/rpcmining.cpp
  rpc/rpcmisc.cpp
  rpc/rpcnet.cpp
  rpc/rpcprotocol.cpp
  rpc/rpcrawtransaction.cpp
  rpc/rpcserver.cpp
  rpc/rpcwallet.cpp
  univalue/univalue.cpp
  univalue/univalue_read.cpp
  univalue/univalue_write.cpp
  pbkdf2.cpp
  script/stakescript.cpp
  signals.cpp
  processtx.cpp
  verifydb.cpp )

set(DIR_HEADERS
  build.h
  txdb.h
  key.h
  addrman.h
  amount.h
  arith_uint256.h
  base58.h
  chain/blockindex.h
  bloom.h
  chain/chain.h
  chain/chainman.h
  networks/netman.h
  chain/checkpoints.h
  clientversion.h
  coins.h
  compressor.h
  dbwrapper.h
  crypto/hash.h
  keystore.h
  main.h
  merkleblock.h
  messages.h
  miner.h
  net.h
  netbase.h
  noui.h
  pow.h
  processblock.h
  processheader.h
  protocol.h
  pubkey.h
  random.h
  scheduler.h
  sync.h
  timedata.h
  torcontrol.h
  txmempool.h
  uint256.h
  util/util.h
  fs.h
  args.h
  util/utilmoneystr.h
  util/utilstrencodings.h
  util/utiltime.h
  validationinterface.h
  versionbits.h
  wallet/crypter.h
  wallet/db.h
  wallet/wallet.h
  wallet/wallet_ismine.h
  wallet/walletdb.h
  support/cleanse.h
  support/pagelocker.h
  script/bitcoinconsensus.h
  script/interpreter.h
  script/script.h
  script/script_error.h
  script/sigcache.h
  script/sign.h
  script/standard.h
  chain/block.h
  tx/tx.h
  policy/fees.h
  policy/policy.h
  policy/rbf.h
  crypto/hmac_sha256.h
  crypto/hmac_sha512.h
  crypto/ripemd160.h
  crypto/sha1.h
  crypto/sha256.h
  crypto/sha512.h
  crypto/chacha20.h
  consensus/merkle.h
  init.h
  crypto/scrypt.h
  kernel.h
  httprpc.h
  httpserver.h
  rpc/rpcclient.h
  rpc/rpcprotocol.h
  rpc/rpcserver.h
  univalue/univalue.h
  pbkdf2.h
  script/stakescript.h
  signals.h
  processtx.h
  verifydb.h )

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -O2 -Wall -Wextra -Wformat -Wvla -Wformat-security -Wthread-safety-analysis -Wno-unused-parameter -Wno-self-assign -Wno-unused-local-typedef -Wno-deprecated-register -Wno-implicit-fallthrough")
add_definitions(-DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS -I/usr/local/opt/berkeley-db@4/include -DMAC_OSX)

# Boost Dependencies
set(Boost_USE_STATIC_LIBS        ON) # only find static libs
find_package( Boost REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options )
if (${Boost_VERSION} EQUAL 104400 AND MSVC_VERSION EQUAL 1600)
  # Avoid error with boost 1.44 interprocess and MSVC10
  add_definitions(-DBOOST_NO_RVALUE_REFERENCES)
endif (${Boost_VERSION} EQUAL 104400 AND MSVC_VERSION EQUAL 1600)
include_directories(${Boost_INCLUDE_DIRS})

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(LibEvent REQUIRED)
include_directories(${LIBEVENT_INCLUDE_DIR})

# BerkeleyDB
set(DB_VERSION 47)
find_package(BerkeleyDB REQUIRED)
include_directories(${DB_INCLUDE_DIR})

# LevelDB
add_subdirectory(leveldb)

# Sources
include_directories(${Boost_INCLUDE_DIRS}
                    ${OPENSSL_INCLUDE_DIRS}
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/helpers
                    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb/helpers/memenv
                    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1
                    ${CMAKE_CURRENT_SOURCE_DIR}/secp256k1/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/univalue
)


add_library(eccoin ${DIR_HEADERS} ${DIR_SOURCES})
target_link_libraries(eccoin leveldb
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${Boost_LIBRARIES}
                      ${OPENSSL_LIBRARIES}
                      ${LIBEVENT_LIB}
)

add_executable(eccoind ${CMAKE_CURRENT_SOURCE_DIR}/eccoind.cpp)
target_link_libraries(eccoind eccoin leveldb
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${Boost_LIBRARIES}
                      ${OPENSSL_LIBRARIES}
                      ${LIBEVENT_LIB})



