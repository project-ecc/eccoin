# ECC Build System
# 
# This CMakeLists.txt is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

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

#
# Boost Dependencies
# 
set( Boost_USE_STATIC_LIBS        OFF )
set( Boost_USE_MULTITHREADED      ON )
set( Boost_USE_STATIC_RUNTIME     OFF )
set( BOOST_ALL_DYN_LINK           ON ) # force dynamic linking for all libraries
find_package( Boost REQUIRED )
include_directories( ${Boost_INCLUDE_DIR} )
ucm_add_linker_flags(SHARED ${Boost_LIBRARY_DIRS})

# 
# OpenSSL Dependencies
# 
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
ucm_add_linker_flags(SHARED ${OPENSSL_LIBRARIES})

#
# LibEvent Dependencies
# 
find_package(LibEvent REQUIRED)
include_directories(${LIBEVENT_INCLUDE_DIR})
ucm_add_linker_flags(SHARED ${LIBEVENT_LIB})

#
# BerkeleyDB
# 
set(DB_VERSION 47)
find_package(BerkeleyDB REQUIRED)
include_directories(${BERKELEY_DB_INCLUDE_DIR})
ucm_add_linker_flags(SHARED ${BERKELEY_DB_LIBRARIES})

# 
# LevelDB
# 
add_subdirectory(leveldb)

ucm_print_flags()