DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/build $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/univalue

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBSECP256K1=secp256k1/libsecp256k1.la

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  libbitcoin_server.a
 
BITCOIN_INCLUDES += $(BDB_CPPFLAGS)
EXTRA_LIBRARIES += libbitcoin_wallet.a

if BUILD_BITCOIN_LIBS
lib_LTLIBRARIES = libbitcoinconsensus.la
LIBBITCOIN_CONSENSUS=libbitcoinconsensus.la
else
LIBBITCOIN_CONSENSUS=
endif

bin_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += eccoind
endif

.PHONY: FORCE check-symbols check-security
# bitcoin core #
BITCOIN_CORE_H = \
  addrman.h \
  amount.h \
  args.h \
  arith_uint256.h \
  base58.h \
  bloom.h \
  chain/chain.h \
  chain/chainman.h \
  chain/blockindex.h \
  chain/checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coincontrol.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  core_io.h \
  core_memusage.h \
  crypto/hash.h \
  dbwrapper.h \
  httprpc.h \
  httpserver.h \
  init.h \
  kernel.h \
  key.h \
  keystore.h \
  limitedmap.h \
  main.h \
  messages.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  netbase.h \
  networks/netman.h \
  networks/network.h \
  networks/networktemplate.h \
  noui.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  prevector.h \
  chain/block.h \
  tx/tx.h \
  pbkdf2.h \
  processblock.h \
  processheader.h \
  processtx.h \
  protocol.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpc/rpcclient.h \
  rpc/rpcprotocol.h \
  rpc/rpcserver.h \
  scheduler.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/stakescript.h \
  script/standard.h \
  crypto/scrypt.h \
  serialize.h \
  signals.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/pagelocker.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  uint256.h \
  undo.h \
  univalue/univalue.h \
  univalue/univalue_escapes.h \
  util/util.h \
  util/utilmoneystr.h \
  util/utilstrencodings.h \
  util/utiltime.h \
  validationinterface.h \
  verifydb.h \
  version.h \
  versionbits.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h 

build/build.h: FORCE
	@$(MKDIR_P) $(builddir)/build
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/build/build.h \
	  $(abs_top_srcdir)
libbitcoin_util_a-clientversion.$(OBJEXT): build/build.h

# server: shared between bitcoin 
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  addrman.cpp \
  bloom.cpp \
  chain/chain.cpp \
  chain/checkpoints.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  kernel.cpp \
  main.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  rest.cpp \
  rpc/rpcblockchain.cpp \
  rpc/rpcmining.cpp \
  rpc/rpcmisc.cpp \
  rpc/rpcnet.cpp \
  rpc/rpcrawtransaction.cpp \
  rpc/rpcserver.cpp \
  script/sigcache.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  amount.cpp \
  arith_uint256.cpp \
  base58.cpp \
  chain/chainman.cpp \
  coins.cpp \
  compressor.cpp \
  consensus/merkle.cpp \
  core_read.cpp \
  core_write.cpp \
  crypto/hash.cpp \
  key.cpp \
  keystore.cpp \
  netbase.cpp \
  chain/block.cpp \
  chain/blockindex.cpp \
  processblock.cpp \
  processheader.cpp \
  processtx.cpp \
  tx/tx.cpp \
  protocol.cpp \
  pubkey.cpp \
  scheduler.cpp \
  pbkdf2.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sign.cpp \
  script/standard.cpp \
  script/stakescript.cpp \
  args.cpp \
  support/pagelocker.cpp \
  chain/chainman.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  networks/netman.cpp \
  messages.cpp \
  random.cpp \
  rpc/rpcprotocol.cpp \
  support/cleanse.cpp \
  sync.cpp \
  uint256.cpp \
  univalue/univalue.cpp \
  univalue/univalue_read.cpp \
  univalue/univalue_write.cpp \
  util/util.cpp \
  util/utilmoneystr.cpp \
  util/utilstrencodings.cpp \
  util/utiltime.cpp \
  verifydb.cpp \
  signals.cpp \
  crypto/chacha20.cpp \
  crypto/chacha20.h \
  crypto/common.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/scrypt.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  rpc/rpcdump.cpp \
  rpc/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  policy/rbf.cpp \
  rpc/rpcclient.cpp \
  $(BITCOIN_CORE_H)

if GLIBC_BACK_COMPAT
libbitcoin_server_a_SOURCES += compat/glibc_compat.cpp
endif

# bitcoin binary #
eccoind_SOURCES = eccoind.cpp
eccoind_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES)
eccoind_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
eccoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

eccoind_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

eccoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS)

# bitcoinconsensus library #
if BUILD_BITCOIN_LIBS
include_HEADERS = script/bitcoinconsensus.h
libbitcoinconsensus_la_SOURCES = \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  crypto/hash.cpp \
  pubkey.cpp \
  script/bitcoinconsensus.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  uint256.cpp \
  util/utilstrencodings.cpp

if GLIBC_BACK_COMPAT
  libbitcoinconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libbitcoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libbitcoinconsensus_la_LIBADD = $(LIBSECP256K1) $(eccoind_LDADD) -lcrypto
libbitcoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/build -I$(srcdir)/secp256k1/include -DBUILD_BITCOIN_INTERNAL $(BITCOIN_INCLUDES)
libbitcoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif
#

CLEANFILES = leveldb/libleveldb.a leveldb/libmemenv.a
CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno

DISTCLEANFILES = build/build.h

EXTRA_DIST = leveldb

clean-local:
	-$(MAKE) -C leveldb clean
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(abspath $(<D) $<)

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif
