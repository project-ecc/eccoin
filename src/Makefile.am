DIST_SUBDIRS = secp256k1 univalue rsm

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

BITCOIN_CONFIG_INCLUDES=-I$(builddir)/config
BITCOIN_INCLUDES=-I$(builddir) -I$(builddir)/build $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

BITCOIN_INCLUDES += -I$(srcdir)/secp256k1/include
BITCOIN_INCLUDES += -I$(srcdir)/univalue/include
BITCOIN_INCLUDES += -I$(srcdir)/rsm/include

LIBBITCOIN_SERVER=libbitcoin_server.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBUNIVALUE=univalue/libunivalue.la
LIBRSM=rsm/librsm.la

if ENABLE_ZMQ
LIBBITCOIN_ZMQ=libbitcoin_zmq.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

$(LIBRSM): $(wildcard rsm/lib/*) $(wildcard rsm/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)


# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
 $(LIBBITCOIN_SERVER) \
 $(LIBBITCOIN_ZMQ)

bin_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_BITCOIND
  bin_PROGRAMS += eccoind
endif

.PHONY: FORCE check-symbols check-security check-formatting
# bitcoin core #
BITCOIN_CORE_H = \
  amount.h \
  args.h \
  arith_uint256.h \
  base58.h \
  beta.h \
  blockgeneration/blockgeneration.h \
  blockgeneration/compare.h \
  blockgeneration/miner.h \
  blockgeneration/minter.h \
  blockstorage/blockstorage.h \
  bloom.h \
  chain/chain.h \
  chain/chainman.h \
  chain/blockindex.h \
  chain/checkpoints.h \
  chain/outpoint.h \
  chain/txout.h \
  chain/txin.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/ecc_endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tx_verify.h \
  consensus/validation.h \
  core_io.h \
  core_memusage.h \
  crypter.h \
  crypto/hash.h \
  dbwrapper.h \
  deadlock-detection/locklocation.h \
  deadlock-detection/lockorder.h \
  deadlock-detection/threaddeadlock.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  init.h \
  kernel.h \
  key.h \
  keypoolentry.h \
  keystore.h \
  limitedmap.h \
  main.h \
  memusage.h \
  merkleblock.h \
  net/addrdb.h \
  net/addrman.h \
  net/aodv.h \
  net/datapacket.h \
  net/messages.h \
  net/net.h \
  net/netaddress.h \
  net/netbase.h \
  net/nodestate.h \
  net/packetmanager.h \
  net/protocol.h \
  net/routingtag.h \
  net/tagdb.h \
  net/tagstore.h \
  networks/netman.h \
  networks/network.h \
  networks/networktemplate.h \
  policy/fees.h \
  policy/policy.h \
  pow.h \
  prevector.h \
  chain/block.h \
  chain/tx.h \
  crypto/pbkdf2.h \
  processblock.h \
  processheader.h \
  pubkey.h \
  random.h \
  reverselock.h \
  rpc/events.h \
  rpc/rpcclient.h \
  rpc/rpcprotocol.h \
  rpc/rpcserver.h \
  script/interpreter.h \
  script/script.h \
  script/script_error.h \
  script/sigcache.h \
  script/sign.h \
  script/stakescript.h \
  script/standard.h \
  crypto/scrypt.h \
  serialize.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/pagelocker.h \
  sync.h \
  threadgroup.h \
  threadsafety.h \
  timedata.h \
  tinyformat.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  uint256.h \
  undo.h \
  util/logger.h \
  util/util.h \
  util/utilmoneystr.h \
  util/utilstrencodings.h \
  util/utiltime.h \
  validationinterface.h \
  verifydb.h \
  version.h \
  wallet/cryptokeystore.h \
  wallet/db.h \
  wallet/wallet.h \
  wallet/wallet_ismine.h \
  wallet/walletdb.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h

build/build.h: FORCE
	@$(MKDIR_P) $(builddir)/build
	@$(top_srcdir)/share/genbuild.sh $(abs_top_builddir)/src/build/build.h \
	  $(abs_top_srcdir)
libbitcoin_server_a-clientversion.$(OBJEXT): build/build.h
#libbitcoin_util_a-clientversion.$(OBJEXT): build/build.h

# server: shared between bitcoin
libbitcoin_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libbitcoin_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIC_FLAGS) $(PIE_FLAGS)
libbitcoin_server_a_SOURCES = \
  globals.cpp \
  deadlock-detection/lockorder.cpp \
  deadlock-detection/threaddeadlock.cpp \
  sync.cpp \
  amount.cpp \
  args.cpp \
  arith_uint256.cpp \
  base58.cpp \
  beta.cpp \
  blockgeneration/blockgeneration.cpp \
  blockgeneration/miner.cpp \
  blockgeneration/minter.cpp \
  blockstorage/blockstorage.cpp \
  bloom.cpp \
  chain/block.cpp \
  chain/blockindex.cpp \
  chain/chain.cpp \
  chain/chainman.cpp \
  chain/checkpoints.cpp \
  chain/tx.cpp \
  clientversion.cpp \
  consensus/merkle.cpp \
  consensus/tx_verify.cpp \
  coins.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  crypter.cpp \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.cpp \
  crypto/chacha20.h \
  crypto/common.h \
  crypto/hash.cpp \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/pbkdf2.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/scrypt.cpp \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  dbwrapper.cpp \
  fs.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  kernel.cpp \
  key.cpp \
  keystore.cpp \
  main.cpp \
  merkleblock.cpp \
  net/addrdb.cpp \
  net/addrman.cpp \
  net/aodv.cpp \
  net/datapacket.cpp \
  net/messages.cpp \
  net/net.cpp \
  net/netaddress.cpp \
  net/netbase.cpp \
  net/tagdb.cpp \
  net/tagstore.cpp \
  net/nodestate.cpp \
  net/packetmanager.cpp \
  net/protocol.cpp \
  net/routingtag.cpp \
  networks/netman.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  pow.cpp \
  processblock.cpp \
  processheader.cpp \
  pubkey.cpp \
  random.cpp \
  rpc/rpcaodv.cpp \
  rpc/rpcblockchain.cpp \
  rpc/rpcclient.cpp \
  rpc/rpcdump.cpp \
  rpc/rpcmining.cpp \
  rpc/rpcmisc.cpp \
  rpc/rpcnet.cpp \
  rpc/rpcprotocol.cpp \
  rpc/rpcrawtransaction.cpp \
  rpc/rpcserver.cpp \
  rpc/rpcwallet.cpp \
  script/interpreter.cpp \
  script/script.cpp \
  script/script_error.cpp \
  script/sigcache.cpp \
  script/sign.cpp \
  script/standard.cpp \
  script/stakescript.cpp \
  support/cleanse.cpp \
  support/pagelocker.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  validationinterface.cpp \
  uint256.cpp \
  util/logger.cpp \
  util/util.cpp \
  util/utilmoneystr.cpp \
  util/utilstrencodings.cpp \
  util/utiltime.cpp \
  verifydb.cpp \
  wallet/cryptokeystore.cpp \
  wallet/db.cpp \
  wallet/wallet.cpp \
  wallet/wallet_ismine.cpp \
  wallet/walletdb.cpp \
  $(BITCOIN_CORE_H)

if ENABLE_ZMQ
libbitcoin_zmq_a_CPPFLAGS = $(BITCOIN_INCLUDES) $(ZMQ_CFLAGS)
libbitcoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libbitcoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp
endif

if GLIBC_BACK_COMPAT
libbitcoin_server_a_SOURCES += compat/glibc_compat.cpp
endif

# bitcoin binary #
eccoind_SOURCES = eccoind.cpp
eccoind_CPPFLAGS = $(AM_CPPFLAGS) $(BITCOIN_INCLUDES) $(EVENT_CFLAGS)
eccoind_CXXFLAGS = $(AM_CXXFLAGS) $(PIC_FLAGS) $(PIE_FLAGS)
eccoind_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS)

eccoind_LDADD = \
  $(LIBBITCOIN_SERVER) \
  $(LIBBITCOIN_ZMQ) \
  $(LIBBITCOIN_CRYPTO) \
  $(LIBUNIVALUE) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBRSM) \
  $(LIBSECP256K1)

eccoind_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

#
CLEANFILES = $(EXTRA_LIBRARIES)

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rsm/*.gcda rsm/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno

DISTCLEANFILES = build/build.h

EXTRA_DIST = leveldb $(CTAES_DIST)

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-$(MAKE) -C rsm clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h

.rc.o:
	@test -f $(WINDRES)
	$(AM_V_GEN) $(WINDRES) -DWINDRES_PREPROC -i $< -o $@

.mm.o:
	$(AM_V_CXX) $(OBJCXX) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	  $(CPPFLAGS) $(AM_CXXFLAGS) $(QT_INCLUDES) $(AM_CXXFLAGS) $(PIC_FLAGS) $(PIE_FLAGS) $(CXXFLAGS) -c -o $@ $<

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


check-formatting:
	@echo "Checking source formatting style..."
	(cd $(top_srcdir)/src; ../contrib/devtools/clang-format.py check clang-format-3.8 `cat ./.formatted-files`)

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
