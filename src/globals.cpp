// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "coins.h"
#include "fs.h"
#include "main.h"
#include "net/aodv.h"
#include "net/messages.h"
#include "net/packetmanager.h"
#include "deadlock-detection/threaddeadlock.h"
#include "txdb.h"
#include "wallet/wallet.h"

#ifdef DEBUG_LOCKORDER
LockData lockdata;
#endif

/**
 * Global state
 */

CCriticalSection cs_main;
CCriticalSection cs_orphans;
CCriticalSection cs_blockstorage;
CCriticalSection cs_mapRelay;

/**
 * Every received block is assigned a unique and increasing identifier, so we
 * know which one to give priority in case of a fork.
 */
CCriticalSection cs_nBlockSequenceId;
CCriticalSection cs_LastBlockFile;

CCriticalSection cs_nTimeOffset;
int64_t nTimeOffset = 0;

/** Global variable that points to the active CCoinsView */
std::unique_ptr<CCoinsViewCache> pcoinsTip GUARDED_BY(cs_main);

/** Global variable that points to the active block tree */
std::unique_ptr<CBlockTreeDB> pblocktree GUARDED_BY(cs_main);

/**
 * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
 * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
 * missing the data for the block.
 */
std::set<CBlockIndex *, CBlockIndexWorkComparator> setBlockIndexCandidates GUARDED_BY(cs_main);

CCriticalSection cs_mapLocalHost;
std::map<CNetAddr, LocalServiceInfo> mapLocalHost;
// Connection Slot mitigation - used to determine how many connection attempts over time
CCriticalSection cs_mapInboundConnectionTracker;
std::map<CNetAddr, ConnectionHistory> mapInboundConnectionTracker;

CCriticalSection cs_proxyInfos;
proxyType proxyInfo[NET_MAX];
proxyType nameProxy;

CCriticalSection cs_rpcWarmup;
bool fRPCRunning = false;
bool fRPCInWarmup = true;
std::string rpcWarmupStatus("RPC server started");

CCriticalSection cs_nWalletUnlockTime;
int64_t nWalletUnlockTime;

CCriticalSection csPathCached;
fs::path pathCached;
fs::path pathCachedNetSpecific;



CWallet *pwalletMain = nullptr;
CNetworkManager *pnetMan = nullptr;
std::unique_ptr<CConnman> g_connman;
std::unique_ptr<PeerLogicValidation> peerLogic;

CAodvRouteTable g_aodvtable;
CPacketManager g_packetman;
