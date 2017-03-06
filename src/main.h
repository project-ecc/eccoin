// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include "bignum.h"
#include "sync.h"
#include "net.h"
#include "script.h"
#include "scrypt_mine.h"
#include "global.h"
#include <list>

class CWallet;
class CWalletTx;

using namespace std;
using namespace boost;

int64_t getMinFee(int64_t nTime);
#ifndef MIN_TX_FEE
#define MIN_TX_FEE getMinFee
#endif
static const int64_t MAX_MONEY = 50000000000 * COIN;
static const int64_t COIN_YEAR_REWARD = 10 * CENT; // 10% per year
static const int64_t MAX_MINT_PROOF_OF_STAKE = 0.1 * COIN;
static const int MODIFIER_INTERVAL_SWITCH = 2500;
static const int64_t nMaxClockDrift = 2 * 60 * 60;        // two hours

inline bool MoneyRange(int64_t nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif

inline int64_t PastDrift(int64_t nTime)   { return nTime - 10 * 60; } // up to 10 minutes from the past
inline int64_t FutureDrift(int64_t nTime) { return nTime + 10 * 60; } // up to 10 minutes from the future


extern CMedianFilter<int> cPeerBlockCounts;
extern CScript COINBASE_FLAGS;
extern CCriticalSection cs_main;
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
extern unsigned int nNodeLifespan;

extern unsigned int nTransactionsUpdated;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockSize;
extern int64_t nLastCoinStakeSearchInterval;
extern const std::string strMessageMagic;
extern CCriticalSection cs_setpwalletRegistered;
extern std::set<CWallet*> setpwalletRegistered;
extern void *scrypt_buffer_alloc();
extern void scrypt_buffer_free(void *scratchpad);
extern void scrypt_hash_mine(const void* input, size_t inputlen, uint32_t *res, void *scratchpad);

// Settings
extern int64_t nTransactionFee;
extern int64_t nMinimumInputValue;
extern unsigned int nDerivationMethodIndex;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64_t nMinDiskSpace = 52428800;

class CReserveKey;
class CTxDB;
class CTxIndex;

void RegisterWallet(CWallet* pwalletIn);
void UnregisterWallet(CWallet* pwalletIn);
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
bool ProcessBlock(CNode* pfrom, CBlock* pblock);
bool CheckDiskSpace(uint64_t nAdditionalBytes=0);
FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE* AppendBlockFile(unsigned int& nFileRet);
bool LoadBlockIndex(bool fAllowNew=true);
void PrintBlockTree();
CBlockIndex* FindBlockByHeight(int nHeight);
bool LoadExternalBlockFile(FILE* fileIn);

bool CheckProofOfWork(uint256 hash, unsigned int nBits);
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake);
int64_t GetProofOfWorkReward(int64_t nFees, const int nHeight, uint256 prevHash);
int64_t GetProofOfStakeReward(int64_t nCoinAge, int nHeight);
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime);
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime);
int GetNumBlocksOfPeers();
bool IsInitialBlockDownload();
std::string GetWarnings(std::string strFor);
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);
uint256 WantedByOrphan(const CBlock* pblockOrphan);
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake);
void StakeMiner(CWallet *pwallet);
void ResendWalletTransactions(bool fForce = false);
void Inventory(const uint256& hash);
unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans);
bool AddOrphanTx(const CTransaction& tx);
void EraseOrphanTx(uint256 hash);
uint256 GetOrphanRoot(const CBlock* pblock);
bool GetTransaction(const uint256& hashTx, CWalletTx& wtx);
extern CWallet* pwalletMain;
bool GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);


#endif
