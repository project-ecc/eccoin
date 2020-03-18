// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"

#include "args.h"
#include "arith_uint256.h"
#include "blockstorage/blockstorage.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "checkqueue.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "crypto/hash.h"
#include "init.h"
#include "kernel.h"
#include "merkleblock.h"
#include "net/addrman.h"
#include "net/messages.h"
#include "net/net.h"
#include "networks/netman.h"
#include "networks/networktemplate.h"
#include "policy/policy.h"
#include "pow.h"
#include "processblock.h"
#include "processheader.h"
#include "random.h"
#include "script/script.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "txdb.h"
#include "txmempool.h"

#include "undo.h"
#include "util/util.h"
#include "util/utilmoneystr.h"
#include "util/utilstrencodings.h"
#include "validationinterface.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/foreach.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>

#include <random>
#include <random>
#include <sstream>


std::atomic<int64_t> nTimeBestReceived(0);


CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
unsigned int nBytesPerSigOp = DEFAULT_BYTES_PER_SIGOP;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;

/** Fees smaller than this (in satoshi) are considered zero fee (for relaying, mining and transaction creation) */
CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);

CTxMemPool mempool(::minRelayTxFee);

std::map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(cs_orphans);
std::map<uint256, std::set<uint256> > mapOrphanTransactionsByPrev GUARDED_BY(cs_orphans);


/**
 * Returns true if there are nRequired or more blocks of minVersion or above
 * in the last Consensus::Params::nMajorityWindow blocks, starting at pstart and going backwards.
 */
bool IsSuperMajority(int minVersion,
    const CBlockIndex *pstart,
    unsigned nRequired,
    const Consensus::Params &consensusParams);

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "ECC Signed Message:\n";


CBlockIndex *pindexBestInvalid;

/** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
 * Pruned nodes may have entries where B is missing data.
 */
std::multimap<CBlockIndex *, CBlockIndex *> mapBlocksUnlinked;

extern CCriticalSection cs_nBlockSequenceId;
extern CCriticalSection cs_LastBlockFile;
std::vector<CBlockFileInfo> vinfoBlockFile;
int nLastBlockFile = 0;

/** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
uint32_t nBlockSequenceId = 1;

/**
 * Sources of received blocks, saved to be able to send them reject
 * messages or ban them when processing happens afterwards. Protected by
 * cs_main.
 */

/** Number of preferable block download peers. */
std::atomic<int> nPreferredDownload{0};

/** Dirty block index entries. */
std::set<CBlockIndex *> setDirtyBlockIndex;

/** Dirty block file entries. */
std::set<int> setDirtyFileInfo;

/** Number of peers from which we're downloading blocks. */
int nPeersWithValidatedDownloads = 0;

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

int GetHeight() { return pnetMan->getChainActive()->chainActive.Height(); }
//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = pnetMan->getChainActive()->chainActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST) ?
                                   pnetMan->getChainActive()->chainActive.Tip()->GetMedianTimePast() :
                                   GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool TestLockPointValidity(const LockPoints *lp)
{
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock)
    {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
        if (!pnetMan->getChainActive()->chainActive.Contains(lp->maxInputBlock))
        {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints *lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs_txmempool);

    CBlockIndex *tip = pnetMan->getChainActive()->chainActive.Tip();
    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints)
    {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else
    {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++)
        {
            const CTxIn &txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin))
            {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT)
            {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            }
            else
            {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp)
        {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (auto height : prevheights)
            {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight + 1)
                {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

void LimitMempoolSize(CTxMemPool &pool, size_t limit, unsigned long age)
{
    std::vector<COutPoint> vCoinsToUncache;
    int expired = pool.Expire(GetTime() - age, vCoinsToUncache);
    for (const COutPoint &txin : vCoinsToUncache)
    {
        pcoinsTip->Uncache(txin);
    }
    if (expired != 0)
        LogPrint("mempool", "Expired %i transactions from the memory pool\n", expired);

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint &removed : vNoSpendsRemaining)
    {
        pcoinsTip->Uncache(removed);
    }
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s%s (code %i)", state.GetRejectReason(),
        state.GetDebugMessage().empty() ? "" : ", " + state.GetDebugMessage(), state.GetRejectCode());
}

bool AcceptToMemoryPoolWorker(CTxMemPool &pool,
    CValidationState &state,
    const CTransactionRef &ptx,
    bool fLimitFree,
    bool *pfMissingInputs,
    bool fOverrideMempoolLimit,
    bool fRejectAbsurdFee,
    std::vector<COutPoint> &vCoinsToUncache)
{
    const CTransaction &tx = *ptx;
    AssertLockHeld(cs_main);

    if (!CheckTransaction(tx, state))
    {
        return false;
    }

    // Coinbase/Coinstake is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase() || tx.IsCoinStake())
    {
        return state.DoS(100, false, REJECT_INVALID, "coinbase");
    }

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (fRequireStandard && !IsStandardTx(tx, reason))
    {
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);
    }

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
    {
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");
    }

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    if (pool.exists(hash))
    {
        return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    {
        READLOCK(pool.cs_txmempool); // protect pool.mapNextTx
        for (auto const &txin : tx.vin)
        {
            auto itConflicting = pool.mapNextTx.find(txin.prevout);
            if (itConflicting != pool.mapNextTx.end())
            {
                // Disable replacement feature for good
                return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");
            }
        }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        CAmount nValueIn = 0;
        LockPoints lp;
        {
            WRITELOCK(pool.cs_txmempool);
            CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
            view.SetBackend(viewMemPool);

            // do all inputs exist?
            if (pfMissingInputs)
            {
                *pfMissingInputs = false;
                BOOST_FOREACH (const CTxIn txin, tx.vin)
                {
                    // At this point we begin to collect coins that are potential candidates for uncaching because as
                    // soon as we make the call below to view.HaveCoin() any missing coins will be pulled into cache.
                    // Therefore, any coin in this transaction that is not already in cache will be tracked here such
                    // that if this transaction fails to enter the memory pool, we will then uncache those coins that
                    // were not already present, unless the transaction is an orphan.
                    //
                    // We still want to keep orphantx coins in the event the orphantx is finally accepted into the
                    // mempool or shows up in a block that is mined.  Therefore if pfMissingInputs returns true then
                    // any coins in vCoinsToUncache will NOT be uncached.
                    if (!pcoinsTip->HaveCoinInCache(txin.prevout))
                    {
                        vCoinsToUncache.push_back(txin.prevout);
                    }

                    if (!view.HaveCoin(txin.prevout))
                    {
                        // fMissingInputs and not state.IsInvalid() is used to detect this condition, don't set
                        // state.Invalid()
                        *pfMissingInputs = true;
                    }
                }
                if (*pfMissingInputs == true)
                    return false;
            }

            // Bring the best block into scope
            view.GetBestBlock();

            nValueIn = view.GetValueIn(tx);

            // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
            view.SetBackend(dummy);

            // Only accept BIP68 sequence locked transactions that can be mined in the next
            // block; we don't want our mempool filled up with transactions that can't
            // be mined yet.
            // Must keep pool.cs_txmempool for this unless we change CheckSequenceLocks to take a
            // CoinsViewCache instead of create its own
            if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            {
                return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");
            }
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
        {
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");
        }

        unsigned int nSigOps = GetLegacySigOpCount(tx);
        nSigOps += GetP2SHSigOpCount(tx, view);

        CAmount nValueOut = tx.GetValueOut();
        CAmount nFees = nValueIn - nValueOut;
        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        double nPriorityDummy = 0;
        pool.ApplyDeltas(hash, nPriorityDummy, nModifiedFees);

        CAmount inChainInputValue;
        double dPriority = view.GetPriority(tx, pnetMan->getChainActive()->chainActive.Height(), inChainInputValue);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        for (auto const &txin : tx.vin)
        {
            CoinAccessor coin(view, txin.prevout);
            if (coin->IsCoinBase())
            {
                fSpendsCoinbase = true;
                break;
            }
        }

        CTxMemPoolEntry entry(ptx, nFees, GetTime(), dPriority, pnetMan->getChainActive()->chainActive.Height(),
            pool.HasNoInputsOf(tx), inChainInputValue, fSpendsCoinbase, nSigOps, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if ((nSigOps > MAX_STANDARD_TX_SIGOPS) || (nBytesPerSigOp && nSigOps > nSize / nBytesPerSigOp))
        {
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false, strprintf("%d", nSigOps));
        }

        CAmount mempoolRejectFee =
            pool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
        if (mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee)
        {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false,
                strprintf("%d < %d", nFees, mempoolRejectFee));
        }

        // Continuously rate-limit free (really, very-low-fee) transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        static const double maxFeeCutoff =
            boost::lexical_cast<double>(gArgs.GetArg("-maxlimitertxfee", DEFAULT_MAXLIMITERTXFEE));
        // starting value for feeCutoff in satoshi per byte
        static const double initFeeCutoff =
            boost::lexical_cast<double>(gArgs.GetArg("-minlimitertxfee", DEFAULT_MINLIMITERTXFEE));
        static const int nLimitFreeRelay = gArgs.GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY);

        // get current memory pool size
        uint64_t poolBytes = pool.GetTotalTxSize();

        // Calculate feeCutoff in satoshis per byte:
        //   When the feeCutoff is larger than the satoshiPerByte of the
        //   current transaction then spam blocking will be in effect. However
        //   Some free transactions will still get through based on -limitfreerelay
        static double feeCutoff = initFeeCutoff;
        static double nFreeLimit = nLimitFreeRelay;
        static int64_t nLastTime = GetTime();

        int64_t nNow = GetTime();

        // When the mempool starts falling use an exponentially decaying ~24 hour window:
        // nFreeLimit = nFreeLimit + ((double)(DEFAULT_LIMIT_FREE_RELAY - nFreeLimit) / pow(1.0 - 1.0/86400,
        // (double)(nNow - nLastTime)));
        nFreeLimit /= std::pow(1.0 - 1.0 / 86400, (double)(nNow - nLastTime));

        // When the mempool starts falling use an exponentially decaying ~24 hour window:
        feeCutoff *= std::pow(1.0 - 1.0 / 86400, (double)(nNow - nLastTime));

        uint64_t nLargestBlockSeen = MAX_BLOCK_SIZE;
        if (poolBytes < nLargestBlockSeen)
        {
            feeCutoff = std::max(feeCutoff, initFeeCutoff);
            nFreeLimit = std::min(nFreeLimit, (double)nLimitFreeRelay);
        }
        else if (poolBytes < (nLargestBlockSeen * MAX_BLOCK_SIZE_MULTIPLIER))
        {
            // Gradually choke off what is considered a free transaction
            feeCutoff =
                std::max(feeCutoff, initFeeCutoff + ((maxFeeCutoff - initFeeCutoff) * (poolBytes - nLargestBlockSeen) /
                                                        (nLargestBlockSeen * (MAX_BLOCK_SIZE_MULTIPLIER - 1))));

            // Gradually choke off the nFreeLimit as well but leave at least DEFAULT_MIN_LIMITFREERELAY
            // So that some free transactions can still get through
            nFreeLimit = std::min(
                nFreeLimit, ((double)nLimitFreeRelay - ((double)(nLimitFreeRelay - DEFAULT_MIN_LIMITFREERELAY) *
                                                           (double)(poolBytes - nLargestBlockSeen) /
                                                           (nLargestBlockSeen * (MAX_BLOCK_SIZE_MULTIPLIER - 1)))));
            if (nFreeLimit < DEFAULT_MIN_LIMITFREERELAY)
                nFreeLimit = DEFAULT_MIN_LIMITFREERELAY;
        }
        else
        {
            feeCutoff = maxFeeCutoff;
            nFreeLimit = DEFAULT_MIN_LIMITFREERELAY;
        }
        minRelayTxFee = CFeeRate(feeCutoff * 1000);
        LogPrint("MEMPOOL",
            "MempoolBytes:%d  LimitFreeRelay:%.5g  FeeCutOff:%.4g  FeesSatoshiPerByte:%.4g  TxBytes:%d  TxFees:%d\n",
            poolBytes, nFreeLimit, ((double)::minRelayTxFee.GetFee(nSize)) / nSize, ((double)nFees) / nSize, nSize,
            nFees);
        if (fLimitFree && nModifiedFees < ::minRelayTxFee.GetFee(nSize))
        {
            static double dFreeCount;

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0 / 600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= gArgs.GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY) * 10 * 1000)
            {
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "rate limited free transaction");
            }
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount + nSize);
            dFreeCount += nSize;
        }

        if (fRejectAbsurdFee && tx.nVersion == 1 && nFees > maxTxFee)
        {
            LogPrintf("Absurdly-high-fee of %d for tx with version of 1 \n", nFees);
            return state.Invalid(false, REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, ::minRelayTxFee.GetFee(nSize) * 10000));
        }

        if (fRejectAbsurdFee && tx.nVersion == 2 && nFees > 100000000)
        {
            LogPrintf("Absurdly-high-fee of %d for tx with version of 2 \n", nFees);
            return state.Invalid(false, REJECT_HIGHFEE, "absurdly-high-fee", strprintf("%d > %d", nFees, 100000000));
        }


        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT) * 1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT) * 1000;
        std::string errString;

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!CheckInputs(tx, state, view, true, STANDARD_SCRIPT_VERIFY_FLAGS, true, nullptr))
        {
            LogPrint("MEMPOOL", "CheckInputs failed for tx: %s\n", tx.GetHash().ToString().c_str());
            return false;
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.

        if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, nullptr))
        {
            return error(
                "%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s, %s",
                __func__, hash.ToString(), FormatStateMessage(state));
        }
        {
            WRITELOCK(pool.cs_txmempool);
            if (!pool._CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize,
                    nLimitDescendants, nLimitDescendantSize, errString))
            {
                return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
            }
        }

        {
            WRITELOCK(pool.cs_txmempool);
            // Store transaction in memory
            pool.addUnchecked(hash, entry, setAncestors, !pnetMan->getChainActive()->IsInitialBlockDownload());
        }

        // trim mempool and check if tx was trimmed
        if (!fOverrideMempoolLimit)
        {
            LimitMempoolSize(pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
                gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
            {
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
            }
        }

        if (!fRejectAbsurdFee)
        {
            SyncWithWallets(ptx, nullptr, -1);
        }
    }

    return true;
}

bool AcceptToMemoryPool(CTxMemPool &pool,
    CValidationState &state,
    const CTransactionRef &tx,
    bool fLimitFree,
    bool *pfMissingInputs,
    bool fOverrideMempoolLimit,
    bool fRejectAbsurdFee)
{
    std::vector<COutPoint> vCoinsToUncache;
    LOCK(cs_main);
    bool res = AcceptToMemoryPoolWorker(
        pool, state, tx, fLimitFree, pfMissingInputs, fOverrideMempoolLimit, fRejectAbsurdFee, vCoinsToUncache);
    if (pfMissingInputs && !res && !*pfMissingInputs)
    {
        for (const COutPoint &remove : vCoinsToUncache)
        {
            pcoinsTip->Uncache(remove);
        }
    }
    return res;
}

//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool CScriptCheck::operator()()
{
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    CachingTransactionSignatureChecker checker(ptxTo, nIn, cacheStore);
    if (!VerifyScript(scriptSig, scriptPubKey, nFlags, checker, &error))
    {
        return false;
    }
    return true;
}

bool CheckInputs(const CTransaction &tx,
    CValidationState &state,
    const CCoinsViewCache &inputs,
    bool fScriptChecks,
    unsigned int flags,
    bool cacheStore,
    std::vector<CScriptCheck> *pvChecks)
{
    if (!tx.IsCoinBase())
    {
        if (!Consensus::CheckTxInputs(tx, state, inputs))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last block chain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (fScriptChecks)
        {
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                const COutPoint &prevout = tx.vin[i].prevout;
                CoinAccessor coin(inputs, prevout);
                assert(!coin->IsSpent());

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.
                const CScript &scriptPubKey = coin->out.scriptPubKey;
                const CAmount amount = coin->out.nValue;

                // Verify signature
                CScriptCheck check(scriptPubKey, amount, tx, i, flags, cacheStore);
                if (pvChecks)
                {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                }
                else if (!check())
                {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS)
                    {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(
                            scriptPubKey, amount, tx, i, flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore);
                        if (check2())
                        {
                            return state.Invalid(
                                false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)",
                                                               ScriptErrorString(check.GetScriptError())));
                        }
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after a soft-fork
                    // super-majority vote has passed.
                    return state.DoS(100, false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)",
                                                                     ScriptErrorString(check.GetScriptError())));
                }
            }
        }
    }

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string &strMessage, const std::string &userMessage)
{
    strMiscWarning = strMessage;
    LogPrintf("*** %s\n", strMessage);
    LogPrintf("Error: A fatal internal error occurred, see debug.log for details\n");
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState &state, const std::string &strMessage, const std::string &userMessage)
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld)
    {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld)
    {
        if (fFinalize)
            TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool FlushStateToDisk(CValidationState &state, FlushStateMode mode)
{
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    int64_t nNow = GetTimeMicros();
    // Avoid writing/flushing immediately after startup.
    if (nLastWrite == 0)
    {
        nLastWrite = nNow;
    }
    if (nLastFlush == 0)
    {
        nLastFlush = nNow;
    }
    if (nLastSetChain == 0)
    {
        nLastSetChain = nNow;
    }
    size_t cacheSize = pcoinsTip->DynamicMemoryUsage();
    static int64_t nSizeAfterLastFlush = 0;
    // The cache is close to the limit. Try to flush and trim.
    bool fCacheCritical = ((mode == FLUSH_STATE_IF_NEEDED) && (cacheSize > nCoinCacheUsage * 0.995)) ||
                          (cacheSize - nSizeAfterLastFlush > (int64_t)nMaxCacheIncreaseSinceLastFlush);
    // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload
    // after a crash.
    bool fPeriodicWrite =
        mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
    // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
    bool fPeriodicFlush =
        mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
    // Combine all conditions that result in a full cache flush.
    bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheCritical || fPeriodicFlush;
    // Write blocks and block index to disk.
    if (fDoFullFlush || fPeriodicWrite)
    {
        // Depend on nMinDiskSpace to ensure we can write block index
        if (!CheckDiskSpace(0))
        {
            return state.Error("out of disk space");
        }
        FlushBlockFile();
        // Then update all block file information (which may refer to block and undo files).
        {
            std::vector<std::pair<int, const CBlockFileInfo *> > vFiles;
            vFiles.reserve(setDirtyFileInfo.size());
            for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end();)
            {
                vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                setDirtyFileInfo.erase(it++);
            }
            std::vector<const CBlockIndex *> vBlocks;
            vBlocks.reserve(setDirtyBlockIndex.size());
            for (std::set<CBlockIndex *>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end();)
            {
                vBlocks.push_back(*it);
                setDirtyBlockIndex.erase(it++);
            }
            if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks))
            {
                return AbortNode(state, "Files to write to block index database");
            }
        }
        nLastWrite = nNow;
    }
    // Flush best chain related state. This can only be done if the blocks / block index write was also done.
    if (fDoFullFlush)
    {
        // Typical Coin structures on disk are around 48 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
        {
            return state.Error("out of disk space");
        }
        // Flush the chainstate (which may refer to block index entries).
        if (!pcoinsTip->Flush())
        {
            return AbortNode(state, "Failed to write to coin database");
        }
        nLastFlush = nNow;
        // Trim, but never trim more than nMaxCacheIncreaseSinceLastFlush
        size_t nTrimSize = nCoinCacheUsage * .90;
        if (nCoinCacheUsage - nMaxCacheIncreaseSinceLastFlush > nTrimSize)
        {
            nTrimSize = nCoinCacheUsage - nMaxCacheIncreaseSinceLastFlush;
        }
        pcoinsTip->Trim(nTrimSize);
        nSizeAfterLastFlush = pcoinsTip->DynamicMemoryUsage();
    }
    if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) &&
                            nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000))
    {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().SetBestChain(pnetMan->getChainActive()->chainActive.GetLocator());
        nLastSetChain = nNow;
    }

    // As a safeguard, periodically check and correct any drift in the value of cachedCoinsUsage.  While a
    // correction should never be needed, resetting the value allows the node to continue operating, and only
    // an error is reported if the new and old values do not match.
    if (fPeriodicFlush)
    {
        pcoinsTip->ResetCachedCoinUsage();
    }
    return true;
}

void FlushStateToDisk()
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void PruneBlockIndexCandidates()
{
    AssertLockHeld(cs_main);
    if (setBlockIndexCandidates.empty())
        return; // nothing to prune

    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex *, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() &&
           setBlockIndexCandidates.value_comp()(*it, pnetMan->getChainActive()->chainActive.Tip()))
    {
        setBlockIndexCandidates.erase(it++);
    }
}


bool InvalidateBlock(CValidationState &state, const Consensus::Params &consensusParams, CBlockIndex *pindex)
{
    RECURSIVEWRITELOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);

    while (pnetMan->getChainActive()->chainActive.Contains(pindex))
    {
        CBlockIndex *pindexWalk = pnetMan->getChainActive()->chainActive.Tip();
        pindexWalk->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(pindexWalk);
        setBlockIndexCandidates.erase(pindexWalk);
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, consensusParams))
        {
            mempool.removeForReorg(pcoinsTip.get(), pnetMan->getChainActive()->chainActive.Tip()->nHeight + 1,
                STANDARD_LOCKTIME_VERIFY_FLAGS);
            return false;
        }
    }

    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
        gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);

    BlockMap::iterator it = pnetMan->getChainActive()->mapBlockIndex.begin();
    while (it != pnetMan->getChainActive()->mapBlockIndex.end())
    {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx &&
            !setBlockIndexCandidates.value_comp()(it->second, pnetMan->getChainActive()->chainActive.Tip()))
        {
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    mempool.removeForReorg(
        pcoinsTip.get(), pnetMan->getChainActive()->chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    return true;
}

bool ReconsiderBlock(CValidationState &state, CBlockIndex *pindex)
{
    int nHeight = pindex->nHeight;
    RECURSIVEWRITELOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
    // Remove the invalidity flag from this block
    if (!pindex->IsValid())
    {
        pindex->nStatus &= ~BLOCK_FAILED_MASK;
        setDirtyBlockIndex.insert(pindex);
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->nChainTx &&
            setBlockIndexCandidates.value_comp()(pnetMan->getChainActive()->chainActive.Tip(), pindex))
        {
            setBlockIndexCandidates.insert(pindex);
        }
        if (pindex == pindexBestInvalid)
        {
            // Reset invalid block marker if it was pointing to one of those.
            pindexBestInvalid = NULL;
        }
    }
    // Remove the invalidity flag from all descendants.
    BlockMap::iterator it = pnetMan->getChainActive()->mapBlockIndex.begin();
    while (it != pnetMan->getChainActive()->mapBlockIndex.end())
    {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex)
        {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx &&
                setBlockIndexCandidates.value_comp()(pnetMan->getChainActive()->chainActive.Tip(), it->second))
            {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid)
            {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = NULL;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != NULL)
    {
        if (pindex->nStatus & BLOCK_FAILED_MASK)
        {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(const CBlock &block,
    CValidationState &state,
    CBlockIndex *pindexNew,
    const CDiskBlockPos &pos)
{
    // for setBlockIndexCandidates
    AssertLockHeld(cs_main);
    // for nStatus and nSequenceId
    RECURSIVEWRITELOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == NULL || pindexNew->pprev->nChainTx)
    {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex *> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty())
        {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (pnetMan->getChainActive()->chainActive.Tip() == NULL ||
                !setBlockIndexCandidates.value_comp()(pindex, pnetMan->getChainActive()->chainActive.Tip()))
            {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
                range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second)
            {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    }
    else
    {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE))
        {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }

    return true;
}

bool FindBlockPos(CValidationState &state,
    CDiskBlockPos &pos,
    unsigned int nAddSize,
    unsigned int nHeight,
    uint64_t nTime,
    bool fKnown)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile)
    {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown)
    {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE)
        {
            nFile++;
            if (vinfoBlockFile.size() <= nFile)
            {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile)
    {
        if (!fKnown)
        {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown)
    {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks)
        {
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos))
            {
                FILE *file = OpenBlockFile(pos);
                if (file)
                {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE,
                        pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool CheckIndexAgainstCheckpoint(const CBlockIndex *pindexPrev,
    CValidationState &state,
    const CNetworkTemplate &chainparams,
    const uint256 &hash)
{
    if (*pindexPrev->phashBlock == chainparams.GetConsensus().hashGenesisBlock)
        return true;

    int nHeight = pindexPrev->nHeight + 1;
    // Don't accept any forks from the main chain prior to last checkpoint
    CBlockIndex *pcheckpoint = Checkpoints::GetLastCheckpoint(chainparams.Checkpoints());
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight));

    return true;
}

bool ContextualCheckBlock(const CBlock &block, CValidationState &state, CBlockIndex *const pindexPrev)
{
    const int nHeight = pindexPrev == NULL ? 0 : pindexPrev->nHeight + 1;
    const Consensus::Params &consensusParams = pnetMan->getActivePaymentNetwork()->GetConsensus();

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;

    int64_t nLockTimeCutoff;
    if (pindexPrev == nullptr)
        nLockTimeCutoff = block.GetBlockTime();
    else
        nLockTimeCutoff =
            (nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST) ? pindexPrev->GetMedianTimePast() : block.GetBlockTime();

    // Check that all transactions are finalized
    for (auto const &tx : block.vtx)
    {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff))
        {
            return state.DoS(
                10, error("%s: contains a non-final transaction", __func__), REJECT_INVALID, "bad-txns-nonfinal");
        }
    }

    // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
    // if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
    if (block.nVersion >= 2 &&
        IsSuperMajority(2, pindexPrev, consensusParams.nMajorityEnforceBlockUpgrade, consensusParams))
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin()))
        {
            return state.DoS(
                100, error("%s: block height mismatch in coinbase", __func__), REJECT_INVALID, "bad-cb-height");
        }
    }

    return true;
}


bool IsSuperMajority(int minVersion,
    const CBlockIndex *pstart,
    unsigned nRequired,
    const Consensus::Params &consensusParams)
{
    unsigned int nFound = 0;
    for (int i = 0; i < consensusParams.nMajorityWindow && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}


/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    uint64_t retval = 0;
    for (auto const &file : vinfoBlockFile)
    {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = fs::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", "Error: Disk space is low!");

    return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

std::string GetWarnings(const std::string &strFor)
{
    std::string strStatusBar;
    std::string strRPC;

    if (!CLIENT_VERSION_IS_RELEASE)
    {
        strStatusBar =
            "This is a pre-release test build - use at your own risk - do not use for mining or merchant applications";
    }

    if (gArgs.GetBoolArg("-testsafemode", DEFAULT_TESTSAFEMODE))
        strStatusBar = strRPC = "testsafemode enabled";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        strStatusBar = strMiscWarning;
    }

    if (fLargeWorkForkFound)
    {
        strStatusBar = strRPC =
            "Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.";
    }
    else if (fLargeWorkInvalidChainFound)
    {
        strStatusBar = strRPC = "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or "
                                "other nodes may need to upgrade.";
    }

    else if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    return "error";
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst,
        nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

// ppcoin: find last block index up to pindex
const CBlockIndex *GetLastBlockIndex(const CBlockIndex *pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}


unsigned int GetNextTargetRequired(const CBlockIndex *pindexLast, bool fProofOfStake)
{
    RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
    arith_uint256 bnTargetLimit = UintToArith256(pnetMan->getActivePaymentNetwork()->GetConsensus().powLimit);

    if (fProofOfStake)
    {
        // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
        bnTargetLimit = UintToArith256(pnetMan->getActivePaymentNetwork()->GetConsensus().posLimit);
    }

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex *pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);

    // Special rule for regtest: we never retarget.
    if (pnetMan->getActivePaymentNetwork()->GetConsensus().fPowNoRetargeting)
    {
        return pindexPrev->nBits;
    }

    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex *pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if (nActualSpacing < 0)
    {
        nActualSpacing = 1;
    }
    else if (nActualSpacing > pnetMan->getActivePaymentNetwork()->GetConsensus().nTargetTimespan)
    {
        nActualSpacing = pnetMan->getActivePaymentNetwork()->GetConsensus().nTargetTimespan;
    }

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexPrev->nBits);
    int64_t spacing;
    int64_t targetSpacing = pnetMan->getActivePaymentNetwork()->GetConsensus().nTargetSpacing;
    if (pindexPrev->GetMedianTimePast() > SERVICE_UPGRADE_HARDFORK)
    {
        targetSpacing = 150;
    }
    if (fProofOfStake)
    {
        spacing = targetSpacing;
    }
    else
    {
        spacing = std::min(
            (3 * (int64_t)targetSpacing), ((int64_t)targetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight)));
    }
    int64_t nTargetSpacing = spacing;
    int64_t nInterval = pnetMan->getActivePaymentNetwork()->GetConsensus().nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > bnTargetLimit)
    {
        bnNew = bnTargetLimit;
    }

    return bnNew.GetCompact();
}

int generateMTRandom(unsigned int s, int range)
{
    std::mt19937 gen(s);
    std::uniform_int_distribution<> dist(0, range);
    return dist(gen);
}

static const int64_t nMinSubsidy = 1 * COIN;
static const CAmount OLD_MAX_MONEY = 50000000000 * COIN;

// miner's coin base reward
int64_t GetProofOfWorkReward(int64_t nFees, const int nHeight, uint256 prevHash)
{
    if (pnetMan->getActivePaymentNetwork()->MineBlocksOnDemand())
    {
        // just return 50 coins for regtest and the fees
        return (50 * COIN) + nFees;
    }

    int64_t nSubsidy = 100000 * COIN;

    if (nHeight == 1)
    {
        nSubsidy = 0.0099 * OLD_MAX_MONEY;
        return nSubsidy + nFees;
    }
    else if (nHeight > 86400) // will be blocked all the pow after CUTOFF_HEIGHT
    {
        return nMinSubsidy + nFees;
    }

    std::string cseed_str = prevHash.ToString().substr(15, 7);
    const char *cseed = cseed_str.c_str();
    long seed = hex2long(cseed);
    nSubsidy += generateMTRandom(seed, 200000) * COIN;

    return nSubsidy + nFees;
}

int64_t ValueFromAmountAsInt(int64_t amount) { return amount / COIN; }
const int YEARLY_BLOCKCOUNT = 700800;
// miner's coin stake reward based on coin age spent (coin-days)
int64_t GetProofOfStakeReward(int64_t nCoinAge, int nHeight)
{
    int64_t nRewardCoinYear = 2.5 * MAX_MINT_PROOF_OF_STAKE;
    int64_t CMS = pnetMan->getChainActive()->chainActive.Tip()->nMoneySupply;
    if (CMS == MAX_MONEY)
    {
        // if we are already at max money supply limits (25 billion coins, we return 0 as no new coins are to be minted
        LogPrint("kernel", "GetProofOfStakeReward(): create=%i nCoinAge=%d\n", 0, nCoinAge);
        return 0;
    }
    if (nHeight > 500000 && nHeight < 1005000)
    {
        int64_t nextMoney = (ValueFromAmountAsInt(CMS) + nRewardCoinYear);
        if (nextMoney > MAX_MONEY)
        {
            int64_t difference = nextMoney - MAX_MONEY;
            nRewardCoinYear = nextMoney - difference;
        }
        if (nextMoney == MAX_MONEY)
        {
            nRewardCoinYear = 0;
        }
        int64_t nSubsidy = nCoinAge * nRewardCoinYear / 365;
        LogPrint("kernel", "GetProofOfStakeReward(): create=%s nCoinAge=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
        return nSubsidy;
    }

    nRewardCoinYear = 25 * CENT; // 25%
    int64_t nSubsidy = nCoinAge * nRewardCoinYear / 365;
    if (nHeight >= 1005000)
    {
        int64_t nextMoney = CMS + nSubsidy;
        // this conditional should only happen once
        if (nextMoney > MAX_MONEY)
        {
            // CMS + subsidy = nextMoney
            // nextMoney - MAX = difference and we should take this difference away from nSubsidy so nSubsidy stops at
            // max money and doesnt go over
            // credits go to cvargos for this fix
            int64_t difference = (nextMoney - MAX_MONEY);
            nSubsidy = nSubsidy - difference;
        }
    }
    LogPrint("kernel", "GetProofOfStakeReward(): create=%s nCoinAge=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
    return nSubsidy;
}
