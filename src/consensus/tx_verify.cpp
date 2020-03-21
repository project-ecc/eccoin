// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/chainman.h"
#include "consensus/tx_verify.h"
#include "base58.h"
#include "consensus/consensus.h"
#include "main.h"
#include "net/messages.h"
#include "script/standard.h"
#include "util/utilmoneystr.h"
#include "wallet/wallet.h"

bool CheckTransaction(const CTransaction &tx, CValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    int32_t out = 0;
    for (auto const &txout : tx.vout)
    {
        if (txout.nValue < 0)
        {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        }
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        out++;
    }

    // Check for duplicate inputs
    std::set<COutPoint> vInOutPoints;
    for (auto const &txin : tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (auto const &txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }
    if (tx.nVersion == 2)
    {
        if (tx.serviceReferenceHash.IsNull())
        {
            state.DoS(100, false, REJECT_INVALID, "bad-stx-ref-hash");
        }
    }
    return true;
}

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache &inputs)
{
    RECURSIVEREADLOCK(g_chainman.cs_mapBlockIndex);
    BlockMap::iterator i = g_chainman.mapBlockIndex.find(inputs.GetBestBlock());
    if (i != g_chainman.mapBlockIndex.end())
    {
        CBlockIndex *pindexPrev = i->second;
        if (pindexPrev)
            return pindexPrev->nHeight + 1;
        else
        {
            throw std::runtime_error("GetSpendHeight(): mapBlockIndex contains null block");
        }
    }
    throw std::runtime_error("GetSpendHeight(): best block does not exist");
}

bool Consensus::CheckTxInputs(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &inputs)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(false, 0, "", "Inputs unavailable");

    CAmount nValueIn = 0;
    CAmount nFees = 0;
    int nSpendHeight = -1;
    for (uint64_t i = 0; i < tx.vin.size(); i++)
    {
        const COutPoint &prevout = tx.vin[i].prevout;
        Coin coin;
        inputs.GetCoin(prevout, coin); // Make a copy so I don't hold the utxo lock
        assert(!coin.IsSpent());

        // If prev is coinbase or coinstake, check that it's matured
        if (coin.IsCoinBase() || tx.IsCoinStake())
        {
            if (nSpendHeight == -1)
                nSpendHeight = GetSpendHeight(inputs);
            if (nSpendHeight - coin.nHeight < COINBASE_MATURITY &&
                g_chainman.chainActive.Tip()->nHeight > 1600000)
                return state.Invalid(false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                    strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }

    if (!tx.IsCoinStake())
    {
        if (nValueIn < tx.GetValueOut())
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(tx.GetValueOut())));
        // Tally transaction fees
        CAmount nTxFee = nValueIn - tx.GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");
    }
    else
    {
        // ppcoin: coin stake tx earns reward instead of paying fee
        uint64_t nCoinAge;
        if (!tx.GetCoinAge(nCoinAge))
        {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-cant-get-coin-age", false,
                strprintf("ConnectInputs() : %s unable to get coin age for coinstake",
                                 tx.GetHash().ToString().substr(0, 10).c_str()));
        }

        int64_t nStakeReward = tx.GetValueOut() - nValueIn;
        if (nStakeReward >
            GetProofOfStakeReward(tx.GetCoinAge(nCoinAge, true), nSpendHeight) + DEFAULT_TRANSACTION_MINFEE)
        {
            LogPrint("kernel", "nStakeReward = %d , CoinAge = %d \n", nStakeReward, nCoinAge);
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-stake-reward-too-high", false,
                strprintf("ConnectInputs() : %s stake reward exceeded", tx.GetHash().ToString().substr(0, 10).c_str()));
        }
    }
    return true;
}

unsigned int GetLegacySigOpCount(const CTransaction &tx)
{
    unsigned int nSigOps = 0;
    for (auto const &txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (auto const &txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction &tx, const CCoinsViewCache &inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CoinAccessor coin(inputs, tx.vin[i].prevout);
        assert(!coin->IsSpent());
        if (coin && coin->out.scriptPubKey.IsPayToScriptHash())
            nSigOps += coin->out.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
    {
        return true;
    }
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
    {
        return true;
    }
    for (auto const &txin : tx.vin)
    {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
        {
            return false;
        }
    }
    return true;
}

/**
 * Calculates the block height and previous block's median time past at
 * which the transaction will be considered final in the context of BIP 68.
 * Also removes from the vector of input heights any entries which did not
 * correspond to sequence locked inputs as they do not affect the calculation.
 */
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx,
    int flags,
    std::vector<int> *prevHeights,
    const CBlockIndex &block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // tx.nVersion is signed integer so requires cast to unsigned otherwise
    // we would be doing a signed comparison and half the range of nVersion
    // wouldn't support BIP 68.
    bool fEnforceBIP68 = static_cast<uint32_t>(tx.nVersion) >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68)
    {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++)
    {
        const CTxIn &txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG)
        {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG)
        {
            int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK)
                                                                << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) -
                                              1);
        }
        else
        {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex &block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int> *prevHeights, const CBlockIndex &block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}
