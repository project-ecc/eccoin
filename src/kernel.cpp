/// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "main.h"
#include "kernel.h"
#include "txdb.h"
#include "net.h"
#include "crypto/scrypt.h"
#include "utiltime.h"
#include "timedata.h"
#include "script/stakescript.h"

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(uint256 hashBlockFrom, uint256& nStakeModifier)
{
    nStakeModifier.SetNull();
    if (!mapBlockIndex.count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");
    const CBlockIndex* pindex = mapBlockIndex[hashBlockFrom];

    int blocksToGo = 5;
    if (chainActive.Tip()->nHeight >= 1493600)
    {
        blocksToGo = 180;
    }
    while(chainActive.Next(pindex) && blocksToGo > 0)
    {
        pindex = chainActive.Next(pindex);
        blocksToGo = blocksToGo - 1;
    }
    if(blocksToGo > 0)
    {
        LogPrintf("blocks to go was still greater than 0 even though we ran out of next indexs \n");
        return false;
    }

    CDataStream ss(SER_GETHASH, 0);
    ss << pindex->nStakeModifier;
    ss << pindex->hashProofOfStake;
    ss << pindex->pprev->nStakeModifier;
    ss << pindex->pprev->hashProofOfStake;
    ss << pindex->pprev->pprev->nStakeModifier;
    ss << pindex->pprev->pprev->hashProofOfStake;
    uint256 nStakeModifierNew = Hash(ss.begin(), ss.end());
    nStakeModifier = nStakeModifierNew;
    return true;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, const CTransaction& tx, uint256& nStakeModifier)
{
    nStakeModifier.SetNull();
    if (tx.IsNull())
    {
        if(!pindexPrev)
        {
            return true;  // genesis block's modifier is 0
        }
        return false;
    }
    if(tx.IsCoinBase())
    {
        /// if it isnt one of first 3 blocks run this calc then return. otherwise just return
        if(pindexPrev->pprev && pindexPrev->pprev->pprev)
        {
            CDataStream ss(SER_GETHASH, 0);
            ss << pindexPrev->nStakeModifier;
            ss << pindexPrev->hashProofOfStake;
            ss << pindexPrev->pprev->nStakeModifier;
            ss << pindexPrev->pprev->hashProofOfStake;
            ss << pindexPrev->pprev->pprev->nStakeModifier;
            ss << pindexPrev->pprev->pprev->hashProofOfStake;
            uint256 nStakeModifierNew = Hash(ss.begin(), ss.end());
            nStakeModifier = nStakeModifierNew;
        }
        return true;
    }

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    // First try finding the previous transaction in database
    CTransaction txPrev;
    uint256 blockHashOfTx;
    if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), blockHashOfTx))
        return error("ComputeNextStakeModifier() : INFO: read txPrev failed");  // previous transaction not in main chain, may occur during initial download

    // Read block header
    CBlock block;
    CBlockIndex* index = mapBlockIndex[blockHashOfTx];

    if (!ReadBlockFromDisk(block, index, Params().GetConsensus()))
        return fDebug? error("ComputeNextStakeModifier() : read block failed") : false; // unable to read block of previous transaction

    if (!GetKernelStakeModifier(block.GetHash(), nStakeModifier))
    {
        LogPrintf("ComputeNextStakeModifier(): GetKernelStakeModifier return false\n");
        return false;
    }
    return true;
}

// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier:
//       (v0.3) scrambles computation to make it very difficult to precompute
//              future proof-of-stake at the time of the coin's confirmation
//       (v0.2) nBits (deprecated): encodes all past block timestamps
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(int nHeight, unsigned int nBits, const CBlock& blockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake)
{
    if (nTimeTx < txPrev.nTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash() : nTime violation");

    unsigned int nTimeBlockFrom = blockFrom.GetBlockTime();
    if (nTimeBlockFrom + Params().getStakeMinAge() > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash() : min age violation");

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev.vout[prevout.n].nValue;

    // v0.3 protocol kernel hash weight starts from 0 at the min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    int64_t nTimeWeight = ((int64_t)nTimeTx - txPrev.nTime) - Params().getStakeMinAge();

    /// this works out to be (number of coins / number of seconds in a day) * age where age is number of seconds that have past since utxo was created
    CBigNum bnCoinDayWeight = CBigNum(nTimeWeight) * (CBigNum(nValueIn) / COIN / (86400)); // 86400 = 24 * 60 * 60

    // LogPrintf(">>> CheckStakeKernelHash: nTimeWeight = %"PRI64d"\n", nTimeWeight);
    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint256 nStakeModifier;
    nStakeModifier.SetNull();

    if (!GetKernelStakeModifier(blockFrom.GetHash(), nStakeModifier))
    {
        LogPrintf(">>> CheckStakeKernelHash: GetKernelStakeModifier return false\n");
        return false;
    }
    // LogPrintf(">>> CheckStakeKernelHash: passed GetKernelStakeModifier\n");
    ss << nStakeModifier;

    ss << nTimeBlockFrom << nTxPrevOffset << txPrev.nTime << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());

    if(nHeight > 1500000)
    {
        arith_uint256 arith_hashProofOfStake = UintToArith256(hashProofOfStake);

        arith_uint256 dayWeight = UintToArith256(bnCoinDayWeight.getuint256());
        arith_uint256 coinDay = UintToArith256(bnTargetPerCoinDay.getuint256());
        arith_uint256 hashTarget = GetNextTargetRequired(chainActive.Tip(), true);
        /// the older the coins are, the higher the day weight. this means with a higher dayWeight you get a bigger reduction in your hashProofOfStake
        /// this should lead to older and older coins needing to be selected as the difficulty rises due to fast block minting. larger inputs will also help this
        /// but not nearly as much as older coins will. RNG with the result of the hash is also always a factor
        arith_hashProofOfStake = arith_hashProofOfStake - (dayWeight / coinDay);

        // Now check if proof-of-stake hash meets target protocol
        if(arith_hashProofOfStake > hashTarget)
        {
            // LogPrintf(">>> bnCoinDayWeight = %s, bnTargetPerCoinDay=%s\n",
            //	bnCoinDayWeight.ToString().c_str(), bnTargetPerCoinDay.ToString().c_str());
            // LogPrintf(">>> CheckStakeKernelHash - hashProofOfStake too much\n");
            return false;
        }
    }

    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(int nHeight, const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake)
{
    if (!tx.IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx.GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];

    // First try finding the previous transaction in database
    CTransaction txPrev;
    uint256 blockHashOfTx;
    if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), blockHashOfTx))
        return error("CheckProofOfStake() : INFO: read txPrev failed");  // previous transaction not in main chain, may occur during initial download
    // Verify signature
    if (!VerifySignature(txPrev, tx, 0, true))
        return error("CheckProofOfStake() : VerifySignature failed on coinstake %s", tx.GetHash().ToString().c_str());

    // Read block header
    CBlock block;
    CBlockIndex* index = mapBlockIndex[blockHashOfTx];

    if (!ReadBlockFromDisk(block, index, Params().GetConsensus()))
        return fDebug? error("CheckProofOfStake() : read block failed") : false; // unable to read block of previous transaction

    CDiskTxPos txindex;
    pblocktree->ReadTxIndex(txPrev.GetHash(), txindex);
    unsigned int txOffset = txindex.nTxOffset + 80; // header is 80 bytes, and nTxOffset doesnt inclde header
    if (!CheckStakeKernelHash(nHeight, nBits, block, txOffset, txPrev, txin.prevout, tx.nTime, hashProofOfStake))
        return error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx.GetHash().ToString().c_str(), hashProofOfStake.ToString().c_str()); // may occur during initial download or if behind on block chain sync

    return true;
}
