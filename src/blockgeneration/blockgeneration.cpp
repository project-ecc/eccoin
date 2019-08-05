// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockgeneration.h"
#include "compare.h"
#include "consensus/merkle.h"
#include "miner.h"
#include "minter.h"
#include "util/util.h"
#include "wallet/wallet.h"

std::atomic<bool> shutdown_miner_threads(false);
std::atomic<bool> shutdown_minter_threads(false);

void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev, unsigned int &nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight + 1; // Height first in coinbase required for block.version=2
    pblock->vtx[0]->vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0]->vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast() + 1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextTargetRequired(pindexPrev, false);

    return nNewTime - nOldTime;
}

std::unique_ptr<CBlockTemplate> CreateNewBlock(CWallet *pwallet, const CScript &scriptPubKeyIn, bool fProofOfStake)
{
    if (fProofOfStake)
    {
        return CreateNewPoSBlock(pwallet, scriptPubKeyIn);
    }
    return CreateNewPoWBlock(pwallet, scriptPubKeyIn);
}

thread_group *minerThreads = nullptr;

void ThreadMiner(void *parg, bool shutdownOnly)
{
    if (minerThreads != nullptr)
    {
        minerThreads->interrupt_all();
        minerThreads->join_all();
        delete minerThreads;
        minerThreads = nullptr;
        return;
    }
    if (shutdownOnly)
    {
        return;
    }
    minerThreads = new thread_group(&shutdown_miner_threads);
    CWallet *pwallet = (CWallet *)parg;
    try
    {
        minerThreads->create_thread(&EccMiner, pwallet);
    }
    catch (std::exception &e)
    {
        PrintException(&e, "ThreadECCMiner()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadECCMiner()");
    }
    nHPSTimerStart = 0;
    dHashesPerSec = 0;
}

thread_group *minterThreads = nullptr;

void ThreadMinter(void *parg, bool shutdownOnly)
{
    if (minterThreads != nullptr)
    {
        minterThreads->interrupt_all();
        minterThreads->join_all();
        delete minterThreads;
        minterThreads = nullptr;
        return;
    }
    if (shutdownOnly)
    {
        return;
    }
    minterThreads = new thread_group(&shutdown_minter_threads);
    CWallet *pwallet = (CWallet *)parg;
    try
    {
        minterThreads->create_thread(&EccMinter, pwallet);
    }
    catch (std::exception &e)
    {
        PrintException(&e, "ThreadECCMinter()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadECCMinter()");
    }
}

void ThreadGeneration(void *parg, bool shutdownOnly, bool fProofOfStake)
{
    if (fProofOfStake)
    {
        ThreadMinter(parg, shutdownOnly);
    }
    else
    {
        ThreadMiner(parg, shutdownOnly);
    }
}
