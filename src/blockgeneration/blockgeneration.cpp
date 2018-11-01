/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "blockgeneration.h"
#include "compare.h"
#include "consensus/merkle.h"
#include "miner.h"
#include "minter.h"
#include "util/util.h"
#include "wallet/wallet.h"

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

boost::thread_group *minerThreads = nullptr;

void ThreadMiner(void *parg, bool shutdownOnly)
{
    if (minerThreads != nullptr)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = nullptr;
        return;
    }
    if (shutdownOnly)
    {
        return;
    }
    minerThreads = new boost::thread_group();
    CWallet *pwallet = (CWallet *)parg;
    try
    {
        minerThreads->create_thread(boost::bind(&EccMiner, pwallet));
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
    LogPrintf("Thread Miner thread exiting \n");
}

boost::thread_group *minterThreads = nullptr;

void ThreadMinter(void *parg, bool shutdownOnly)
{
    if (minterThreads != nullptr)
    {
        minterThreads->interrupt_all();
        delete minterThreads;
        minterThreads = nullptr;
        return;
    }
    if (shutdownOnly)
    {
        return;
    }
    minterThreads = new boost::thread_group();
    CWallet *pwallet = (CWallet *)parg;
    try
    {
        minterThreads->create_thread(boost::bind(&EccMinter, pwallet));
    }
    catch (std::exception &e)
    {
        PrintException(&e, "ThreadECCMinter()");
    }
    catch (...)
    {
        PrintException(NULL, "ThreadECCMinter()");
    }
    LogPrintf("Thread Minter thread exiting \n");
}

void ThreadGeneration(void *parg, bool shutdownOnly, bool fProofOfStake)
{
    if(fProofOfStake)
    {
        ThreadMinter(parg, shutdownOnly);
    }
    else
    {
        ThreadMiner(parg, shutdownOnly);
    }
}
