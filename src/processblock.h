/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
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

#ifndef PROCESSBLOCK_H
#define PROCESSBLOCK_H

#include "consensus/params.h"
#include "consensus/validation.h"
#include "main.h"

class CValidationState;
class CNode;
class CBlock;
class CNetworkTemplate;
class CDiskBlockPos;
class CBlockIndex;

extern bool fLargeWorkForkFound;
extern bool fLargeWorkInvalidChainFound;

CBlockIndex *FindMostWorkChain();
void CheckBlockIndex(const Consensus::Params &consensusParams);
/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * @param[out]  state   This may be set to an Error state if any error occurred processing it, including during
 * validation/connection/etc of otherwise unrelated blocks during reorganisation; or it may be set to an Invalid state
 * if pblock is itself invalid (but this is not guaranteed even when the block is checked). If you want to *possibly*
 * get feedback on whether pblock is valid, you must also install a CValidationInterface (see validationinterface.h) -
 * this will have its BlockChecked method called whenever *any* block completes validation.
 * @param[in]   pfrom   The node which we are receiving the block from; it is added to mapBlockSource and may be
 * penalised if the block is invalid.
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and
 * whitelisted peers.
 * @param[out]  dbp     If pblock is stored to disk (or already there), this will be set to its location.
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(CValidationState &state,
    const CNetworkTemplate &chainparams,
    const CNode *pfrom,
    const std::shared_ptr<const CBlock> pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp);
bool DisconnectTip(CValidationState &state, const Consensus::Params &consensusParams);
void InvalidChainFound(CBlockIndex *pindexNew);
void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state);
bool UndoReadFromDisk(CBlockUndo &blockundo, const CDiskBlockPos &pos, const uint256 &hashBlock);

/** Run an instance of the script checking thread */
void ThreadScriptCheck();
void InterruptScriptCheck();

/** Apply the effects of this block (with given index) on the UTXO set represented by coins */
bool ConnectBlock(const CBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &coins,
    bool fJustCheck = false);

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
bool DisconnectBlock(const CBlock &block,
    CValidationState &state,
    const CBlockIndex *pindex,
    CCoinsViewCache &coins,
    bool *pfClean = NULL);

/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState &state,
    const CNetworkTemplate &chainparams,
    const std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());


#endif // PROCESSBLOCK_H
