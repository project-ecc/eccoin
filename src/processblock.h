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

CBlockIndex* FindMostWorkChain();
void CheckBlockIndex(const Consensus::Params& consensusParams);
bool ProcessNewBlock(CValidationState& state, const CNetworkTemplate& chainparams, const CNode* pfrom, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, CDiskBlockPos* dbp);
bool DisconnectTip(CValidationState& state, const Consensus::Params& consensusParams);
void InvalidChainFound(CBlockIndex* pindexNew);
void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state);
bool UndoReadFromDisk(CBlockUndo& blockundo, const CDiskBlockPos& pos, const uint256& hashBlock);

/** Run an instance of the script checking thread */
void ThreadScriptCheck();

/** Apply the effects of this block (with given index) on the UTXO set represented by coins */
bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool fJustCheck = false);

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  In case pfClean is provided, operation will try to be tolerant about errors, and *pfClean
 *  will be true if no problems were found. Otherwise, the return value will be false in case
 *  of problems. Note that in any case, coins may be modified. */
bool DisconnectBlock(const CBlock& block, CValidationState& state, const CBlockIndex* pindex, CCoinsViewCache& coins, bool* pfClean = NULL);

void removeImpossibleChainTips();

/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState& state, const CNetworkTemplate& chainparams, const std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());


#endif // PROCESSBLOCK_H
