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
bool ProcessNewBlock(CValidationState& state, const CNetworkTemplate& chainparams, const CNode* pfrom, const CBlock* pblock, bool fForceProcessing, CDiskBlockPos* dbp, BlockOrigin origin);
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

#endif // PROCESSBLOCK_H
