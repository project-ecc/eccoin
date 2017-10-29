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

#endif // PROCESSBLOCK_H
