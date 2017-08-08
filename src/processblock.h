#ifndef PROCESSBLOCK_H
#define PROCESSBLOCK_H

#include "consensus/params.h"
#include "consensus/validation.h"

class CValidationState;
class CNode;
class CBlock;
class CChainParams;
class CDiskBlockPos;
class CBlockIndex;

CBlockIndex* FindMostWorkChain();
void CheckBlockIndex(const Consensus::Params& consensusParams);
bool ProcessNewBlock(CValidationState& state, const CChainParams& chainparams, const CNode* pfrom, const CBlock* pblock, bool fForceProcessing, CDiskBlockPos* dbp);
bool DisconnectTip(CValidationState& state, const Consensus::Params& consensusParams);

#endif // PROCESSBLOCK_H
