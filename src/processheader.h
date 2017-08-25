#ifndef PROCESSHEADER_H
#define PROCESSHEADER_H

#include "primitives/block.h"
#include "validationinterface.h"
#include "chainparams.h"

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true);
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex *pindexPrev);
bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex=NULL);

#endif // PROCESSHEADER_H
