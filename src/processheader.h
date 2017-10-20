#ifndef PROCESSHEADER_H
#define PROCESSHEADER_H

#include "primitives/block.h"
#include "validationinterface.h"
#include "networks/baseparams.h"

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true);
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex *pindexPrev);
bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CBaseParams& chainparams, CBlockIndex** ppindex=NULL);

#endif // PROCESSHEADER_H
