#ifndef PROCESSHEADER_H
#define PROCESSHEADER_H

#include "primitives/block.h"
#include "validationinterface.h"

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true);
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex *pindexPrev);


#endif // PROCESSHEADER_H
