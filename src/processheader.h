#ifndef PROCESSHEADER_H
#define PROCESSHEADER_H

#include "validationinterface.h"
#include "networks/networktemplate.h"

bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, bool fCheckPOW = true);
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex *pindexPrev);
bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CNetworkTemplate& chainparams, CBlockIndex** ppindex=NULL);

#endif // PROCESSHEADER_H
