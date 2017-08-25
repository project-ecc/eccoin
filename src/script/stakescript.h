#ifndef STAKESCRIPT_H
#define STAKESCRIPT_H

#include "script.h"

class CTransaction;

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn);
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn);
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash);

#endif // STAKESCRIPT_H
