#ifndef STAKESCRIPT_H
#define STAKESCRIPT_H

#include "script.h"

class CTransaction;

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,bool fValidatePayToScriptHash, int nHashType);
bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,int nHashType);
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType);
bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash, int nHashType);

#endif // STAKESCRIPT_H
