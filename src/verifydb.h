#ifndef VERIFYDB_H
#define VERIFYDB_H

#include "networks/networktemplate.h"
#include "coins.h"

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB {
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(const CNetworkTemplate& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth);
};

#endif // VERIFYDB_H
