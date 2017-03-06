#ifndef CBLOCKLOCATOR_H
#define CBLOCKLOCATOR_H

#include "serialize.h"
#include "blockindex.h"
#include "global.h"


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */

class CBlockLocator
{
protected:
    std::vector<uint256> vHave;
public:
    CBlockLocator()
    {
    }

    explicit CBlockLocator(const CBlockIndex* pindex)
    {
        Set(pindex);
    }

    explicit CBlockLocator(uint256 hashBlock)
    {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end())
            Set((*mi).second);
    }

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull();
    bool IsNull();
    void Set(const CBlockIndex* pindex);
    int GetDistanceBack();
    CBlockIndex* GetBlockIndex();
    uint256 GetBlockHash();
    int GetHeight();
};

#endif // CBLOCKLOCATOR_H
