#ifndef CINPOINT_H
#define CINPOINT_H

#include "serialize.h"
#include "uint256.h"

class CTransaction;

/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    CTransaction* ptx;
    unsigned int n;
    CInPoint();
    CInPoint(CTransaction* ptxIn, unsigned int nIn);
    void SetNull();
    bool IsNull() const;
};



/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    unsigned int n;

    COutPoint();
    COutPoint(uint256 hashIn, unsigned int nIn);
    IMPLEMENT_SERIALIZE
    (
            READWRITE(FLATDATA(*this));
    )

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    void SetNull();
    bool IsNull() const;
    std::string ToString() const;
    void print() const;
};


#endif // CINPOINT_H
