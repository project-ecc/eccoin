#include "disk.h"

CDiskTxPos::CDiskTxPos()
{
    SetNull();
}

CDiskTxPos::CDiskTxPos(unsigned int nFileIn, unsigned int nBlockPosIn, unsigned int nTxPosIn)
{
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nTxPos = nTxPosIn;
}

void CDiskTxPos::SetNull()
{
    nFile = (unsigned int) -1;
    nBlockPos = 0;
    nTxPos = 0;
}

bool CDiskTxPos::IsNull() const
{
    return (nFile == (unsigned int) -1);
}

std::string CDiskTxPos::ToString() const
{
    if (IsNull())
        return "null";
    else
        return strprintf("(nFile=%u, nBlockPos=%u, nTxPos=%u)", nFile, nBlockPos, nTxPos);
}


void CDiskTxPos::print() const
{
    LogPrintf("%s", ToString().c_str());
}
