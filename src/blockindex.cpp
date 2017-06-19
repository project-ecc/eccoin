#include "block.h"
#include "blockindex.h"
#include "bignum.h"
#include "points.h"
#include "transaction.h"

#include <map>

CBlockIndex* pindexBest = NULL;
CBlockIndex *pindexBestHeader = NULL;


void CBlockIndex::SetNull()
{
    pnext = NULL;
    nBlockPos = 0;
    nChainTrust = 0;

    nMint = 0;
    nMoneySupply = 0;
    nStakeModifier = 0;
    nStakeModifierChecksum = 0;
    nChainTx = 0;

    // proof-of-stake specific fields
    prevoutStake.SetNull();
    nStakeTime = 0;
    hashProofOfStake.SetNull();

    phashBlock = NULL;
    pprev = NULL;
    pskip = NULL;
    nHeight = 0;
    nFile = 0;

    nVersion       = 0;
    hashMerkleRoot = uint256();
    nTime          = 0;
    nBits          = 0;
    nNonce         = 0;
}

CBlockIndex::CBlockIndex()
{
    phashBlock = NULL;
    pprev = NULL;
    pnext = NULL;
    nFile = 0;
    nBlockPos = 0;
    nHeight = 0;
    nChainTrust = 0;
    nMint = 0;
    nMoneySupply = 0;
    nFlags = 0;
    nStakeModifier = 0;
    nStakeModifierChecksum = 0;
    hashProofOfStake = 0;
    prevoutStake.SetNull();
    nStakeTime = 0;

    nVersion       = 0;
    hashMerkleRoot = 0;
    nTime          = 0;
    nBits          = 0;
    nNonce         = 0;
}

CBlockIndex::CBlockIndex(const CBlockHeader& block)
{
    SetNull();

    nVersion       = block.nVersion;
    hashMerkleRoot = block.hashMerkleRoot;
    nTime          = block.nTime;
    nBits          = block.nBits;
    nNonce         = block.nNonce;
}

CBlockIndex::CBlockIndex(unsigned int nFileIn, unsigned int nBlockPosIn, CBlock& block)
{
    phashBlock = NULL;
    pprev = NULL;
    pnext = NULL;
    nFile = nFileIn;
    nBlockPos = nBlockPosIn;
    nHeight = 0;
    nChainTrust = 0;
    nMint = 0;
    nMoneySupply = 0;
    nFlags = 0;
    nStakeModifier = 0;
    nStakeModifierChecksum = 0;
    hashProofOfStake = 0;
    if (block.IsProofOfStake())
    {
        SetProofOfStake();
        prevoutStake = block.vtx[1].vin[0].prevout;
        nStakeTime = block.vtx[1].nTime;
    }
    else
    {
        prevoutStake.SetNull();
        nStakeTime = 0;
    }

    nVersion       = block.nVersion;
    hashMerkleRoot = block.hashMerkleRoot;
    nTime          = block.nTime;
    nBits          = block.nBits;
    nNonce         = block.nNonce;
}

CBlock CBlockIndex::GetBlockHeader() const
{
    CBlock block;
    block.nVersion       = nVersion;
    if (pprev)
        block.hashPrevBlock = pprev->GetBlockHash();
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nNonce;
    return block;
}

uint256 CBlockIndex::GetBlockHash() const
{
    return *phashBlock;
}

int64_t CBlockIndex::GetBlockIndexTime() const
{
    return (int64_t)nTime;
}

uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if (bnTarget <= 0)
        return 0;

    return ((CBigNum(1)<<256) / (bnTarget+1)).getuint256();
}

bool CBlockIndex::IsInMainChain() const
{
    return (pnext || this == pindexBest);
}

bool CBlockIndex::CheckIndex() const
{
    return true;
}

int64_t CBlockIndex::GetPastTimeLimit() const
{
    return GetMedianTimePast();
}

int64_t CBlockIndex::GetMedianTimePast() const
{
    int64_t pmedian[nMedianTimeSpan];
    int64_t* pbegin = &pmedian[nMedianTimeSpan];
    int64_t* pend = &pmedian[nMedianTimeSpan];

    const CBlockIndex* pindex = this;
    for (int i = 0; i < nMedianTimeSpan && pindex; i++, pindex = pindex->pprev)
        *(--pbegin) = pindex->GetBlockIndexTime();

    std::sort(pbegin, pend);
    return pbegin[(pend - pbegin)/2];
}

int64_t CBlockIndex::GetMedianTime() const
{
    const CBlockIndex* pindex = this;
    for (int i = 0; i < nMedianTimeSpan/2; i++)
    {
        if (!pindex->pnext)
            return GetBlockIndexTime();
        pindex = pindex->pnext;
    }
    return pindex->GetMedianTimePast();
}


bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool CBlockIndex::IsProofOfWork() const
{
    return !(nFlags & BLOCK_PROOF_OF_STAKE);
}

bool CBlockIndex::IsProofOfStake() const
{
    return (nFlags & BLOCK_PROOF_OF_STAKE);
}

void CBlockIndex::SetProofOfStake()
{
    nFlags |= BLOCK_PROOF_OF_STAKE;
}

unsigned int CBlockIndex::GetStakeEntropyBit() const
{
    return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1);
}

bool CBlockIndex::SetStakeEntropyBit(unsigned int nEntropyBit)
{
    if (nEntropyBit > 1)
        return false;
    nFlags |= (nEntropyBit? BLOCK_STAKE_ENTROPY : 0);
    return true;
}

bool CBlockIndex::GeneratedStakeModifier() const
{
    return (nFlags & BLOCK_STAKE_MODIFIER);
}

void CBlockIndex::SetStakeModifier(uint64_t nModifier, bool fGeneratedStakeModifier)
{
    nStakeModifier = nModifier;
    if (fGeneratedStakeModifier)
        nFlags |= BLOCK_STAKE_MODIFIER;
}

std::string CBlockIndex::ToString() const
{
    return strprintf("CBlockIndex(nprev=%p, pnext=%p, nFile=%u, nBlockPos=%-6d nHeight=%d, nMint=%s, nMoneySupply=%s, nFlags=(%s)(%d)(%s), nStakeModifier=%d, nStakeModifierChecksum=%08x, hashProofOfStake=%s, prevoutStake=(%s), nStakeTime=%d merkle=%s, hashBlock=%s)",
        pprev, pnext, nFile, nBlockPos, nHeight,
        FormatMoney(nMint).c_str(), FormatMoney(nMoneySupply).c_str(),
        GeneratedStakeModifier() ? "MOD" : "-", GetStakeEntropyBit(), IsProofOfStake()? "PoS" : "PoW",
        nStakeModifier, nStakeModifierChecksum,
        hashProofOfStake.ToString().c_str(),
        prevoutStake.ToString().c_str(), nStakeTime,
        hashMerkleRoot.ToString().c_str(),
        GetBlockHash().ToString().c_str());
}

void CBlockIndex::print() const
{
    LogPrintf("%s\n", ToString().c_str());
}


uint256 CDiskBlockIndex::GetBlockHash() const
{
    if (fUseFastIndex && (nTime < GetAdjustedTime() - 24 * 60 * 60) && blockHash != 0)
        return blockHash;

    CBlock block;
    block.nVersion        = nVersion;
    block.hashPrevBlock   = hashPrev;
    block.hashMerkleRoot  = hashMerkleRoot;
    block.nTime           = nTime;
    block.nBits           = nBits;
    block.nNonce          = nNonce;

    const_cast<CDiskBlockIndex*>(this)->blockHash = block.GetHash();

    return blockHash;
}

std::string CDiskBlockIndex::ToString() const
{
    std::string str = "CDiskBlockIndex(";
    str += CBlockIndex::ToString();
    str += strprintf("\n                hashBlock=%s, hashPrev=%s, hashNext=%s)",
        GetBlockHash().ToString().c_str(),
        hashPrev.ToString().c_str(),
        hashNext.ToString().c_str());
    return str;
}

void CDiskBlockIndex::print() const
{
    LogPrintf("%s\n", ToString().c_str());
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }
/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}
