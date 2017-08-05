// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "block.h"

#include "../hash.h"
#include "../tinyformat.h"
#include "../utilstrencodings.h"
#include "../crypto/common.h"
#include "../main.h"
#include "util.h"
#include "../chain.h"
#include "../timedata.h"
#include "../crypto/scrypt.h"

uint256 CBlockHeader::GetHash() const
{
    uint256 thash;
    void * scratchbuff = scrypt_buffer_alloc();

    scrypt_hash_mine(((const void*)&(nVersion)), sizeof(CBlockHeader), ((uint32_t*)&(thash)), scratchbuff);

    scrypt_buffer_free(scratchbuff);

    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i].ToString() << "\n";
    }
    return s.str();
}


// entropy bit for stake modifier if chosen by modifier
unsigned int CBlock::GetStakeEntropyBit(unsigned int nHeight) const
{
    // Take last bit of block hash as entropy bit
    unsigned int nEntropyBit = static_cast<unsigned int>((GetHash().Get64()) & uint64_t(1));
    return nEntropyBit;
}

// ppcoin: two types of block: proof-of-work or proof-of-stake
bool CBlock::IsProofOfStake() const
{
    return (vtx.size() > 1 && vtx[1].IsCoinStake());
}

bool CBlock::IsProofOfWork() const
{
    return !IsProofOfStake();
}

std::pair<COutPoint, unsigned int> CBlock::GetProofOfStake() const
{
    //return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
    return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, this->nTime) : std::make_pair(COutPoint(), (unsigned int)0);
}


bool CBlock::SignScryptBlock(const CKeyStore& keystore)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;

    if(!IsProofOfStake())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                std::vector<unsigned char>& vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                    continue;
                if (key.GetPubKey() != vchPubKey)
                    continue;
                if(!key.Sign(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    else
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            std::vector<unsigned char>& vchPubKey = vSolutions[0];
            CKey key;

            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;

            return key.Sign(GetHash(), vchBlockSig);
        }
    }

    LogPrintf("Sign failed\n");
    return false;
}

bool CBlock::CheckBlockSignature() const
{
        if (GetHash() == chainActive.Genesis()->GetBlockHash())
            return vchBlockSig.empty();

        std::vector<std::vector<unsigned char> > vSolutions;
        txnouttype whichType;

        if(IsProofOfStake())
        {
            const CTxOut& txout = vtx[1].vout[1];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;
            if (whichType == TX_PUBKEY)
            {
                std::vector<unsigned char>& vchPubKey = vSolutions[0];
                return CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig);
            }
        }
        else
        {
            for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
            {
                const CTxOut& txout = vtx[0].vout[i];

                if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                    return false;

                if (whichType == TX_PUBKEY)
                {
                    // Verify
                    std::vector<unsigned char>& vchPubKey = vSolutions[0];
                    if(CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig))
                        continue;
                    return true;
                }
            }
        }
        return false;
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = std::max(GetBlockTime(), GetAdjustedTime());
}

// ppcoin: get max transaction timestamp
int64_t CBlock::GetMaxTransactionTime() const
{
    int64_t maxTransactionTime = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
        maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
    return maxTransactionTime;
}
