/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "chain/chain.h"
#include "crypto/common.h"
#include "crypto/hash.h"
#include "crypto/scrypt.h"
#include "init.h"
#include "main.h"
#include "networks/netman.h"
#include "networks/networktemplate.h"
#include "timedata.h"
#include "tinyformat.h"
#include "util/util.h"
#include "util/utilstrencodings.h"

uint256 CBlockHeader::GetHash() const
{
    uint256 thash;
    void *scratchbuff = scrypt_buffer_alloc();

    scrypt_hash_mine(((const void *)&(nVersion)), sizeof(CBlockHeader), ((uint32_t *)&(thash)), scratchbuff);

    scrypt_buffer_free(scratchbuff);

    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf(
        "CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(), nVersion, hashPrevBlock.ToString(), hashMerkleRoot.ToString(), nTime, nBits, nNonce,
        vtx.size());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        s << "  " << vtx[i]->ToString() << "\n";
    }
    return s.str();
}


// ppcoin: two types of block: proof-of-work or proof-of-stake
bool CBlock::IsProofOfStake() const { return (vtx.size() > 1 && vtx[1]->IsCoinStake()); }
bool CBlock::IsProofOfWork() const { return !IsProofOfStake(); }
std::pair<COutPoint, unsigned int> CBlock::GetProofOfStake() const
{
    // return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime) : std::make_pair(COutPoint(),
    // (unsigned int)0);
    return IsProofOfStake() ? std::make_pair(vtx[1]->vin[0].prevout, this->nTime) :
                              std::make_pair(COutPoint(), (unsigned int)0);
}


bool CBlock::SignScryptBlock(const CKeyStore &keystore)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;

    if (!IsProofOfStake())
    {
        for (unsigned int i = 0; i < vtx[0]->vout.size(); i++)
        {
            const CTxOut &txout = vtx[0]->vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                std::vector<unsigned char> &vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                {
                    continue;
                }
                if (key.GetPubKey() != vchPubKey)
                {
                    continue;
                }
                if (!key.Sign(GetHash(), vchBlockSig))
                {
                    continue;
                }

                return true;
            }
        }
    }
    else
    {
        const CTxOut &txout = vtx[1]->vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            std::vector<unsigned char> &vchPubKey = vSolutions[0];
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
    if (GetHash() == pnetMan->getActivePaymentNetwork()->GetConsensus().hashGenesisBlock)
        return vchBlockSig.empty();

    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;

    if (IsProofOfStake())
    {
        const CTxOut &txout = vtx[1]->vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;
        if (whichType == TX_PUBKEY)
        {
            std::vector<unsigned char> &vchPubKey = vSolutions[0];
            if (vchBlockSig.empty())
                return false;
            return CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig);
        }
    }
    else
    {
        for (unsigned int i = 0; i < vtx[0]->vout.size(); i++)
        {
            const CTxOut &txout = vtx[0]->vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            {
                return false;
            }
            if (whichType == TX_PUBKEY)
            {
                // Verify
                std::vector<unsigned char> &vchPubKey = vSolutions[0];
                if (vchBlockSig.empty())
                {
                    LogPrintf("sig is empty? \n");
                    continue;
                }
                if (!CPubKey(vchPubKey).Verify(GetHash(), vchBlockSig))
                {
                    LogPrintf("probably will see this message \n");
                    continue;
                }
                return true;
            }
            LogPrintf("got here somehow?");
        }
    }
    LogPrintf("CheckBlockSignature failed \n");
    return false;
}

void CBlock::UpdateTime() { nTime = std::max(GetBlockTime(), GetAdjustedTime()); }
// ppcoin: get max transaction timestamp
int64_t CBlock::GetMaxTransactionTime() const
{
    int64_t maxTransactionTime = 0;
    for (auto const &tx : vtx)
        maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx->nTime);
    return maxTransactionTime;
}
