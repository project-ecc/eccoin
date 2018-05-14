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

#include "ans/ans.h"
#include "main.h"
#include "consensus/consensus.h"
#include "script/standard.h"
#include "base58.h"
#include "messages.h"

bool CheckTransaction(const CTransaction& tx, CValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, false, REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    for (auto const& txout: tx.vout)
    {
        if (txout.nValue < 0)
        {
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-negative");
        }
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs
    std::set<COutPoint> vInOutPoints;
    for (auto const& txin: tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        for (auto const& txin: tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, false, REJECT_INVALID, "bad-txns-prevout-null");
    }
    if(tx.nVersion == 2)
    {
        if(tx.serviceReferenceHash.IsNull())
        {
            state.DoS(100, false, REJECT_INVALID, "bad-stx-ref-hash");
        }
    }
    return true;
}


/// This should only be run after CheckTransaction is run on the payment transaction
bool CheckServiceTransaction(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state)
{
    if(stx.IsNull())
    {
        return state.DoS(100, false, REJECT_INVALID, "service-transaction-is-null");
    }

    if(ptx.IsNull())
    {
        return state.DoS(100, false, REJECT_INVALID, "payment-transaction-is-null");
    }

    if(ptx.nVersion < 2)
    {
        return state.DoS(100, false, REJECT_INVALID, "payment-version-too-low");
    }

    if(stx.GetHash() != ptx.serviceReferenceHash)
    {
        return state.DoS(100, false, REJECT_INVALID, "service-hash-not-referenced");
    }

    if(stx.paymentReferenceHash != ptx.GetHash())
    {
        return state.DoS(100, false, REJECT_INVALID, "payment-hash-not-referenced");
    }

    std::vector<std::vector<unsigned char> > vSolutionsIn;
    txnouttype whichTypeIn;
    CKeyID addressInID;
    CBitcoinAddress addrIn;

    if(ptx.vin.size() != 1)
    {
        return state.DoS(100, false, REJECT_INVALID, "payment-tx-vin-improper-size");
    }
    if(ptx.vout.size() > 2) // should only be sending to ourself and maybe have a change output
    {
        return state.DoS(100, false, REJECT_INVALID, "payment-tx-vout-improper-size");
    }

    /// get the pubkeys to resolve and compare
    COutPoint prev = ptx.vin[0].prevout;

    // First try finding the previous transaction in database
    CTransaction txPrev;
    uint256 blockHashOfTx;
    // previous transaction not in main chain, may occur during initial download
    if (!GetTransaction(prev.hash, txPrev, pnetMan->getActivePaymentNetwork()->GetConsensus(), blockHashOfTx))
    {
        return state.DoS(100, false, REJECT_INVALID, "read-txPrev-failed");
    }

    CScript scriptPubKeyIn = txPrev.vout[prev.n].scriptPubKey;
    CScript scriptPubKeyOut = ptx.vout[0].scriptPubKey;


    if (!Solver(scriptPubKeyIn, whichTypeIn, vSolutionsIn))
    {
        return state.DoS(100, false, REJECT_INVALID, "could-not-solve-for-sig-in");
    }

    if (whichTypeIn == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutionsIn[0]);
        if (!pubKey.IsValid())
        {
            return state.DoS(100, false, REJECT_INVALID, "invalid-pub-key-in");
        }
        addressInID = pubKey.GetID();
    }
    else if (whichTypeIn == TX_PUBKEYHASH)
    {
        addressInID = CKeyID(uint160(vSolutionsIn[0]));
    }
    else
    {
        return state.DoS(100, false, REJECT_INVALID, "invalid-sig-type-in");
    }
    addrIn = CBitcoinAddress(addressInID);


    std::vector<std::vector<unsigned char> > vSolutionsOut;
    txnouttype whichTypeOut;
    CKeyID addressOutID;
    CBitcoinAddress addrOut;

    if (!Solver(scriptPubKeyOut, whichTypeOut, vSolutionsOut))
    {
        return state.DoS(100, false, REJECT_INVALID, "could-not-solve-for-sig-out");
    }

    if (whichTypeOut == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutionsOut[0]);
        if (!pubKey.IsValid())
        {
            return state.DoS(100, false, REJECT_INVALID, "invalid-pub-key-out");
        }
        addressOutID = pubKey.GetID();
    }
    else if (whichTypeOut == TX_PUBKEYHASH)
    {
        addressOutID = CKeyID(uint160(vSolutionsOut[0]));
    }
    else
    {
        return state.DoS(100, false, REJECT_INVALID, "invalid-sig-type-out");
    }
    addrOut = CBitcoinAddress(addressOutID);

    if(addrIn.ToString() != addrOut.ToString())
    {
        return state.DoS(100, false, REJECT_INVALID, "ownership-being-transfered");
    }
    return true;
}

/// TODO : this is a reallyyy hacky shortcut but oh well
std::string numToHex(int num)
{
    num = num % 16;
    if(num == 0)
    {
        return "0";
    }
    else if(num == 1)
    {
        return "1";
    }
    else if(num == 2)
    {
        return "2";
    }
    else if(num == 3)
    {
        return "3";
    }
    else if(num == 4)
    {
        return "4";
    }
    else if(num == 5)
    {
        return "5";
    }
    else if(num == 6)
    {
        return "6";
    }
    else if(num == 7)
    {
        return "7";
    }
    else if(num == 8)
    {
        return "8";
    }
    else if(num == 9)
    {
        return "9";
    }
    else if(num == 10)
    {
        return "A";
    }
    else if(num == 11)
    {
        return "B";
    }
    else if(num == 12)
    {
        return "C";
    }
    else if(num == 13)
    {
        return "D";
    }
    else if(num == 14)
    {
        return "E";
    }
    else if(num == 15)
    {
        return "F";
    }
    return "0";
}

// TODO : should clean this up and do this in a better way
void CalcVerificationCode(const CServiceTransaction &stx, std::string& code, const CBlock* pblock)
{
    CTransaction tx;
    uint256 blockHashOfTx;
    CBlock block;
    int height = 0;
    if(pblock == nullptr)
    {
         if(!GetTransaction(stx.paymentReferenceHash, tx, pnetMan->getActivePaymentNetwork()->GetConsensus(), blockHashOfTx))
         {
             return;
         }
         CBlockIndex* index = pnetMan->getActivePaymentNetwork()->getChainManager()->mapBlockIndex[blockHashOfTx];
         if (!ReadBlockFromDisk(block, index, pnetMan->getActivePaymentNetwork()->GetConsensus()))
         {
             return;
         }
         height = pnetMan->getActivePaymentNetwork()->getChainManager()->mapBlockIndex[block.GetHash()]->nHeight;
    }
    else
    {
        // if block was passed in this way it means its being processed, so we can use tip + 1
        height = pnetMan->getActivePaymentNetwork()->getChainManager()->chainActive.Tip()->nHeight + 1;
        block = *pblock;
    }
    int ptxIndex = 0;
    for(uint32_t i = 0 ; i < block.vtx.size(); i++)
    {
        if(block.vtx[i]->GetHash() == stx.paymentReferenceHash)
        {
            ptxIndex = i;
            break;
        }
    }
    std::string tempNum = std::to_string(height);
    if(tempNum.size() % 2 != 0)
    {
        tempNum = "0" + tempNum;
    }
    std::vector<std::string> subs;
    for(uint32_t i = 0; i < tempNum.length(); i = i + 2)
    {
        subs.push_back(tempNum.substr(i,2));
    }
    for(uint32_t j = 0; j < subs.size(); j++ )
    {
        code = code + numToHex(std::stoi(subs[j]));
    }
    code = code + "-" + std::to_string(ptxIndex);
}

void ProcessANSCommand(const CServiceTransaction &stx, const CTransaction& ptx, const CBlock* block)
{
    std::string addr = "";
    std::vector<std::vector<unsigned char> > vSolutionsOut;
    txnouttype whichTypeOut;
    CKeyID addressOutID;
    CBitcoinAddress addrOut;
    CScript scriptPubKeyOut = ptx.vout[0].scriptPubKey;
    if (!Solver(scriptPubKeyOut, whichTypeOut, vSolutionsOut))
    {
        return;
    }

    if (whichTypeOut == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutionsOut[0]);
        if (!pubKey.IsValid())
        {
           return;
        }
        addressOutID = pubKey.GetID();
    }
    else if (whichTypeOut == TX_PUBKEYHASH)
    {
        addressOutID = CKeyID(uint160(vSolutionsOut[0]));
    }
    else
    {
        return;
    }
    addrOut = CBitcoinAddress(addressOutID);
    addr = addrOut.ToString();

    // process for specific code
    if(stx.nOpCode == Opcode_ANS::OP_REGISTER)
    {
        std::string code = "";
        CalcVerificationCode(stx, code, block);
        CAnsRecord newRec(stx, addr, code);
        // check to make sure address does not already have an A record, we can check this by checking for PTR record
        if(pansMain->existsRecord(AnsRecordTypes::PTR_RECORD,newRec.getAddress()))
        {
            return;
        }
        if(!pansMain->addRecord(A_RECORD, newRec.getName(), newRec))
        {
            return;
        }
        pansMain->addRecord(PTR_RECORD, newRec.getAddress(), newRec);
    }
    else if(stx.nOpCode == Opcode_ANS::OP_RENEW)
    {
        pansMain->addTimeToRecord(stx, addr, stx.nExpireTime);
    }
    // else, leave blank for future use
}

void ProcessServiceCommand(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state, const CBlock* block)
{
    if(stx.nServiceId == 0)
    {
        ProcessANSCommand(stx, ptx, block);
    }
    // else, leave blank for future use
}


