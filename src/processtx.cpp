// Copyright (c) 2017 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
bool CheckTransactionANS(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state)
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
    if(ptx.vout.size() != 2)
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

    if(stx.nOpCode == 0)
    {
        CAnsRecord newRec(username, CalcValidTime(stxNew.nTime, stxNew.paymentReferenceHash), stxNew.paymentReferenceHash, stxNew.GetHash());
        pansMain->addRecord(A_RECORD, username, newRec);
    }
    // else, leave blank for future use

    return true;
}



