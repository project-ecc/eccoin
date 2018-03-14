// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tx/tx.h"

#include "crypto/hash.h"
#include "tinyformat.h"
#include "util/utilstrencodings.h"
#include "txdb.h"
#include "timedata.h"
#include "networks/networktemplate.h"
#include "chain/chain.h"
#include "main.h"
#include "args.h"
#include "consensus/consensus.h"
#include "wallet/wallet.h"
#include "networks/netman.h"
#include "init.h"
#include "txmempool.h"

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

uint256 CTxOut::GetHash() const
{
    return SerializeHash(*this);
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

uint256 CTransaction::GetHash() const
{
    return SerializeHash(*this);
}

void CTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CTransaction::CTransaction() : nVersion(CTransaction::CURRENT_VERSION), nTime(GetAdjustedTime()), vin(), vout(), nLockTime(0), serviceReferenceHash() {
    serviceReferenceHash.SetNull();
}

CTransaction::CTransaction(const CTransaction &tx) : nVersion(tx.nVersion), nTime(tx.nTime), vin(tx.vin), vout(tx.vout), nLockTime(tx.nLockTime), serviceReferenceHash(tx.serviceReferenceHash) {
    UpdateHash();
}

CTransaction& CTransaction::operator=(const CTransaction &tx) {
    *const_cast<int*>(&nVersion) = tx.nVersion;
    *const_cast<unsigned int*>(&nTime) = tx.nTime;
    *const_cast<std::vector<CTxIn>*>(&vin) = tx.vin;
    *const_cast<std::vector<CTxOut>*>(&vout) = tx.vout;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<uint256*>(&hash) = tx.hash;
    *const_cast<uint256*>(&serviceReferenceHash) = tx.serviceReferenceHash;

    return *this;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (std::vector<CTxOut>::const_iterator it(vout.begin()); it != vout.end(); ++it)
    {
        nValueOut += it->nValue;
        if (!MoneyRange(it->nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error("CTransaction::GetValueOut(): value out of range");
    }
    return nValueOut;
}

double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}

bool CTransaction::IsFinal(int nBlockHeight, int64_t nBlockTime) const
{
    // Time based nLockTime implemented in 0.1.6
    if (nLockTime == 0)
        return true;
    if (nBlockHeight == 0)
        nBlockHeight = pnetMan->getActivePaymentNetwork()->getChainManager()->chainActive.Height();
    if (nBlockTime == 0)
        nBlockTime = GetAdjustedTime();
    if ((int64_t)nLockTime < ((int64_t)nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;
    for(const CTxIn& txin : vin)
        if (!txin.IsFinal())
            return false;
    return true;
}

int64_t CTransaction::GetMinFee(unsigned int nBlockSize, unsigned int nBytes) const
{
    int64_t nBaseFee = DEFAULT_TRANSACTION_MINFEE;

    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;

    // To limit dust spam, require MIN_TX_FEE/MIN_RELAY_TX_FEE if any output is less than 0.01
    if (nMinFee < nBaseFee)
    {
        for(const CTxOut& txout: vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;
    }

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.


uint64_t CTransaction::GetCoinAge(uint64_t nCoinAge, bool byValue) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    for(const CTxIn& txin: vin)
    {
        CDiskTxPos txindex;
        if (!pnetMan->getActivePaymentNetwork()->getChainManager()->pblocktree->ReadTxIndex(txin.prevout.hash, txindex))
            continue;  // previous transaction not in main chain

        // Read block header
        CBlock block;
        CDiskBlockPos blockPos(txindex.nFile, txindex.nPos);
        if (!ReadBlockFromDisk(block, blockPos, pnetMan->getActivePaymentNetwork()->GetConsensus()))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + pnetMan->getActivePaymentNetwork()->getStakeMinAge() > nTime)
            continue; // only count coins meeting min age requirement

        CTransaction txPrev;
        uint256 blockHashOfTx;
        if (!GetTransaction(txin.prevout.hash, txPrev, pnetMan->getActivePaymentNetwork()->GetConsensus(), blockHashOfTx))
        {
            return false;
        }

        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug && gArgs.GetBoolArg("-printcoinage", false))
            LogPrintf("coin age nValueIn=%d nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && gArgs.GetBoolArg("-printcoinage", false))
        LogPrintf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return nCoinAge;
}


bool CTransaction::GetCoinAge(uint64_t& nCoinAge) const
{
    CBigNum bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    for(const CTxIn& txin: vin)
    {
        CDiskTxPos txindex;
        if (!pnetMan->getActivePaymentNetwork()->getChainManager()->pblocktree->ReadTxIndex(txin.prevout.hash, txindex))
            continue;  // previous transaction not in main chain

        // Read block header
        CBlock block;
        CDiskBlockPos blockPos(txindex.nFile, txindex.nPos);
        if (!ReadBlockFromDisk(block, blockPos, pnetMan->getActivePaymentNetwork()->GetConsensus()))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + pnetMan->getActivePaymentNetwork()->getStakeMinAge() > nTime)
            continue; // only count coins meeting min age requirement

        CTransaction txPrev;
        uint256 blockHashOfTx;
        if (!GetTransaction(txin.prevout.hash, txPrev, pnetMan->getActivePaymentNetwork()->GetConsensus(), blockHashOfTx))
        {
            return false;
        }

        if (nTime < txPrev.nTime)
            return false;  // Transaction timestamp violation

        int64_t nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime-txPrev.nTime) / CENT;

        if (fDebug && gArgs.GetBoolArg("-printcoinage", false))
            LogPrintf("coin age nValueIn=%d nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && gArgs.GetBoolArg("-printcoinage", false))
        LogPrintf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}


/** Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(const uint256 &hash, CTransaction &txOut, const Consensus::Params& consensusParams, uint256 &hashBlock, bool fAllowSlow)
{
    CBlockIndex *pindexSlow = NULL;

    LOCK(cs_main);

    if (mempool.lookup(hash, txOut))
    {
        return true;
    }

    CDiskTxPos postx;
    if (pnetMan->getActivePaymentNetwork()->getChainManager()->pblocktree->ReadTxIndex(hash, postx)) {
        CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
        if (file.IsNull())
            return error("%s: OpenBlockFile failed", __func__);
        CBlockHeader header;
        try {
            file >> header;
            fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
            file >> txOut;
        } catch (const std::exception& e) {
            return error("%s: Deserialize or I/O error - %s", __func__, e.what());
        }
        hashBlock = header.GetHash();
        if (txOut.GetHash() != hash)
            return error("%s: txid mismatch", __func__);
        return true;
    }

    if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
        int nHeight = -1;
        {
            CCoinsViewCache &view = *pnetMan->getActivePaymentNetwork()->getChainManager()->pcoinsTip;
            const CCoins* coins = view.AccessCoins(hash);
            if (coins)
                nHeight = coins->nHeight;
        }
        if (nHeight > 0)
            pindexSlow = pnetMan->getActivePaymentNetwork()->getChainManager()->chainActive[nHeight];
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (auto const& tx: block.vtx) {
                if (tx->GetHash() == hash)
                {
                    txOut = *tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}
