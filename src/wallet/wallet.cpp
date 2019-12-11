// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"

#include "args.h"
#include "base58.h"
#include "blockstorage/blockstorage.h"
#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "chain/tx.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "init.h"
#include "kernel.h"
#include "key.h"
#include "keystore.h"
#include "main.h"
#include "net/net.h"
#include "policy/policy.h"
#include "script/script.h"
#include "script/sign.h"
#include "timedata.h"
#include "txdb.h"
#include "txmempool.h"
#include "util/util.h"
#include "util/utilmoneystr.h"

#include <assert.h>

#include <boost/algorithm/string/replace.hpp>


const char *DEFAULT_WALLET_DAT = "wallet.dat";

/** Transaction fee set by the user */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = DEFAULT_SPEND_ZEROCONF_CHANGE;
bool fSendFreeTransactions = DEFAULT_SEND_FREE_TRANSACTIONS;
bool fWalletUnlockStakingOnly = false;
std::atomic<bool> fAllowKeypoolRefills{DEFAULT_ALLOW_KEYPOOL_REFILLS};

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(DEFAULT_TRANSACTION_MINFEE);
/**
 * If fee estimation does not have enough data to provide estimates, use this fee instead.
 * Has no effect if not using fee estimation
 * Override with -fallbackfee
 */
CFeeRate CWallet::fallbackFee = CFeeRate(DEFAULT_FALLBACK_FEE);

const uint256 CMerkleTx::ABANDON_HASH(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));

namespace AddressBookType
{
const char *UNKNOWN = "unknown";
const char *SEND = "send";
const char *RECEIVE = "receive";
};

struct CompareValueOnly
{
    bool operator()(const std::pair<CAmount, std::pair<const CWalletTx *, unsigned int> > &t1,
        const std::pair<CAmount, std::pair<const CWalletTx *, unsigned int> > &t2) const
    {
        return t1.first < t2.first;
    }
};

std::string COutput::ToString() const
{
    return strprintf(
        "COutput(%s, %d, %d) [%s]", tx->tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->tx->vout[i].nValue));
}

const CWalletTx *CWallet::GetWalletTx(const uint256 &hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

CPubKey CWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    // default to compressed public keys if we want 0.6.0 wallets
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY);

    CKey secret;
    secret.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey(): AddKey failed");
    return pubkey;
}

bool CWallet::AddKeyPubKey(const CKey &secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted())
    {
        return CWalletDB(strWalletFile).WriteKey(pubkey, secret.GetPrivKey(), mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile)
                .WriteCryptedKey(vchPubKey, vchCryptedSecret, mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::AddCScript(const CScript &redeemScript)
{
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(Hash160(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript &redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = CBitcoinAddress(CScriptID(redeemScript)).ToString();
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can "
                  "never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest) { return CCryptoKeyStore::AddWatchOnly(dest); }
bool CWallet::Unlock(const SecureString &strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial _vMasterKey;

    {
        LOCK(cs_wallet);
        for (auto const &pMasterKey : mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(_vMasterKey))
                return true;
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString &strOldWalletPassphrase,
    const SecureString &strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial _vMasterKey;
        for (auto &pMasterKey : mapMasterKeys)
        {
            if (!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, _vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(_vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                    pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                    pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations =
                    (pMasterKey.second.nDeriveIterations +
                        pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) /
                    2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf(
                    "Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt,
                        pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(_vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::SetBestChain(const CBlockLocator &loc)
{
    CWalletDB walletdb(strWalletFile);
    walletdb.WriteBestBlock(loc);
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB *pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
        nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB *pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

std::set<uint256> CWallet::GetConflicts(const uint256 &txid) const
{
    std::set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx &wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    for (auto const &txin : wtx.tx->vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue; // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator _it = range.first; _it != range.second; ++_it)
            result.insert(_it->second);
    }
    return result;
}

void CWallet::Flush(bool shutdown) { bitdb.Flush(shutdown); }
bool CWallet::Verify(const std::string &walletFile, std::string &warningString, std::string &errorString)
{
    if (!bitdb.Open(GetDataDir()))
    {
        // try moving the database env out of the way
        fs::path pathDatabase = GetDataDir() / "database";
        fs::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime());
        try
        {
            fs::rename(pathDatabase, pathDatabaseBak);
            LogPrintf("Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        }
        catch (const fs::filesystem_error &)
        {
            // failure is ok (well, not really, but it's not worse than what we started with)
        }

        // try again
        if (!bitdb.Open(GetDataDir()))
        {
            // if it still fails, it probably means we can't even create the database env
            std::string msg = strprintf("Error initializing wallet database environment %s!", GetDataDir());
            errorString += msg;
            return true;
        }
    }

    if (gArgs.GetBoolArg("-salvagewallet", false))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, walletFile, true))
            return false;
    }

    if (fs::exists(GetDataDir() / walletFile))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(walletFile, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            warningString += strprintf(("Warning: wallet.dat corrupt, data salvaged!"
                                        " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                        " your balance or transactions are incorrect you should"
                                        " restore from a backup."),
                GetDataDir());
        }
        if (r == CDBEnv::RECOVER_FAIL)
            errorString += ("wallet.dat corrupt, salvage failed");
    }

    return true;
}

void CWallet::SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx *copyFrom = NULL;
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256 &hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos)
        {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (TxSpends::iterator it = range.first; it != range.second; ++it)
    {
        const uint256 &hash = it->second;
        CWalletTx *copyTo = &mapWallet[hash];
        if (copyFrom == copyTo)
            continue;
        if (!copyFrom->IsEquivalentTo(*copyTo))
            continue;
        copyTo->mapValue = copyFrom->mapValue;
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256 &hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256 &wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end())
        {
            int depth = mit->second.GetDepthInMainChain();
            if (depth > 0 || (depth == 0 && !mit->second.isAbandoned()))
                return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToSpends(const COutPoint &outpoint, const uint256 &wtxid)
{
    mapTxSpends.insert(std::make_pair(outpoint, wtxid));

    std::pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData(range);
}


void CWallet::AddToSpends(const uint256 &wtxid)
{
    assert(mapWallet.count(wtxid));
    CWalletTx &thisTx = mapWallet[wtxid];
    if (thisTx.tx->IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (auto const &txin : thisTx.tx->vin)
        AddToSpends(txin.prevout, wtxid);
}

bool CWallet::EncryptWallet(const SecureString &strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial _vMasterKey;
    RandAddSeedPerfmon();

    _vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(&_vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;
    RandAddSeedPerfmon();

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(
        strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations =
        (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) /
        2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(
            strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(_vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            assert(!pwalletdbEncryption);
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            if (!pwalletdbEncryption->TxnBegin())
            {
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
                return false;
            }
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(_vMasterKey))
        {
            if (fFileBacked)
            {
                pwalletdbEncryption->TxnAbort();
                delete pwalletdbEncryption;
            }
            // We now probably have half of our keys encrypted in memory, and half not...
            // die and let the user reload the unencrypted wallet.
            assert(false);
        }

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        if (fFileBacked)
        {
            if (!pwalletdbEncryption->TxnCommit())
            {
                delete pwalletdbEncryption;
                // We now have keys encrypted in memory, but not on disk...
                // die to avoid confusion and let the user reload the unencrypted wallet.
                assert(false);
            }

            delete pwalletdbEncryption;
            pwalletdbEncryption = NULL;
        }

        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);
    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb)
    {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    }
    else
    {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        for (std::pair<const uint256, CWalletTx> &item : mapWallet)
        {
            item.second.MarkDirty();
        }
    }
}

bool CWallet::AddToWallet(const CWalletTx &wtxIn, bool fFromLoadWallet, CWalletDB *pwalletdb)
{
    uint256 hash = wtxIn.tx->GetHash();

    if (fFromLoadWallet)
    {
        mapWallet[hash] = wtxIn;
        CWalletTx &wtx = mapWallet[hash];
        wtx.BindWallet(this);
        wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));
        AddToSpends(hash);
        for (auto const &txin : wtx.tx->vin)
        {
            if (mapWallet.count(txin.prevout.hash))
            {
                CWalletTx &prevtx = mapWallet[txin.prevout.hash];
                if (prevtx.nIndex == -1 && !prevtx.hashUnset())
                {
                    MarkConflicted(prevtx.hashBlock, wtx.tx->GetHash());
                }
            }
        }
    }
    else
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        std::pair<std::map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(std::make_pair(hash, wtxIn));
        CWalletTx &wtx = (*ret.first).second;
        wtx.BindWallet(this);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext(pwalletdb);
            wtxOrdered.insert(std::make_pair(wtx.nOrderPos, &wtx));

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (!wtxIn.hashUnset())
            {
                RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
                if (pnetMan->getChainActive()->mapBlockIndex.count(wtxIn.hashBlock))
                {
                    int64_t latestNow = wtx.nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        const TxItems &txOrdered = wtxOrdered;
                        for (TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second;
                            if (pwtx == &wtx)
                                continue;
                            int64_t nSmartTime = 0;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    int64_t blocktime = pnetMan->getChainActive()->mapBlockIndex[wtxIn.hashBlock]->GetBlockTime();
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    LogPrintf("AddToWallet(): found %s in block %s not in index\n", wtxIn.tx->GetHash().ToString(),
                        wtxIn.hashBlock.ToString());
            }
            AddToSpends(hash);
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (!wtxIn.hashUnset() && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            // If no longer abandoned, update
            if (wtxIn.hashBlock.IsNull() && wtx.isAbandoned())
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.nIndex != wtx.nIndex))
            {
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
        }

        //// debug print
        LogPrintf("AddToWallet %s  %s%s\n", wtxIn.tx->GetHash().ToString(), (fInsertedNew ? "new" : ""),
            (fUpdated ? "update" : ""));

        // Write to disk
        if (fInsertedNew || fUpdated)
        {
            if (!wtx.WriteToDisk(pwalletdb))
            {
                return false;
            }
        }

        // Break debit/credit balance caches:
        wtx.MarkDirty();

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = gArgs.GetArg("-walletnotify", "");

        if (!strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.tx->GetHash().GetHex());
            std::thread t(runCommand, strCmd);
            t.detach(); // thread runs free
        }
    }
    return true;
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransactionRef &ptx, const CBlock *pblock, bool fUpdate)
{
    {
        const CTransaction &tx = *ptx;
        AssertLockHeld(cs_wallet);
        if (pblock)
        {
            for (auto const &txin : tx.vin)
            {
                std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range =
                    mapTxSpends.equal_range(txin.prevout);
                while (range.first != range.second)
                {
                    if (range.first->second != tx.GetHash())
                    {
                        LogPrintf(
                            "Transaction %s (in block %s) conflicts with wallet transaction %s (both spend %s:%i)\n",
                            tx.GetHash().ToString(), pblock->GetHash().ToString(), range.first->second.ToString(),
                            range.first->first.hash.ToString(), range.first->first.n);
                        MarkConflicted(pblock->GetHash(), range.first->second);
                    }
                    range.first++;
                }
            }
        }
        bool fExisted = mapWallet.count(tx.GetHash()) != 0;
        if (fExisted && !fUpdate)
            return false;
        if (fExisted || IsMine(tx) || IsFromMe(tx))
        {
            CWalletTx wtx(this, ptx);
            // Get merkle branch if transaction was found in a block
            if (pblock)
            {
                wtx.SetMerkleBranch(*pblock);
            }
            // Do not flush the wallet here for performance reasons
            // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our
            // SetBestChain-mechanism
            CWalletDB walletdb(strWalletFile, "r+", false);
            return AddToWallet(wtx, false, &walletdb);
        }
    }
    return false;
}

bool CWallet::AbandonTransaction(const uint256 &hashTx)
{
    LOCK(cs_wallet);

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    // Can't mark abandoned if confirmed or in mempool
    assert(mapWallet.count(hashTx));
    CWalletTx &origtx = mapWallet[hashTx];
    if (origtx.GetDepthInMainChain() > 0 || origtx.InMempool())
    {
        return false;
    }

    todo.insert(hashTx);

    while (!todo.empty())
    {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx &wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        // If the orig tx was not in block, none of its spends can be
        assert(currentconfirm <= 0);
        // if (currentconfirm < 0) {Tx and spends are already conflicted, no need to abandon}
        if (currentconfirm == 0 && !wtx.isAbandoned())
        {
            // If the orig tx was not in block/mempool, none of its spends can be in mempool
            assert(!wtx.InMempool());
            wtx.nIndex = -1;
            wtx.setAbandoned();
            wtx.MarkDirty();
            wtx.WriteToDisk(&walletdb);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them abandoned too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(hashTx, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now)
            {
                if (!done.count(iter->second))
                {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (auto const &txin : wtx.tx->vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }

    return true;
}

void CWallet::MarkConflicted(const uint256 &hashBlock, const uint256 &hashTx)
{
    LOCK(cs_wallet);
    int conflictconfirms = 0;
    CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(hashBlock);
    if (pindex)
    {
        RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
        if (pnetMan->getChainActive()->chainActive.Contains(pindex))
        {
            conflictconfirms = -(pnetMan->getChainActive()->chainActive.Height() - pindex->nHeight + 1);
        }
    }
    // If number of conflict confirms cannot be determined, this means
    // that the block is still unknown or not yet part of the main chain,
    // for example when loading the wallet during a reindex. Do nothing in that
    // case.
    if (conflictconfirms >= 0)
        return;

    // Do not flush the wallet here for performance reasons
    CWalletDB walletdb(strWalletFile, "r+", false);

    std::set<uint256> todo;
    std::set<uint256> done;

    todo.insert(hashTx);

    while (!todo.empty())
    {
        uint256 now = *todo.begin();
        todo.erase(now);
        done.insert(now);
        assert(mapWallet.count(now));
        CWalletTx &wtx = mapWallet[now];
        int currentconfirm = wtx.GetDepthInMainChain();
        if (conflictconfirms < currentconfirm)
        {
            // Block is 'more conflicted' than current confirm; update.
            // Mark transaction as conflicted with this block.
            wtx.nIndex = -1;
            wtx.hashBlock = hashBlock;
            wtx.MarkDirty();
            wtx.WriteToDisk(&walletdb);
            // Iterate over all its outputs, and mark transactions in the wallet that spend them conflicted too
            TxSpends::const_iterator iter = mapTxSpends.lower_bound(COutPoint(now, 0));
            while (iter != mapTxSpends.end() && iter->first.hash == now)
            {
                if (!done.count(iter->second))
                {
                    todo.insert(iter->second);
                }
                iter++;
            }
            // If a transaction changes 'conflicted' state, that changes the balance
            // available of the outputs it spends. So force those to be recomputed
            for (auto const &txin : wtx.tx->vin)
            {
                if (mapWallet.count(txin.prevout.hash))
                    mapWallet[txin.prevout.hash].MarkDirty();
            }
        }
    }
}

void CWallet::SyncTransaction(const CTransactionRef &ptx, const CBlock *pblock, int txIdx)
{
    LOCK(cs_wallet);

    if (!AddToWalletIfInvolvingMe(ptx, pblock, true))
    {
        return; // Not one of ours
    }

    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    for (const CTxIn &txin : ptx->vin)
    {
        if (mapWallet.count(txin.prevout.hash))
            mapWallet[txin.prevout.hash].MarkDirty();
    }
}

isminetype CWallet::IsMine(const CTxIn &txin) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx &prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                return IsMine(prev.tx->vout[txin.prevout.n]);
        }
    }
    return ISMINE_NO;
}

CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter &filter) const
{
    {
        LOCK(cs_wallet);
        std::map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx &prev = (*mi).second;
            if (txin.prevout.n < prev.tx->vout.size())
                if (IsMine(prev.tx->vout[txin.prevout.n]) & filter)
                    return prev.tx->vout[txin.prevout.n].nValue;
        }
    }
    return 0;
}

isminetype CWallet::IsMine(const CTxOut &txout) const { return ::IsMine(*this, txout.scriptPubKey); }
CAmount CWallet::GetCredit(const CTxOut &txout, const isminefilter &filter) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetCredit(): value out of range");
    return ((IsMine(txout) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut &txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut &txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetChange(): value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

bool CWallet::IsMine(const CTransaction &tx) const
{
    for (auto const &txout : tx.vout)
        if (IsMine(txout))
            return true;
    return false;
}

bool CWallet::IsFromMe(const CTransaction &tx) const { return (GetDebit(tx, ISMINE_ALL) > 0); }
CAmount CWallet::GetDebit(const CTransaction &tx, const isminefilter &filter) const
{
    CAmount nDebit = 0;
    for (auto const &txin : tx.vin)
    {
        nDebit += GetDebit(txin, filter);
        if (!MoneyRange(nDebit))
            throw std::runtime_error("CWallet::GetDebit(): value out of range");
    }
    return nDebit;
}

CAmount CWallet::GetCredit(const CTransaction &tx, const isminefilter &filter) const
{
    CAmount nCredit = 0;
    for (auto const &txout : tx.vout)
    {
        nCredit += GetCredit(txout, filter);
        if (!MoneyRange(nCredit))
            throw std::runtime_error("CWallet::GetCredit(): value out of range");
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction &tx) const
{
    CAmount nChange = 0;
    for (auto const &txout : tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error("CWallet::GetChange(): value out of range");
    }
    return nChange;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (tx->IsCoinBase() || tx->IsCoinStake())
        {
            // Generated block
            if (!hashUnset())
            {
                std::map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            std::map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(tx->GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashUnset())
                {
                    std::map<uint256, int>::const_iterator mj = pwallet->mapRequestCount.find(hashBlock);
                    if (mj != pwallet->mapRequestCount.end())
                        nRequests = (*mj).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

void CWalletTx::GetAmounts(std::list<COutputEntry> &listReceived,
    std::list<COutputEntry> &listSent,
    CAmount &nFee,
    const isminefilter &filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();

    // Compute fee:
    CAmount nDebit = GetDebit(filter);
    if (nDebit > 0) // debit>0 means we signed/sent this transaction
    {
        CAmount nValueOut = tx->GetValueOut();
        nFee = nDebit - nValueOut;
    }

    // Sent/received.
    for (unsigned int i = 0; i < tx->vout.size(); ++i)
    {
        const CTxOut &txout = tx->vout[i];

        // Skip stake out for coinstake transactions
        if (txout.scriptPubKey.empty())
            continue;

        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;

        if (!ExtractDestination(txout.scriptPubKey, address) && !txout.scriptPubKey.IsUnspendable())
        {
            LogPrintf(
                "CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n", this->tx->GetHash().ToString());
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }
}

void CWalletTx::GetAmounts(CAmount &nReceived, CAmount &nSent, CAmount &nFee, const isminefilter &filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, filter);

    for (auto const &s : listSent)
        nSent += s.amount;
    nFee = allFee;

    {
        LOCK(pwallet->cs_wallet);
        for (auto const &r : listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                std::map<CTxDestination, CAddressBookData>::const_iterator mi =
                    pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end())
                {
                    nReceived += r.amount;
                }
            }
            else
            {
                nReceived += r.amount;
            }
        }
    }
}


bool CWalletTx::WriteToDisk(CWalletDB *pwalletdb) { return pwalletdb->WriteTx(tx->GetHash(), *this); }
/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 */
int CWallet::ScanForWalletTransactions(CBlockIndex *pindexStart, bool fUpdate)
{
    int ret = 0;
    int64_t nNow = GetTime();
    CBlockIndex *pindex = pindexStart;
    int nEndHeight = pnetMan->getChainActive()->chainActive.Tip()->nHeight;
    {
        LOCK(cs_wallet);

        // no need to read and scan block, if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200)))
        {
            pindex = pnetMan->getChainActive()->chainActive.Next(pindex);
        }
        GetMainSignals().SystemMessage("RESCAN: STARTED");
        while (pindex)
        {
            CBlock block;
            {
                ReadBlockFromDisk(block, pindex, pnetMan->getActivePaymentNetwork()->GetConsensus());
            }
            for (auto &ptx : block.vtx)
            {
                if (AddToWalletIfInvolvingMe(ptx, &block, fUpdate))
                {
                    ret++;
                }
            }
            pindex = pnetMan->getChainActive()->chainActive.Next(pindex);
            if (GetTime() >= nNow + 60)
            {
                nNow = GetTime();
                LogPrintf("Still rescanning. At block %d out of %d\n", pindex->nHeight, nEndHeight);
                GetMainSignals().SystemMessage(strprintf("RESCAN: BLOCK %d of %d", pindex->nHeight, nEndHeight));
            }
        }
        GetMainSignals().SystemMessage("RESCAN: COMPLETE");
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;

    std::map<int64_t, CWalletTx *> mapSorted;

    {
        LOCK(cs_wallet);
        // Sort pending wallet transactions based on their initial wallet insertion order
        for (auto const &item : mapWallet)
        {
            const uint256 &wtxid = item.first;
            CWalletTx wtx = item.second;
            assert(wtx.tx->GetHash() == wtxid);

            int nDepth = wtx.GetDepthInMainChain();

            if (!wtx.tx->IsCoinBase() && !wtx.tx->IsCoinStake() && (nDepth == 0 && !wtx.isAbandoned()))
            {
                mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
            }
        }
    }

    // Try to add wallet transactions to memory pool
    for (auto const &item : mapSorted)
    {
        CWalletTx &wtx = *(item.second);
        wtx.AcceptToMemoryPool(false);
        SyncWithWallets(wtx.tx, nullptr, -1);
    }
}

void RelayTransaction(const CTransaction &tx, CConnman &connman);

bool CWalletTx::RelayWalletTransaction(CConnman *connman)
{
    if (pwallet == nullptr)
    {
        return false;
    }
    if (!pwallet->GetBroadcastTransactions())
    {
        return false;
    }
    if (tx->IsCoinBase() || tx->IsCoinStake() || isAbandoned() || GetDepthInMainChain() != 0)
    {
        return false;
    }
    RelayTransaction(*tx, *connman);
    return true;
}

std::set<uint256> CWalletTx::GetConflicts() const
{
    std::set<uint256> result;
    if (pwallet != NULL)
    {
        uint256 myHash = tx->GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter &filter) const
{
    if (tx->vin.empty())
        return 0;

    CAmount debit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            nDebitCached = pwallet->GetDebit(*tx, ISMINE_SPENDABLE);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            nWatchDebitCached = pwallet->GetDebit(*tx, ISMINE_WATCH_ONLY);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CAmount CWalletTx::GetCredit(const isminefilter &filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((tx->IsCoinBase() || tx->IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    int64_t credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            nCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            nWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (tx->IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*tx, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((tx->IsCoinBase() || tx->IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = tx->GetHash();
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_SPENDABLE);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableCreditCached = nCredit;
    fAvailableCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool &fUseCache) const
{
    if (tx->IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*tx, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool &fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if ((tx->IsCoinBase() || tx->IsCoinStake()) && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < tx->vout.size(); i++)
    {
        if (!pwallet->IsSpent(tx->GetHash(), i))
        {
            const CTxOut &txout = tx->vout[i];
            nCredit += pwallet->GetCredit(txout, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*tx);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::InMempool() const
{
    if (mempool.exists(tx->GetHash()))
    {
        return true;
    }
    return false;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!CheckFinalTx(*tx))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
    {
        return true;
    }
    if (nDepth < 0)
    {
        return false;
    }
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
    {
        return false;
    }

    // Don't trust unconfirmed transactions from us unless they are in the mempool.
    if (!InMempool())
    {
        return false;
    }

    // Trusted if all inputs are from us and are in the mempool:
    for (auto const &txin : tx->vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx *parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == NULL)
        {
            return false;
        }
        const CTxOut &parentOut = parent->tx->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
        {
            return false;
        }
    }
    return true;
}

bool CWalletTx::IsEquivalentTo(const CWalletTx &_tx) const
{
    CTransaction tx1 = *(this->tx);
    CTransaction tx2 = *(_tx.tx);
    for (unsigned int i = 0; i < tx1.vin.size(); i++)
        tx1.vin[i].scriptSig = CScript();
    for (unsigned int i = 0; i < tx2.vin.size(); i++)
        tx2.vin[i].scriptSig = CScript();
    return CTransaction(tx1) == CTransaction(tx2);
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime, CConnman *connman)
{
    std::vector<uint256> result;

    std::multimap<unsigned int, CWalletTx> mapSorted;
    {
        LOCK(cs_wallet);
        // Sort them in chronological order
        for (auto &item : mapWallet)
        {
            CWalletTx &wtx = item.second;
            // Don't rebroadcast if newer than nTime:
            if (wtx.nTimeReceived > nTime)
                continue;
            mapSorted.insert(std::make_pair(wtx.nTimeReceived, wtx));
        }
    }
    for (auto &item : mapSorted)
    {
        CWalletTx &wtx = item.second;
        if (wtx.RelayWalletTransaction(connman))
            result.push_back(wtx.tx->GetHash());
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime, CConnman *connman)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime - 5 * 60, connman);
    if (!relayed.empty())
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet


/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &(*it).second;
            if (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0 && pcoin->InMempool())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx *pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

void CWallet::AvailableCoins(std::vector<COutput> &vCoins,
    bool fOnlyConfirmed,
    bool fIncludeZeroValue,
    const std::vector<CTxIn> &vin) const
{
    vCoins.clear();

    {
        LOCK(cs_wallet);
        for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const uint256 &wtxid = it->first;
            const CWalletTx *pcoin = &(*it).second;

            if (!CheckFinalTx(*(pcoin->tx)))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if ((pcoin->tx->IsCoinBase() || pcoin->tx->IsCoinStake()) && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;

            // We should not consider coins which aren't at least in our mempool
            // It's possible for these to be conflicted via ancestors which we may never be able to detect
            if (nDepth == 0 && !pcoin->InMempool())
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                if (vin.empty() == false)
                {
                    bool found = false;
                    bool input = false;
                    for (const auto &iter : vin)
                    {
                        if (iter.prevout.hash == pcoin->tx->GetHash())
                        {
                            if (i == iter.prevout.n)
                            {
                                input = true;
                                break;
                            }
                            found = true;
                        }
                    }
                    if (found == false && input == false)
                    {
                        break;
                    }
                    if (found == true && input == false)
                    {
                        continue;
                    }
                }

                isminetype mine = IsMine(pcoin->tx->vout[i]);
                if (!(IsSpent(wtxid, i)) && mine != ISMINE_NO && !IsLockedCoin((*it).first, i) &&
                    (pcoin->tx->vout[i].nValue > 0 || fIncludeZeroValue))
                    vCoins.push_back(COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO));
            }
        }
    }
}

static void ApproximateBestSubset(std::vector<std::pair<CAmount, std::pair<const CWalletTx *, unsigned int> > > vValue,
    const CAmount &nTotalLower,
    const CAmount &nTargetValue,
    std::vector<char> &vfBest,
    CAmount &nBest,
    int iterations = 1000)
{
    std::vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                // The solver here uses a randomized algorithm,
                // the randomness serves no real security purpose but is just
                // needed to prevent degenerate behavior and it is important
                // that the rng is fast. We do not use a constant random sequence,
                // because there may be some privacy improvement by making
                // the selection random.
                if (nPass == 0 ? insecure_rand() & 1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }

    // Reduces the approximate best subset by removing any inputs that are smaller than the surplus of nTotal beyond
    // nTargetValue.
    for (unsigned int i = 0; i < vValue.size(); i++)
    {
        if (vfBest[i] && (nBest - vValue[i].first) >= nTargetValue)
        {
            vfBest[i] = false;
            nBest -= vValue[i].first;
        }
    }
}

CAmount CWallet::GetStake() const
{
    CAmount nTotal = 0;
    LOCK(cs_wallet);
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx *pcoin = &(*it).second;
        if (pcoin->tx->IsCoinStake() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*(pcoin->tx), ISMINE_ALL);
    }
    return nTotal;
}

CAmount CWallet::GetNewMint() const
{
    CAmount nTotal = 0;
    LOCK(cs_wallet);
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        const CWalletTx *pcoin = &(*it).second;
        if (pcoin->tx->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0 && pcoin->GetDepthInMainChain() > 0)
            nTotal += CWallet::GetCredit(*(pcoin->tx), ISMINE_ALL);
    }
    return nTotal;
}

bool CWallet::SelectCoinsMinConf(const CAmount &nTargetValue,
    int nConfMine,
    int nConfTheirs,
    std::vector<COutput> vCoins,
    std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet,
    CAmount &nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    std::pair<CAmount, std::pair<const CWalletTx *, unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    std::vector<std::pair<CAmount, std::pair<const CWalletTx *, unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    for (auto const &output : vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        CAmount n = pcoin->tx->vout[i].nValue;

        std::pair<CAmount, std::pair<const CWalletTx *, unsigned int> > coin =
            std::make_pair(n, std::make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + MIN_CHANGE)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    std::vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + MIN_CHANGE)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + MIN_CHANGE, vfBest, nBest);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + MIN_CHANGE) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else
    {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        LogPrint("selectcoins", "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                LogPrint("selectcoins", "%s ", FormatMoney(vValue[i].first));
        LogPrint("selectcoins", "total %s\n", FormatMoney(nBest));
    }

    return true;
}

bool CWallet::SelectCoins(const CAmount &nTargetValue,
    std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet,
    CAmount &nValueRet,
    const std::vector<CTxIn> &vin) const
{
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true, false, vin);

    if (vin.empty() == false)
    {
        for (const COutput &out : vCoins)
        {
            if (!out.fSpendable)
                continue;
            nValueRet += out.tx->tx->vout[out.i].nValue;
            setCoinsRet.insert(std::make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }

    // calculate value from preset inputs and store them
    std::set<std::pair<const CWalletTx *, uint32_t> > setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    for (auto const &outpoint : vPresetInputs)
    {
        std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx *pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->tx->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->tx->vout[outpoint.n].nValue;
            setPresetCoins.insert(std::make_pair(pcoin, outpoint.n));
        }
        else
            return false; // TODO: Allow non-wallet inputs
    }

    bool res = nTargetValue <= nValueFromPresetInputs ||
               SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 6, vCoins, setCoinsRet, nValueRet) ||
               SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 1, 1, vCoins, setCoinsRet, nValueRet) ||
               (bSpendZeroConfChange &&
                   SelectCoinsMinConf(nTargetValue - nValueFromPresetInputs, 0, 1, vCoins, setCoinsRet, nValueRet));

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;

    return res;
}

bool CWallet::FundTransaction(CTransaction &tx,
    CAmount &nFeeRet,
    int &nChangePosRet,
    std::string &strFailReason,
    bool includeWatching)
{
    std::vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    for (auto const &txOut : tx.vout)
    {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false};
        vecSend.push_back(recipient);
    }

    CReserveKey reservekey(this);
    CWalletTx wtx;
    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosRet, strFailReason, false, tx.vin))
        return false;

    if (nChangePosRet != -1)
    {
        tx.vout.insert(tx.vout.begin() + nChangePosRet, wtx.tx->vout[nChangePosRet]);
    }

    // Add new txins (keeping original txin scriptSig/order)
    for (auto const &txin : wtx.tx->vin)
    {
        bool found = false;
        for (auto const &origTxIn : tx.vin)
        {
            if (txin.prevout.hash == origTxIn.prevout.hash && txin.prevout.n == origTxIn.prevout.n)
            {
                found = true;
                break;
            }
        }
        if (!found)
            tx.vin.push_back(txin);
    }

    return true;
}

bool CWallet::CreateTransaction(const std::vector<CRecipient> &vecSend,
    CWalletTx &wtxNew,
    CReserveKey &reservekey,
    CAmount &nFeeRet,
    int &nChangePosRet,
    std::string &strFailReason,
    bool sign,
    const std::vector<CTxIn> &vin)
{
    if (fWalletUnlockStakingOnly)
    {
        LogPrintf("CreateTransaction() :  Error: Wallet unlocked for staking only, unable to create transaction.\n");
        return false;
    }
    CAmount nValue = 0;
    unsigned int nSubtractFeeFromAmount = 0;
    for (auto const &recipient : vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = ("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = ("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    CTransaction txNew;

    // Discourage fee sniping.
    //
    // For a large miner the value of the transactions in the best block and
    // the mempool can exceed the cost of deliberately attempting to mine two
    // blocks to orphan the current best block. By setting nLockTime such that
    // only the next block can include the transaction, we discourage this
    // practice as the height restricted and limited blocksize gives miners
    // considering fee sniping fewer options for pulling off this attack.
    //
    // A simple way to think about this is from the wallet's point of view we
    // always want the blockchain to move forward. By setting nLockTime this
    // way we're basically making the statement that we only want this
    // transaction to appear in the next block; we don't want to potentially
    // encourage reorgs by allowing transactions to appear at lower heights
    // than the next block in forks of the best chain.
    //
    // Of course, the subsidy is high enough, and transaction volume low
    // enough, that fee sniping isn't a problem yet, but by implementing a fix
    // now we ensure code won't be written that makes assumptions about
    // nLockTime that preclude a fix later.
    txNew.nLockTime = pnetMan->getChainActive()->chainActive.Height();

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)(pnetMan->getChainActive()->chainActive.Height()));
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = 0;
            // Start with no fee and loop until there is enough fee
            while (true)
            {
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                nChangePosRet = -1;
                bool fFirst = true;

                CAmount nValueToSelect = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nValueToSelect += nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                for (auto const &recipient : vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        // Subtract fee equally from each selected recipient
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount;

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    if (txout.IsDust())
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = ("The transaction amount is too small to pay the fee");
                            else
                                strFailReason =
                                    ("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = ("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                std::set<std::pair<const CWalletTx *, unsigned int> > setCoins;
                CAmount nValueIn = 0;
                if (!SelectCoins(nValueToSelect, setCoins, nValueIn, vin))
                {
                    strFailReason = ("Insufficient funds");
                    return false;
                }
                for (auto pcoin : setCoins)
                {
                    CAmount nCredit = pcoin.first->tx->vout[pcoin.second].nValue;
                    // The coin age after the next block (depth+1) is used instead of the current,
                    // reflecting an assumption the user would accept a bit more delay for
                    // a chance at a free transaction.
                    // But mempool inputs might still be in the mempool, so their age stays 0
                    int age = pcoin.first->GetDepthInMainChain();
                    assert(age >= 0);
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age;
                }

                const CAmount nChange = nValueIn - nValueToSelect;
                if (nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-ecc-address
                    CScript scriptChange;
                    if (gArgs.GetBoolArg("-returnchange", DEFAULT_RETURN_CHANGE))
                    {
                        std::map<CTxDestination, CAmount> balances = GetAddressBalances();
                        if (balances.size() < 1)
                        {
                            // if we are in here, something went wrong with getting the address balance map so we should
                            // default to generating a new key
                            /// this is the same behavior if -returnchange was false
                            CPubKey vchPubKey;
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey);
                            assert(ret); // should never fail, as we just unlocked

                            scriptChange = GetScriptForDestination(vchPubKey.GetID());
                        }
                        else
                        {
                            CTxDestination highestAddr;
                            CAmount highestValue = 0;
                            // make sure it is always at least an address, this is just a saftey
                            highestAddr = balances.begin()->first;
                            for (std::map<CTxDestination, CAmount>::iterator it = balances.begin();
                                 it != balances.end(); ++it)
                            {
                                if (it->second > highestValue)
                                {
                                    highestValue = it->second;
                                    highestAddr = it->first;
                                }
                            }
                            scriptChange = GetScriptForDestination(highestAddr);
                        }
                    }
                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        bool ret;
                        ret = reservekey.GetReservedKey(vchPubKey);
                        assert(ret); // should never fail, as we just unlocked

                        scriptChange = GetScriptForDestination(vchPubKey.GetID());
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust())
                    {
                        CAmount nDust = newTxOut.GetDustThreshold() - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust())
                                {
                                    strFailReason =
                                        "The transaction amount is too small to send after the fee has been deducted";
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee.
                    if (newTxOut.IsDust())
                    {
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        // Insert change txn at random position:
                        nChangePosRet = GetRandInt(txNew.vout.size() + 1);
                        std::vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosRet;
                        txNew.vout.insert(position, newTxOut);
                    }
                }
                else
                    reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                for (auto const &coin : setCoins)
                {
                    txNew.vin.push_back(CTxIn(coin.first->tx->GetHash(), coin.second, CScript(),
                        std::numeric_limits<unsigned int>::max() - 1));
                }

                // Sign
                int nIn = 0;
                CTransaction txNewConst(txNew);
                for (auto const &coin : setCoins)
                {
                    bool signSuccess;
                    const CScript &scriptPubKey = coin.first->tx->vout[coin.second].scriptPubKey;
                    CScript &scriptSigRes = txNew.vin[nIn].scriptSig;
                    if (sign)
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, SIGHASH_ALL),
                            scriptPubKey, scriptSigRes);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, scriptSigRes);

                    if (!signSuccess)
                    {
                        strFailReason = ("Signing transaction failed");
                        return false;
                    }
                    nIn++;
                }

                unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign)
                {
                    for (auto &_vin : txNew.vin)
                    {
                        _vin.scriptSig = CScript();
                    }
                }

                // Embed the constructed transaction data in wtxNew.
                wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));

                // Limit size
                if (nBytes >= MAX_STANDARD_TX_SIZE)
                {
                    strFailReason = ("Transaction too large");
                    return false;
                }

                dPriority = wtxNew.tx->ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
                {
                    // Require at least hard-coded AllowFree.
                    if (AllowFree(dPriority))
                    {
                        break;
                    }
                }

                CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = ("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    return true;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx &wtxNew, CReserveKey &reservekey, CConnman *connman, CValidationState &state)
{
    if (fBroadcastTransactions)
    {
        // Broadcast
        if (!wtxNew.AcceptToMemoryPool(false))
        {
            // This must not fail. The transaction has already been signed and recorded.
            LogPrintf("CommitTransaction(): Error: Transaction not valid\n");
            return false;
        }
    }

    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction:\n%s", wtxNew.tx->ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB *pwalletdb = fFileBacked ? new CWalletDB(strWalletFile, "r+") : NULL;

            // Take key pair from key pool so it won't be used again
            reservekey.KeepKey();

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew, false, pwalletdb);

            // Notify that old coins are spent
            std::set<CWalletTx *> setCoins;
            for (auto const &txin : wtxNew.tx->vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.tx->GetHash()] = 0;

        if (fBroadcastTransactions)
        {
            SyncWithWallets(wtxNew.tx, nullptr, -1);
            wtxNew.RelayWalletTransaction(connman);
        }
    }
    return true;
}

CAmount CWallet::GetRequiredFee(unsigned int nTxBytes)
{
    return std::max(minTxFee.GetFee(nTxBytes), ::minRelayTxFee.GetFee(nTxBytes));
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool &pool)
{
    // payTxFee is user-set "I want to pay this much"
    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
    // User didn't set: use -txconfirmtarget to estimate...
    if (nFeeNeeded == 0)
    {
        nFeeNeeded = pool.estimateFee(nConfirmTarget).GetFee(nTxBytes);
        // ... unless we don't have enough mempool data for estimatefee, then use fallbackFee
        if (nFeeNeeded == 0)
            nFeeNeeded = fallbackFee.GetFee(nTxBytes);
    }
    // prevent user from paying a fee below minRelayTxFee or minTxFee
    nFeeNeeded = std::max(nFeeNeeded, GetRequiredFee(nTxBytes));
    // But always obey the maximum
    if (nFeeNeeded > maxTxFee)
        nFeeNeeded = maxTxFee;
    return nFeeNeeded;
}


DBErrors CWallet::LoadWallet(bool &fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile, "cr+").LoadWallet(this);
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    return DB_LOAD_OK;
}


DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx> &vWtx)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile, "cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination &address, const std::string &strType)
{
    {
        LOCK(cs_wallet); // mapAddressBook
        if (!strType.empty()) /* update purpose only if requested */
            mapAddressBook[address].type = strType;
    }
    if (!fFileBacked)
        return false;
    if (!strType.empty() && !CWalletDB(strWalletFile).WritePurpose(CBitcoinAddress(address).ToString(), strType))
        return false;
    return CWalletDB(strWalletFile).WriteName(CBitcoinAddress(address).ToString());
}

bool CWallet::AddressIsMine(const CTxDestination &address)
{
    isminetype mine = ::IsMine(*this, address);
    return (mine == ISMINE_SPENDABLE);
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        for (auto nIndex : setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked() || fAllowKeypoolRefills == false)
            return false;

        int64_t nKeys = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i + 1;
            walletdb.WritePool(nIndex, CKeyPoolEntry(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        LogPrintf("CWallet::NewKeyPool wrote %d new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t)0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPoolEntry(GenerateNewKey())))
                throw std::runtime_error("TopUpKeyPool(): writing generated key failed");
            setKeyPool.insert(nEnd);
            LogPrint("wallet", "keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t &nIndex, CKeyPoolEntry &keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked() && fAllowKeypoolRefills == true)
            TopUpKeyPool();

        // Get the oldest key
        if (setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw std::runtime_error("ReserveKeyFromKeyPool(): read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw std::runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        LogPrint("wallet", "keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    LogPrint("wallet", "keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    LogPrint("wallet", "keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey &result)
{
    int64_t nIndex = 0;
    CKeyPoolEntry keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (IsLocked() || fAllowKeypoolRefills == false)
            {
                return false;
            }
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPoolEntry keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    std::map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        for (auto walletEntry : mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!CheckFinalTx(*(pcoin->tx)) || !pcoin->IsTrusted())
                continue;

            if (pcoin->tx->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->tx->vout[i]))
                    continue;
                if (!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->tx->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

std::set<std::set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    std::set<std::set<CTxDestination> > groupings;
    std::set<CTxDestination> grouping;

    for (auto walletEntry : mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->tx->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            for (auto txin : pcoin->tx->vin)
            {
                CTxDestination address;
                if (!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if (!ExtractDestination(mapWallet[txin.prevout.hash].tx->vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
                for (auto txout : pcoin->tx->vout)
                    if (IsChange(txout))
                    {
                        CTxDestination txoutAddr;
                        if (!ExtractDestination(txout.scriptPubKey, txoutAddr))
                            continue;
                        grouping.insert(txoutAddr);
                    }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++)
            if (IsMine(pcoin->tx->vout[i]))
            {
                CTxDestination address;
                if (!ExtractDestination(pcoin->tx->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    std::set<std::set<CTxDestination> *> uniqueGroupings; // a set of pointers to groups of addresses
    std::map<CTxDestination, std::set<CTxDestination> *> setmap; // map addresses to the unique group containing it
    for (auto _grouping : groupings)
    {
        // make a set of all the groups hit by this new group
        std::set<std::set<CTxDestination> *> hits;
        std::map<CTxDestination, std::set<CTxDestination> *>::iterator it;
        for (auto address : _grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        std::set<CTxDestination> *merged = new std::set<CTxDestination>(_grouping);
        for (auto *hit : hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        for (auto element : *merged)
            setmap[element] = merged;
    }

    std::set<std::set<CTxDestination> > ret;
    for (auto *uniqueGrouping : uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

bool CReserveKey::GetReservedKey(CPubKey &pubkey)
{
    if (nIndex == -1)
    {
        CKeyPoolEntry keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else
        {
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(std::set<CKeyID> &setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK(cs_wallet);
    for (auto const &id : setKeyPool)
    {
        CKeyPoolEntry keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw std::runtime_error("GetAllReserveKeyHashes(): read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw std::runtime_error("GetAllReserveKeyHashes(): unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::GetScriptForMining(boost::shared_ptr<CReserveScript> &script)
{
    boost::shared_ptr<CReserveKey> rKey(new CReserveKey(this));
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    script->reserveScript = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
}

void CWallet::LockCoin(COutPoint &output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(COutPoint &output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint> &vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin(); it != setLockedCoins.end(); it++)
    {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void>
{
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn)
        : keystore(keystoreIn), vKeys(vKeysIn)
    {
    }

    void Process(const CScript &script)
    {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired))
        {
            for (auto const &dest : vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId)
    {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CScriptID &scriptId)
    {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CNoDestination &none) {}
};

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    // the tip can be reorganised; use a 144-block safety margin
    CBlockIndex *pindexMax =
        pnetMan->getChainActive()->chainActive[std::max(0, pnetMan->getChainActive()->chainActive.Height() - 144)];
    std::map<CKeyID, CBlockIndex *> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    for (auto const &keyid : setKeys)
    {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++)
    {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(wtx.hashBlock);
        if (pindex && pnetMan->getChainActive()->chainActive.Contains(pindex))
        {
            // ... which are already in a block
            int nHeight = pindex->nHeight;
            for (auto const &txout : wtx.tx->vout)
            {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                for (auto const &keyid : vAffected)
                {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex *>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->nHeight)
                        rit->second = pindex;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex *>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end();
         it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

CKeyPoolEntry::CKeyPoolEntry() { nTime = GetTime(); }
CKeyPoolEntry::CKeyPoolEntry(const CPubKey &vchPubKeyIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

int CMerkleTx::SetMerkleBranch(const CBlock &block)
{
    // Update the tx's hashBlock
    hashBlock = block.GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)block.vtx.size(); nIndex++)
    {
        if (block.vtx[nIndex]->GetHash() == this->tx->GetHash())
        {
            break;
        }
    }
    if (nIndex == (int)block.vtx.size())
    {
        nIndex = -1;
        LogPrintf("ERROR: SetMerkleBranch(): couldn't find tx in block\n");
        return 0;
    }

    // Is the tx in a block that's in the main chain
    RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
    const CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(hashBlock);
    if (!pindex || !pnetMan->getChainActive()->chainActive.Contains(pindex))
    {
        return 0;
    }
    return pnetMan->getChainActive()->chainActive.Height() - pindex->nHeight + 1;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex *&pindexRet) const
{
    if (hashUnset())
    {
        return 0;
    }
    // Find the block it claims to be in
    CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(hashBlock);
    {
        RECURSIVEREADLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);
        if (!pindex || !pnetMan->getChainActive()->chainActive.Contains(pindex))
        {
            return 0;
        }
    }
    pindexRet = pindex;
    return ((nIndex == -1) ? (-1) : 1) * (pnetMan->getChainActive()->chainActive.Height() - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!tx->IsCoinBase() && !tx->IsCoinStake())
        return 0;
    return std::max(0, (COINBASE_MATURITY + 1) - GetDepthInMainChain());
}

bool CMerkleTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectAbsurdFee)
{
    CValidationState state;
    return ::AcceptToMemoryPool(mempool, state, tx, fLimitFree, NULL, false, fRejectAbsurdFee);
}

bool CWallet::SelectCoinsMinConf(CAmount nTargetValue,
    unsigned int nSpendTime,
    int nConfMine,
    int nConfTheirs,
    std::vector<COutput> vCoins,
    std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet,
    int64_t &nValueRet) const
{
    setCoinsRet.clear();
    nValueRet = 0;

    // List of values less than target
    std::pair<int64_t, std::pair<const CWalletTx *, unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<int64_t>::max();
    coinLowestLarger.second.first = NULL;
    std::vector<std::pair<int64_t, std::pair<const CWalletTx *, unsigned int> > > vValue;
    int64_t nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    for (auto output : vCoins)
    {
        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (IsFromMe(*(pcoin->tx)) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;

        // Follow the timestamp rules
        if (pcoin->tx->nTime > nSpendTime)
            continue;

        int64_t n = pcoin->tx->vout[i].nValue;

        std::pair<int64_t, std::pair<const CWalletTx *, unsigned int> > coin =
            std::make_pair(n, std::make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        return true;
    }

    // Solve subset sum by stochastic approximation
    std::sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    std::vector<char> vfBest;
    int64_t nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
    }
    else
    {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
            }

        if (gArgs.GetBoolArg("-printpriority", false))
        {
            //// debug print
            LogPrintf("SelectCoins() best subset: ");
            for (unsigned int i = 0; i < vValue.size(); i++)
                if (vfBest[i])
                    LogPrintf("%s ", FormatMoney(vValue[i].first).c_str());
            LogPrintf("total %s\n", FormatMoney(nBest).c_str());
        }
    }

    return true;
}

bool CWallet::SelectCoins(CAmount nTargetValue,
    unsigned int nSpendTime,
    std::set<std::pair<const CWalletTx *, unsigned int> > &setCoinsRet,
    int64_t &nValueRet) const
{
    std::vector<COutput> vCoins;
    AvailableCoins(vCoins, true);

    return (SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 6, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 1, 1, vCoins, setCoinsRet, nValueRet) ||
            SelectCoinsMinConf(nTargetValue, nSpendTime, 0, 1, vCoins, setCoinsRet, nValueRet));
}

// ppcoin: create coin stake transaction
bool CWallet::CreateCoinStake(const CKeyStore &keystore,
    unsigned int nBits,
    int64_t nSearchInterval,
    CTransaction &txNew)
{
    // The following split & combine thresholds are important to security
    // Should not be adjusted if you don't understand the consequences
    static unsigned int nStakeSplitAge = (60 * 60 * 24 * 30);
    const CBlockIndex *pIndex0 = GetLastBlockIndex(pnetMan->getChainActive()->chainActive.Tip(), false);
    int64_t nCombineThreshold = 0;
    if (pIndex0->pprev)
        nCombineThreshold =
            GetProofOfWorkReward(pIndex0->nHeight, DEFAULT_TRANSACTION_MINFEE, pIndex0->pprev->GetBlockHash()) / 3;

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);

    txNew.vin.clear();
    txNew.vout.clear();
    // Mark coin stake transaction
    CScript scriptEmpty;
    scriptEmpty.clear();
    txNew.vout.push_back(CTxOut(0, scriptEmpty));
    // Choose coins to use
    CAmount nBalance = GetBalance();
    CAmount nReserveBalance = 0;
    if (gArgs.IsArgSet("-reservebalance") && !ParseMoney(gArgs.GetArg("-reservebalance", ""), nReserveBalance))
        return error("CreateCoinStake : invalid reserve balance amount");
    if (nBalance <= nReserveBalance)
        return false;

    std::set<std::pair<const CWalletTx *, unsigned int> > setCoins;
    std::vector<const CWalletTx *> vwtxPrev;
    int64_t nValueIn = 0;
    if (!SelectCoins(nBalance - nReserveBalance, txNew.nTime, setCoins, nValueIn))
        return false;

    if (setCoins.empty())
        return false;

    int64_t nCredit = 0;
    CScript scriptPubKeyKernel;
    bool fKernelFound = false;
    for (auto pcoin : setCoins)
    {
        CDiskTxPos txindex;
        {
            LOCK2(cs_main, cs_wallet);
            if (!pblocktree->ReadTxIndex(pcoin.first->tx->GetHash(), txindex))
                continue;
        }

        // Read block header
        CBlock block;
        {
            CDiskBlockPos blockPos(txindex.nFile, txindex.nPos);
            if (!ReadBlockFromDisk(block, blockPos, pnetMan->getActivePaymentNetwork()->GetConsensus()))
                continue;
        }

        static int nMaxStakeSearchInterval = 60;

        // LogPrintf(">> block.GetBlockTime() = %"PRI64d", nStakeMinAge = %d, txNew.nTime = %d\n", block.GetBlockTime(),
        // nStakeMinAge,txNew.nTime);
        if (block.GetBlockTime() + pnetMan->getActivePaymentNetwork()->getStakeMinAge() >
            txNew.nTime - nMaxStakeSearchInterval)
            continue; // only count coins meeting min age requirement

        {
            // LogPrintf(">> In.....\n");
            // Search backward in time from the given txNew timestamp
            // Search nSearchInterval seconds back up to nMaxStakeSearchInterval
            uint256 hashProofOfStake;
            hashProofOfStake.SetNull();
            COutPoint prevoutStake = COutPoint(pcoin.first->tx->GetHash(), pcoin.second);
            if (CheckStakeKernelHash(pnetMan->getChainActive()->chainActive.Tip()->nHeight + 1, block,
                    txindex.nTxOffset, *(pcoin.first->tx), prevoutStake, txNew.nTime, hashProofOfStake))
            {
                // Found a kernel
                LogPrint("wallet", "CreateCoinStake : kernel found\n");
                std::vector<std::vector<unsigned char> > vSolutions;
                txnouttype whichType;
                CScript scriptPubKeyOut;
                scriptPubKeyKernel = pcoin.first->tx->vout[pcoin.second].scriptPubKey;
                if (!Solver(scriptPubKeyKernel, whichType, vSolutions))
                {
                    LogPrint("wallet", "CreateCoinStake : failed to parse kernel\n");
                    break;
                }
                LogPrint("wallet", "CreateCoinStake : parsed kernel type=%d\n", whichType);
                if (whichType != TX_PUBKEY && whichType != TX_PUBKEYHASH)
                {
                    LogPrint("wallet", "CreateCoinStake : no support for kernel type=%d\n", whichType);
                    break; // only support pay to public key and pay to address
                }
                if (whichType == TX_PUBKEYHASH) // pay to address type
                {
                    // convert to pay to public key type
                    CKey key;
                    if (!keystore.GetKey(uint160(vSolutions[0]), key))
                    {
                        LogPrint("wallet", "CreateCoinStake : failed to get key for kernel type=%d\n", whichType);
                        break; // unable to find corresponding public key
                    }
                    scriptPubKeyOut << key.GetPubKey() << OP_CHECKSIG;
                }
                else
                    scriptPubKeyOut = scriptPubKeyKernel;

                txNew.vin.push_back(CTxIn(pcoin.first->tx->GetHash(), pcoin.second));
                nCredit += pcoin.first->tx->vout[pcoin.second].nValue;
                vwtxPrev.push_back(pcoin.first);
                txNew.vout.push_back(CTxOut(0, scriptPubKeyOut));
                if (block.GetBlockTime() + nStakeSplitAge > txNew.nTime)
                    txNew.vout.push_back(CTxOut(0, scriptPubKeyOut)); // split stake

                LogPrint("wallet", "CreateCoinStake : added kernel type=%d\n", whichType);
                fKernelFound = true;
                break;
            }
        }
        if (fKernelFound)
            break; // if kernel is found stop searching
    }
    if (!fKernelFound)
    {
        return false;
    }
    if (nCredit == 0 || nCredit > nBalance - nReserveBalance)
    {
        // LogPrintf(">> Wallet: CreateCoinStake: nCredit = %"PRId64", nBalance = %"PRId64", nReserveBalance =
        // %"PRId64"\n", nCredit, nBalance, nReserveBalance);
        return false;
    }

    for (auto pcoin : setCoins)
    {
        // Attempt to add more inputs
        // Only add coins of the same key/address as kernel
        if (txNew.vout.size() == 2 &&
            ((pcoin.first->tx->vout[pcoin.second].scriptPubKey == scriptPubKeyKernel ||
                pcoin.first->tx->vout[pcoin.second].scriptPubKey == txNew.vout[1].scriptPubKey)) &&
            pcoin.first->tx->GetHash() != txNew.vin[0].prevout.hash)
        {
            // Stop adding more inputs if already too many inputs
            if (txNew.vin.size() >= 100)
                break;
            // Stop adding more inputs if value is already pretty significant
            if (nCredit > nCombineThreshold)
                break;
            // Stop adding inputs if reached reserve limit
            if (nCredit + pcoin.first->tx->vout[pcoin.second].nValue > nBalance - nReserveBalance)
                break;
            // Do not add additional significant input
            if (pcoin.first->tx->vout[pcoin.second].nValue > nCombineThreshold)
                continue;
            // Do not add input that is still too young
            /// using stake max age here isnt a bug, its a feature i swear
            /// TODO fix that - 2017/10/29
            if (pcoin.first->tx->nTime + pnetMan->getActivePaymentNetwork()->getStakeMaxAge() > txNew.nTime)
                continue;
            txNew.vin.push_back(CTxIn(pcoin.first->tx->GetHash(), pcoin.second));
            nCredit += pcoin.first->tx->vout[pcoin.second].nValue;
            vwtxPrev.push_back(pcoin.first);
        }
    }
    // Calculate coin age reward
    {
        uint64_t nCoinAge;
        const CBlockIndex *_pIndex0 = GetLastBlockIndex(pnetMan->getChainActive()->chainActive.Tip(), false);

        if (!txNew.GetCoinAge(nCoinAge))
        {
            return error("CreateCoinStake : failed to calculate coin age");
        }

        int64_t nCreditReward = GetProofOfStakeReward(txNew.GetCoinAge(nCoinAge, true), _pIndex0->nHeight);
        LogPrintf("nCreditReward create=%d \n", nCreditReward);
        nCredit = nCredit + nCreditReward;
    }
    // Set output amount
    if (txNew.vout.size() == 3)
    {
        txNew.vout[1].nValue = nCredit / 2;
        txNew.vout[2].nValue = nCredit - txNew.vout[1].nValue;
    }
    else
        txNew.vout[1].nValue = nCredit;
    // Sign
    int nIn = 0;
    for (auto const *pcoin : vwtxPrev)
    {
        if (!SignSignature(*this, *(pcoin->tx), txNew, nIn++))
            return error("CreateCoinStake : failed to sign coinstake");
    }

    // Limit size
    unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
    if (nBytes >= MAX_BLOCK_SIZE / 10)
        return error("CreateCoinStake : exceeded coinstake size limit");

    // Successfully generated coinstake
    return true;
}


bool static UIError(const std::string &str)
{
    LogPrintf("Wallet Error: %s\n", str.c_str());
    return false;
}

void static UIWarning(const std::string &str) { LogPrintf("Wallet Warning: %s\n", str.c_str()); }
bool CWallet::InitLoadWallet()
{
    std::string walletFile = gArgs.GetArg("-wallet", DEFAULT_WALLET_DAT);
    fAllowKeypoolRefills = gArgs.GetBoolArg("-allownewkeys", DEFAULT_ALLOW_KEYPOOL_REFILLS);

    // needed to restore wallet transaction meta data after -zapwallettxes
    std::vector<CWalletTx> vWtx;

    if (gArgs.GetBoolArg("-zapwallettxes", false))
    {
        LogPrintf("Zapping all transactions from wallet...\n");

        CWallet *tempWallet = new CWallet(walletFile);
        DBErrors nZapWalletRet = tempWallet->ZapWalletTx(vWtx);
        if (nZapWalletRet != DB_LOAD_OK)
        {
            return UIError(strprintf(("Error loading %s: Wallet corrupted"), walletFile));
        }

        delete tempWallet;
        tempWallet = nullptr;
    }

    LogPrintf("Loading wallet...");

    int64_t nStart = GetTimeMillis();
    bool fFirstRun = true;
    CWallet *walletInstance = new CWallet(walletFile);
    DBErrors nLoadWalletRet = walletInstance->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
        {
            return UIError(strprintf(("Error loading %s: Wallet corrupted"), walletFile));
        }
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            UIWarning(strprintf(("Error reading %s! All keys read correctly, but transaction data"
                                 " or address book entries might be missing or incorrect."),
                walletFile));
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
        {
            return UIError(
                strprintf(("Error loading %s: Wallet requires newer version of %s"), walletFile, PACKAGE_NAME));
        }
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            return UIError(strprintf(("Wallet needed to be rewritten: restart %s to complete"), PACKAGE_NAME));
        }
        else
        {
            return UIError(strprintf(("Error loading %s"), walletFile));
        }
    }

    if (gArgs.GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = gArgs.GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = WALLET_VERSION;
            walletInstance->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
        {
            LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        }
        if (nMaxVersion < walletInstance->GetVersion())
        {
            return UIError(("Cannot downgrade wallet"));
        }
        walletInstance->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();

        CPubKey newDefaultKey;
        if (walletInstance->GetKeyFromPool(newDefaultKey))
        {
            walletInstance->SetDefaultKey(newDefaultKey);
            if (!walletInstance->SetAddressBook(walletInstance->vchDefaultKey.GetID(), AddressBookType::RECEIVE))
                return UIError("Cannot write default address \n");
        }

        walletInstance->SetBestChain(pnetMan->getChainActive()->chainActive.GetLocator());
    }
    LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);
    RegisterValidationInterface(walletInstance);
    CBlockIndex *pindexRescan = pnetMan->getChainActive()->chainActive.Tip();
    if (gArgs.GetBoolArg("-rescan", false))
        pindexRescan = pnetMan->getChainActive()->chainActive.Genesis();
    else
    {
        CWalletDB walletdb(walletFile);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan =
                pnetMan->getChainActive()->FindForkInGlobalIndex(pnetMan->getChainActive()->chainActive, locator);
        else
            pindexRescan = pnetMan->getChainActive()->chainActive.Genesis();
    }
    if (pnetMan->getChainActive()->chainActive.Tip() && pnetMan->getChainActive()->chainActive.Tip() != pindexRescan)
    {
        LogPrintf("Rescanning last %i blocks (from block %i)...\n",
            pnetMan->getChainActive()->chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        walletInstance->ScanForWalletTransactions(pindexRescan, true);
        LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
        walletInstance->SetBestChain(pnetMan->getChainActive()->chainActive.GetLocator());
        nWalletDBUpdated++;

        // Restore wallet transaction metadata after -zapwallettxes=1
        if (gArgs.GetBoolArg("-zapwallettxes", false) && gArgs.GetArg("-zapwallettxes", "1") != "2")
        {
            CWalletDB walletdb(walletFile);

            for (const CWalletTx &wtxOld : vWtx)
            {
                uint256 hash = wtxOld.tx->GetHash();
                std::map<uint256, CWalletTx>::iterator mi = walletInstance->mapWallet.find(hash);
                if (mi != walletInstance->mapWallet.end())
                {
                    const CWalletTx *copyFrom = &wtxOld;
                    CWalletTx *copyTo = &mi->second;
                    copyTo->mapValue = copyFrom->mapValue;
                    copyTo->vOrderForm = copyFrom->vOrderForm;
                    copyTo->nTimeReceived = copyFrom->nTimeReceived;
                    copyTo->nTimeSmart = copyFrom->nTimeSmart;
                    copyTo->fFromMe = copyFrom->fFromMe;
                    copyTo->strFromAccount = copyFrom->strFromAccount;
                    copyTo->nOrderPos = copyFrom->nOrderPos;
                    copyTo->WriteToDisk(&walletdb);
                }
            }
        }
    }
    walletInstance->SetBroadcastTransactions(gArgs.GetBoolArg("-walletbroadcast", DEFAULT_WALLETBROADCAST));

    pwalletMain = walletInstance;
    return true;
}
