// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>

#include "chain/tx.h"
#include "consensus/validation.h"

class CBlock;
struct CBlockLocator;
class CBlockIndex;
class CConnman;
class CReserveScript;
class CTransaction;
class CValidationInterface;
class CValidationState;
class uint256;

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface *pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface *pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();
/** Push an updated transaction to all registered wallets, pass NULL if block not known, pass -1 if txIdx not known */
void SyncWithWallets(const CTransactionRef &ptx, const CBlock *pblock, int txIdx);

class CValidationInterface
{
protected:
    virtual void UpdatedBlockTip(const CBlockIndex *pindex) {}
    virtual void SyncTransaction(const CTransactionRef &ptx, const CBlock *pblock, int txIdx) {}
    virtual void SetBestChain(const CBlockLocator &locator) {}
    virtual void Inventory(const uint256 &hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman *connman) {}
    virtual void BlockChecked(const CBlock &, const CValidationState &) {}
    virtual void GetScriptForMining(boost::shared_ptr<CReserveScript> &){};
    virtual void NewPoWValidBlock(CBlockIndex *pindex, const CBlock *block) {}
    virtual void SystemMessage(const std::string &message) {}
    virtual void PacketComplete(const uint8_t nProtocolId) {}
    friend void ::RegisterValidationInterface(CValidationInterface *);
    friend void ::UnregisterValidationInterface(CValidationInterface *);
    friend void ::UnregisterAllValidationInterfaces();
};

struct CMainSignals
{
    /** Notifies listeners of updated block chain tip */
    boost::signals2::signal<void(const CBlockIndex *)> UpdatedBlockTip;
    /** Notifies listeners of updated transaction data (transaction, and optionally the block it is found in. */
    boost::signals2::signal<void(const CTransactionRef &, const CBlock *, int txIndex)> SyncTransaction;
    /** Notifies listeners of a new active block chain. */
    boost::signals2::signal<void(const CBlockLocator &)> SetBestChain;
    /** Notifies listeners about an inventory item being seen on the network. */
    boost::signals2::signal<void(const uint256 &)> Inventory;
    /** Tells listeners to broadcast their data. */
    boost::signals2::signal<void(int64_t nBestBlockTime, CConnman *connman)> Broadcast;
    /** Notifies listeners of a block validation result */
    boost::signals2::signal<void(const CBlock &, const CValidationState &)> BlockChecked;
    /** Notifies listeners that a key for mining is required (coinbase) */
    boost::signals2::signal<void(boost::shared_ptr<CReserveScript> &)> ScriptForMining;
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated
     * yet.
     */
    boost::signals2::signal<void(CBlockIndex *, const CBlock *)> NewPoWValidBlock;
    /** Notifies listeners that a system message notification has been raised */
    boost::signals2::signal<void(const std::string &)> SystemMessage;
    /** Notifies listeners that a received packet is complete */
    boost::signals2::signal<void(const uint8_t)> PacketComplete;
};

CMainSignals &GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
