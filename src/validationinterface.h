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

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <boost/signals2/signal.hpp>
#include <boost/shared_ptr.hpp>

#include "consensus/validation.h"
#include "tx/tx.h"

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

class CValidationInterface {
protected:
    virtual void UpdatedBlockTip(const CBlockIndex *pindexNew,
                                 const CBlockIndex *pindexFork,
                                 bool fInitialDownload) {}
    virtual void TransactionAddedToMempool(const CTransactionRef &ptxn) {}
    virtual void BlockConnected(const std::shared_ptr<const CBlock> &block,
                   const CBlockIndex *pindex, const std::vector<CTransactionRef> &txnConflicted) {}
    virtual void BlockDisconnected(const std::shared_ptr<const CBlock> &block) {}
    virtual void SetBestChain(const CBlockLocator &locator) {}
    virtual void Inventory(const uint256 &hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime, CConnman *connman) {}
    virtual void BlockChecked(const CBlock &, const CValidationState &) {}
    virtual void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock> &block){}
    friend void ::RegisterValidationInterface(CValidationInterface *);
    friend void ::UnregisterValidationInterface(CValidationInterface *);
    friend void ::UnregisterAllValidationInterfaces();
};

struct CMainSignals {
    /** Notifies listeners of updated block chain tip */
    boost::signals2::signal<void(const CBlockIndex *, const CBlockIndex *,
                                 bool fInitialDownload)>
        UpdatedBlockTip;
    /** Notifies listeners of a transaction having been added to mempool. */
    boost::signals2::signal<void(const CTransactionRef &)>
        TransactionAddedToMempool;
    /**
     * Notifies listeners of a block being connected.
     * Provides a vector of transactions evicted from the mempool as a result.
     */
    boost::signals2::signal<void(const std::shared_ptr<const CBlock> &,
                                 const CBlockIndex *pindex,
                                 const std::vector<CTransactionRef> &)>
        BlockConnected;
    /** Notifies listeners of a block being disconnected */
    boost::signals2::signal<void(const std::shared_ptr<const CBlock> &)>
        BlockDisconnected;
    /** Notifies listeners of a new active block chain. */
    boost::signals2::signal<void(const CBlockLocator &)> SetBestChain;
    /** Notifies listeners about an inventory item being seen on the network. */
    boost::signals2::signal<void(const uint256 &)> Inventory;
    /** Tells listeners to broadcast their data. */
    boost::signals2::signal<void(int64_t nBestBlockTime, CConnman *connman)>
        Broadcast;
    /** Notifies listeners of a block validation result */
    boost::signals2::signal<void(const CBlock &, const CValidationState &)>
        BlockChecked;
    /**
     * Notifies listeners that a block which builds directly on our current tip
     * has been received and connected to the headers tree, though not validated
     * yet.
     */
    boost::signals2::signal<void(const CBlockIndex *,
                                 const std::shared_ptr<const CBlock> &)>
        NewPoWValidBlock;
};

CMainSignals &GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
