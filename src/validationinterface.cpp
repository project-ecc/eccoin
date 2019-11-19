// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"

static CMainSignals g_signals;

CMainSignals &GetMainSignals() { return g_signals; }
void RegisterValidationInterface(CValidationInterface *pwalletIn)
{
    g_signals.UpdatedBlockTip.connect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1));
    g_signals.SyncTransaction.connect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.SetBestChain.connect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.BlockChecked.connect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.ScriptForMining.connect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.NewPoWValidBlock.connect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, _1, _2));
    g_signals.SystemMessage.connect(boost::bind(&CValidationInterface::SystemMessage, pwalletIn, _1));
    g_signals.PacketComplete.connect(boost::bind(&CValidationInterface::PacketComplete, pwalletIn, _1));
}

void UnregisterValidationInterface(CValidationInterface *pwalletIn)
{
    g_signals.BlockChecked.disconnect(boost::bind(&CValidationInterface::BlockChecked, pwalletIn, _1, _2));
    g_signals.ScriptForMining.disconnect(boost::bind(&CValidationInterface::GetScriptForMining, pwalletIn, _1));
    g_signals.Broadcast.disconnect(boost::bind(&CValidationInterface::ResendWalletTransactions, pwalletIn, _1, _2));
    g_signals.Inventory.disconnect(boost::bind(&CValidationInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CValidationInterface::SetBestChain, pwalletIn, _1));
    g_signals.SyncTransaction.connect(boost::bind(&CValidationInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.UpdatedBlockTip.disconnect(boost::bind(&CValidationInterface::UpdatedBlockTip, pwalletIn, _1));
    g_signals.NewPoWValidBlock.disconnect(boost::bind(&CValidationInterface::NewPoWValidBlock, pwalletIn, _1, _2));
    g_signals.SystemMessage.disconnect(boost::bind(&CValidationInterface::SystemMessage, pwalletIn, _1));
    g_signals.PacketComplete.disconnect(boost::bind(&CValidationInterface::PacketComplete, pwalletIn, _1));
}

void UnregisterAllValidationInterfaces()
{
    g_signals.BlockChecked.disconnect_all_slots();
    g_signals.ScriptForMining.disconnect_all_slots();
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
    g_signals.UpdatedBlockTip.disconnect_all_slots();
    g_signals.NewPoWValidBlock.disconnect_all_slots();
    g_signals.SystemMessage.disconnect_all_slots();
    g_signals.PacketComplete.disconnect_all_slots();
}

void SyncWithWallets(const CTransactionRef &ptx, const CBlock *pblock, int txIdx)
{
    g_signals.SyncTransaction(ptx, pblock, txIdx);
}
