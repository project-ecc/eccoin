// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2015-2018 The Bitcoin Unlimited developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zmqabstractnotifier.h"
#include "util/util.h"


CZMQAbstractNotifier::~CZMQAbstractNotifier() { assert(!psocket); }
bool CZMQAbstractNotifier::NotifyBlock(const CBlockIndex * /*CBlockIndex*/) { return true; }
bool CZMQAbstractNotifier::NotifyTransaction(const CTransactionRef & /*transaction*/) { return true; }
bool CZMQAbstractNotifier::NotifySystem(const std::string & /*message*/) { return true; }
bool CZMQAbstractNotifier::NotifyPacket(const uint8_t /*nProtocolId*/) { return true; }
