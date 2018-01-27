// Copyright (c) 2017 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MESSAGES_H
#define MESSAGES_H

#include "net.h"
#include "chain/blockindex.h"

extern std::unique_ptr<CRollingBloomFilter> recentRejects;

/** Process protocol messages received from a given node */
bool ProcessMessages(CNode* pfrom);

/**
 * Send queued protocol messages to be sent to a give node.
 *
 * @param[in]   pto             The node which we are sending messages to.
 */
bool SendMessages(CNode* pto);

/** Returns a bool indicating whether we requested this block. If we did request it, marks it as receieved and removes block from in flight list*/
bool MarkBlockAsReceived(const uint256& hash);

CBlockIndex* LastCommonAncestor(CBlockIndex* pa, CBlockIndex* pb);

#endif // MESSAGES_H
