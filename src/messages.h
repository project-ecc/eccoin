#ifndef MESSAGES_H
#define MESSAGES_H

#include "net.h"
#include "chain/blockindex.h"

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
