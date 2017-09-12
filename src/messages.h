#ifndef MESSAGES_H
#define MESSAGES_H

#include "net.h"

bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto);
bool MarkBlockAsReceived(const uint256& hash);


#endif // MESSAGES_H
