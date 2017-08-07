#ifndef MESSAGES_H
#define MESSAGES_H

#include "net.h"

bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto);


#endif // MESSAGES_H
