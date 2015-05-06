#ifndef MESSAGES_H
#define MESSAGES_H

#include "alert.h"
#include "bitcoinrpc.h"
#include "checkpoints.h"
#include "db.h"
#include "init.h"
#include "scrypt_kernel.h"
#include "main.h"
#include "net.h"
#include "txdb-leveldb.h"
#include "util.h"
#include "ui_interface.h"


unsigned char pchMessageStart[4] = { 0xce, 0xf1, 0xdb, 0xfa }; ///Scrypt

bool AlreadyHave(CTxDB& txdb, const CInv& inv);
bool ProcessMessages(CNode* pfrom);
bool SendMessages(CNode* pto, bool fSendTrickle);


#endif // MESSAGES_H
