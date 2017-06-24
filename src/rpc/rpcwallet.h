#ifndef WALLET_H
#define WALLET_H

#include "crpc.h"
#include "jsonrpc.h"
#include <string>

void EnsureWalletIsUnlocked();
std::string HelpRequiringPassphrase();


#endif // WALLET_H
