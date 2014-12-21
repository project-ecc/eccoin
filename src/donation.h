#ifndef DONATION_H
#define DONATION_H

#include "serialize.h"
#include "db.h"
#include "wallet.h"

extern std::map<uint256,double> ConfirmedBlocksWaitingOnDonate;
extern void CheckForStakedBlock();
extern double CalcDonationAmount();

#endif // DONATION_H
