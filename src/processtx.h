// Copyright (c) 2017 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXVALIDATION_H
#define TXVALIDATION_H

#include "tx/tx.h"
#include "tx/servicetx.h"
#include "validationinterface.h"

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, CValidationState& state);

bool CheckServiceTransaction(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state);
void ProcessServiceCommand(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state, const CBlock* block = nullptr);

#endif // TXVALIDATION_H
