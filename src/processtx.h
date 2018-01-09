// Copyright (c) 2017 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXVALIDATION_H
#define TXVALIDATION_H

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, CValidationState& state);

#endif // TXVALIDATION_H
