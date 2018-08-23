/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef TXVALIDATION_H
#define TXVALIDATION_H

#include "chain/tx.h"
#include "services/servicetx.h"
#include "validationinterface.h"

/** Context-independent validity checks */
bool CheckTransaction(const CTransaction& tx, CValidationState& state);

bool CheckServiceTransaction(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state);
void ProcessServiceCommand(const CServiceTransaction &stx, const CTransaction& ptx, CValidationState &state, const CBlock* block = nullptr);

#endif // TXVALIDATION_H
