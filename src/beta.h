// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_BETA_H
#define ECCOIN_BETA_H

#include <atomic>

static const bool DEFAULT_BETA_ENABLED = false;

extern std::atomic<bool> fBeta;

bool IsBetaEnabled();

#endif
