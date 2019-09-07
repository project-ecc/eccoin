// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "beta.h"

std::atomic<bool> fBeta{DEFAULT_BETA_ENABLED};

bool IsBetaEnabled()
{
    return fBeta.load();
}
