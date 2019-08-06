// This file is part of the Eccoin project
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "fs.h"

#include <boost/filesystem.hpp>


namespace fsbridge
{
FILE *fopen(const fs::path &p, const char *mode) { return ::fopen(p.string().c_str(), mode); }
FILE *freopen(const fs::path &p, const char *mode, FILE *stream) { return ::freopen(p.string().c_str(), mode, stream); }
} // fsbridge
