// This file is part of the Eccoin project
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_FS_H
#define ECCOIN_FS_H

#include <stdio.h>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/filesystem/detail/utf8_codecvt_facet.hpp>
#include <boost/filesystem/fstream.hpp>

/** Filesystem operations and types */
namespace fs = boost::filesystem;

/** Bridge operations to C stdio */
namespace fsbridge
{
FILE *fopen(const fs::path &p, const char *mode);
FILE *freopen(const fs::path &p, const char *mode, FILE *stream);
}

#endif // ECCOIN_FS_H
