// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <inttypes.h>

/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const uint64_t MAX_BLOCK_SIZE = 1000000; // 1MB
static const uint64_t DEFTAUL_BLOCK_PRIORITY_SIZE = 100000; // 0.1MB
static const uint64_t DEFAULT_LARGEST_TRANSACTION = 1000000; // 1MB

static const int64_t nMaxClockDrift = 2 * 60 * 60; // two hours

/** The maximum allowed number of signature check operations in a block (network rule) */
static const uint64_t MAX_BLOCK_SIGOPS = MAX_BLOCK_SIZE / 50;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 30;

/** Flags for nSequence and nLockTime locks */
enum
{
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
