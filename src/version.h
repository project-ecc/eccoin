// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */


static const int PROTOCOL_VERSION = 60040;

// earlier versions not supported as of Feb 2012, and are disconnected
static const int MIN_PROTO_VERSION = 60037;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 60034;

static const int NETWORK_SERVICE_PROTOCOL_VERSION = 60040;

/**
 * Versioning for network services
 */

#define MAJOR(major) 1000000 * major
#define MINOR(minor) 1000 * minor
#define REVISION(revision) 1 * revision

// version of the network service code
static const uint64_t NETWORK_SERVICE_VERSION = MAJOR(0) + MINOR(1) + REVISION(0);

// AODV routing for public routing ids was introduced in this network service version
static const uint64_t MIN_AODV_VERSION = MAJOR(0) + MINOR(1) + REVISION(0);

// This nodes AODV protocol version, this is unrelated to the network service version
static const uint64_t AODV_PROTOCOL_VERSION = MAJOR(0) + MINOR(1) + REVISION(1);


#endif // BITCOIN_VERSION_H
