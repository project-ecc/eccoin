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

/**
 * Versioning for network services
 */

#define NETWORK_SERVICE_VERSION_MAJOR 0
#define NETWORK_SERVICE_VERSION_MINOR 1
#define NETWORK_SERVICE_VERSION_REVISION 0

// version of the service transaction resolution code
static const int NETWORK_SERVICE_VERSION =
    10000 * NETWORK_SERVICE_VERSION_MAJOR + 100 * NETWORK_SERVICE_VERSION_MINOR + 1 * NETWORK_SERVICE_VERSION_REVISION;

#endif // BITCOIN_VERSION_H
