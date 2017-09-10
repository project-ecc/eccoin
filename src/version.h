// Copyright (c) 2012-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */


static const int PROTOCOL_VERSION = 60035;

// earlier versions not supported as of Feb 2012, and are disconnected
static const int MIN_PROTO_VERSION = 60035;

// "sendheaders" command and announcing blocks with headers starts with this version
static const int SENDHEADERS_VERSION = 60035;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 60035;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 60034;


#endif // BITCOIN_VERSION_H
