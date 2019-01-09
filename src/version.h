/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
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

#ifndef BITCOIN_VERSION_H
#define BITCOIN_VERSION_H

/**
 * network protocol versioning
 */


static const int PROTOCOL_VERSION = 60039;

// earlier versions not supported as of Feb 2012, and are disconnected
static const int MIN_PROTO_VERSION = 60037;

// "sendheaders" command and announcing blocks with headers starts with this version
static const int SENDHEADERS_VERSION = 60035;

//! In this version, 'getheaders' was introduced.
static const int GETHEADERS_VERSION = 60035;

//! "filter*" commands are disabled without NODE_BLOOM after and including this version
static const int NO_BLOOM_VERSION = 60034;

/**
 * Versioning for network services
 */

 #define NETWORK_SERVICE_VERSION_MAJOR 0
 #define NETWORK_SERVICE_VERSION_MINOR 1
 #define NETWORK_SERVICE_VERSION_REVISION 0

// version of the service transaction resolution code
static const int NETWORK_SERVICE_VERSION =  10000 * NETWORK_SERVICE_VERSION_MAJOR +
                                            100 * NETWORK_SERVICE_VERSION_MINOR +
                                            1 * NETWORK_SERVICE_VERSION_REVISION;

#endif // BITCOIN_VERSION_H
