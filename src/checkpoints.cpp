// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "txdb-leveldb.h"
#include "global.h"
#include "main.h"
#include "checkpoints.h"
#include "global.h"
#include "uint256.h"
#include "blockindex.h"
#include "chain.h"

bool Checkpoints::CheckHardened(int nHeight, const uint256& hash)
{
    MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
    if (i == checkpoints.end())
    {
        return true;
    }
    return hash == i->second;
}

int Checkpoints::GetTotalBlocksEstimate()
{
    MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    return checkpoints.rbegin()->first;
}

CBlockIndex* Checkpoints::GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
{
    MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

    BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
    {
        const uint256& hash = i.second;
        std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
        if (t != mapBlockIndex.end())
            return t->second;
    }
    return NULL;
}
