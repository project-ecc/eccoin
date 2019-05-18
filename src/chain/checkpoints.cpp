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

#include "checkpoints.h"

#include "chain.h"
#include "init.h"
#include "main.h"
#include "networks/networktemplate.h"
#include "uint256.h"

#include <boost/foreach.hpp>
#include <stdint.h>

namespace Checkpoints
{
int GetTotalBlocksEstimate(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    if (checkpoints.empty())
        return 0;

    return checkpoints.rbegin()->first;
}

CBlockIndex *GetLastCheckpoint(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    BOOST_REVERSE_FOREACH (const MapCheckpoints::value_type &i, checkpoints)
    {
        const uint256 &hash = i.second;
        CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(hash);
        if (pindex)
        {
            return pindex;
        }
    }
    return nullptr;
}

} // namespace Checkpoints
