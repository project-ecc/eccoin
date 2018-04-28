/*
 * This file is part of the ECC project
 * Copyright (c) 2015-2017 The Bitcoin Core developers
 * Copyright (c) 2017-2018 The ECC developers
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

#ifndef BITCOIN_LIMITEDMAP_H
#define BITCOIN_LIMITEDMAP_H

#include <assert.h>
#include <map>

/** STL-like map container that only keeps the N elements with the highest value. */
template <typename K, typename V>
class limitedmap
{
public:
    typedef K key_type;
    typedef V mapped_type;
    typedef std::pair<const key_type, mapped_type> value_type;
    typedef typename std::map<K, V>::const_iterator const_iterator;
    typedef typename std::map<K, V>::size_type size_type;

protected:
    std::map<K, V> map;
    typedef typename std::map<K, V>::iterator iterator;
    std::multimap<V, iterator> rmap;
    typedef typename std::multimap<V, iterator>::iterator rmap_iterator;
    size_type nMaxSize;

public:
    limitedmap(size_type nMaxSizeIn)
    {
        assert(nMaxSizeIn > 0);
        nMaxSize = nMaxSizeIn;
    }
    const_iterator begin() const { return map.begin(); }
    const_iterator end() const { return map.end(); }
    size_type size() const { return map.size(); }
    bool empty() const { return map.empty(); }
    const_iterator find(const key_type& k) const { return map.find(k); }
    size_type count(const key_type& k) const { return map.count(k); }
    void insert(const value_type& x)
    {
        std::pair<iterator, bool> ret = map.insert(x);
        if (ret.second) {
            if (map.size() > nMaxSize) {
                map.erase(rmap.begin()->second);
                rmap.erase(rmap.begin());
            }
            rmap.insert(make_pair(x.second, ret.first));
        }
    }
    void erase(const key_type& k)
    {
        iterator itTarget = map.find(k);
        if (itTarget == map.end())
            return;
        std::pair<rmap_iterator, rmap_iterator> itPair = rmap.equal_range(itTarget->second);
        for (rmap_iterator it = itPair.first; it != itPair.second; ++it)
            if (it->second == itTarget) {
                rmap.erase(it);
                map.erase(itTarget);
                return;
            }
        // Shouldn't ever get here
        assert(0);
    }
    void update(const_iterator itIn, const mapped_type& v)
    {
        // TODO: When we switch to C++11, use map.erase(itIn, itIn) to get the non-const iterator.
        iterator itTarget = map.find(itIn->first);
        if (itTarget == map.end())
            return;
        std::pair<rmap_iterator, rmap_iterator> itPair = rmap.equal_range(itTarget->second);
        for (rmap_iterator it = itPair.first; it != itPair.second; ++it)
            if (it->second == itTarget) {
                rmap.erase(it);
                itTarget->second = v;
                rmap.insert(make_pair(v, itTarget));
                return;
            }
        // Shouldn't ever get here
        assert(0);
    }
    size_type max_size() const { return nMaxSize; }
    size_type max_size(size_type s)
    {
        assert(s > 0);
        while (map.size() > s) {
            map.erase(rmap.begin()->second);
            rmap.erase(rmap.begin());
        }
        nMaxSize = s;
        return nMaxSize;
    }
};

#endif // BITCOIN_LIMITEDMAP_H
