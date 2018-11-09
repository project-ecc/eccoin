/*
 * This file is part of the Eccoin project
 * Copyright (c) 2014-2017 The Bitcoin Core developers
 * Copyright (c) 20117-2018 The Eccoin developers
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

#ifndef BITCOIN_COMPAT_BYTESWAP_H
#define BITCOIN_COMPAT_BYTESWAP_H

#include <stdint.h>

#if defined(HAVE_BYTESWAP_H)
#include <byteswap.h>
#endif

#if HAVE_DECL_BSWAP_16 == 0
inline uint16_t bswap_16(uint16_t x) { return (x >> 8) | ((x & 0x00ff) << 8); }
#endif // HAVE_DECL_BSWAP16

#if HAVE_DECL_BSWAP_32 == 0
inline uint32_t bswap_32(uint32_t x)
{
    return (
        ((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >> 8) | ((x & 0x0000ff00U) << 8) | ((x & 0x000000ffU) << 24));
}
#endif // HAVE_DECL_BSWAP32

#if HAVE_DECL_BSWAP_64 == 0
inline uint64_t bswap_64(uint64_t x)
{
    return (((x & 0xff00000000000000ull) >> 56) | ((x & 0x00ff000000000000ull) >> 40) |
            ((x & 0x0000ff0000000000ull) >> 24) | ((x & 0x000000ff00000000ull) >> 8) |
            ((x & 0x00000000ff000000ull) << 8) | ((x & 0x0000000000ff0000ull) << 24) |
            ((x & 0x000000000000ff00ull) << 40) | ((x & 0x00000000000000ffull) << 56));
}
#endif // HAVE_DECL_BSWAP64

#endif // BITCOIN_COMPAT_BYTESWAP_H
