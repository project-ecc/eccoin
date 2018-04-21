/*
 * This file is part of the ECC project
 * Copyright (c) 2014-2018 The Bitcoin Core developers
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

#include "crypto/hmac_sha256.h"

#include <string.h>

CHMAC_SHA256::CHMAC_SHA256(const unsigned char* key, size_t keylen)
{
    unsigned char rkey[64];
    if (keylen <= 64) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, 64 - keylen);
    } else {
        CSHA256().Write(key, keylen).Finalize(rkey);
        memset(rkey + 32, 0, 32);
    }

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 64);

    for (int n = 0; n < 64; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 64);
}

void CHMAC_SHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[32];
    inner.Finalize(temp);
    outer.Write(temp, 32).Finalize(hash);
}
