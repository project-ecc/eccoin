/*
 * This file is part of the Eccoin project
 * Copyright (c) 2018 Greg Griffith
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

#ifndef SERVICETX_H
#define SERVICETX_H

#include "serialize.h"
#include "uint256.h"

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CServiceTransaction
{
private:
    /** Memory only. */
    const uint256 hash;
    void UpdateHash() const;

public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION = 1;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION = 2;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    int32_t nVersion;
    uint16_t nServiceId;
    unsigned int nTime;
    uint16_t nOpCode;
    uint32_t nExpireTime;
    std::vector<unsigned char> vdata;
    uint256 paymentReferenceHash;
    // uint256 securityHash;

    /** Construct a CTransaction that qualifies as IsNull() */
    CServiceTransaction();

    /** Convert a CTransaction into a CTransaction. */
    CServiceTransaction(const CServiceTransaction &tx);

    CServiceTransaction &operator=(const CServiceTransaction &tx);

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(*const_cast<int32_t *>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<uint16_t *>(&this->nServiceId));
        READWRITE(*const_cast<uint32_t *>(&this->nTime));
        READWRITE(*const_cast<uint16_t *>(&this->nOpCode));
        READWRITE(*const_cast<uint32_t *>(&nExpireTime));
        READWRITE(*const_cast<std::vector<unsigned char> *>(&vdata));
        READWRITE(*const_cast<uint256 *>(&this->paymentReferenceHash));
        // READWRITE(*const_cast<uint256*>(&this->securityHash));
        if (ser_action.ForRead())
            UpdateHash();
    }

    bool IsNull() const
    {
        /// op code cannot be 0 if data is empty, this only happens in a null object
        return vdata.empty() && nOpCode == 0;
    }

    uint256 GetHash() const;

    friend bool operator==(const CServiceTransaction &a, const CServiceTransaction &b) { return a.hash == b.hash; }
    friend bool operator!=(const CServiceTransaction &a, const CServiceTransaction &b) { return a.hash != b.hash; }
    std::string ToString() const;
    // void setSecurityHash();
};


#endif // SERVICETX_H
