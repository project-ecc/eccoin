/*
 * This file is part of the Eccoin project
 * Copyright (c) 2012-2016 The Bitcoin Core developers
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

#include "dbwrapper.h"

#include "random.h"
#include "util/util.h"

#include <leveldb/cache.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <leveldb/helpers/memenv/memenv.h>
#include <stdint.h>

void HandleError(const leveldb::Status &status)
{
    if (status.ok())
        return;
    LogPrintf("%s\n", status.ToString());
    if (status.IsCorruption())
        throw dbwrapper_error("Database corrupted");
    if (status.IsIOError())
        throw dbwrapper_error("Database I/O error");
    if (status.IsNotFound())
        throw dbwrapper_error("Database entry missing");
    throw dbwrapper_error("Unknown database error");
}

static leveldb::Options GetOptions(size_t nCacheSize)
{
    leveldb::Options options;
    options.block_cache = leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4; // up to two write buffers may be held in memory simultaneously
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    options.max_open_files = 64;
    if (leveldb::kMajorVersion > 1 || (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16))
    {
        // LevelDB versions before 1.16 consider short writes to be corruption. Only trigger error
        // on corruption in later versions.
        options.paranoid_checks = true;
    }
    return options;
}

CDBWrapper::CDBWrapper(const fs::path &path, size_t nCacheSize, bool fMemory, bool fWipe, bool obfuscate)
{
    penv = NULL;
    readoptions.verify_checksums = true;
    iteroptions.verify_checksums = true;
    iteroptions.fill_cache = false;
    syncoptions.sync = true;
    options = GetOptions(nCacheSize);
    options.create_if_missing = true;
    if (fMemory)
    {
        penv = leveldb::NewMemEnv(leveldb::Env::Default());
        options.env = penv;
    }
    else
    {
        if (fWipe)
        {
            LogPrintf("Wiping LevelDB in %s\n", path.string());
            leveldb::Status result = leveldb::DestroyDB(path.string(), options);
            HandleError(result);
        }
        TryCreateDirectory(path);
        LogPrintf("Opening LevelDB in %s\n", path.string());
    }
    leveldb::Status status = leveldb::DB::Open(options, path.string(), &pdb);
    HandleError(status);
    LogPrintf("Opened LevelDB successfully\n");

    // The base-case obfuscation key, which is a noop.
    obfuscate_key = std::vector<unsigned char>(OBFUSCATE_KEY_NUM_BYTES, '\000');

    bool key_exists = Read(OBFUSCATE_KEY_KEY, obfuscate_key);

    if (!key_exists && obfuscate && IsEmpty())
    {
        // Initialize non-degenerate obfuscation if it won't upset
        // existing, non-obfuscated data.
        std::vector<unsigned char> new_key = CreateObfuscateKey();

        // Write `new_key` so we don't obfuscate the key with itself
        Write(OBFUSCATE_KEY_KEY, new_key);
        obfuscate_key = new_key;

        LogPrintf("Wrote new obfuscate key for %s: %s\n", path.string().c_str(), HexStr(obfuscate_key).c_str());
    }

    LogPrintf("Using obfuscation key for %s: %s\n", path.string().c_str(), HexStr(obfuscate_key).c_str());
}

CDBWrapper::~CDBWrapper()
{
    delete pdb;
    pdb = NULL;
    delete options.filter_policy;
    options.filter_policy = NULL;
    delete options.block_cache;
    options.block_cache = NULL;
    delete penv;
    options.env = NULL;
}

bool CDBWrapper::WriteBatch(CDBBatch &batch, bool fSync)
{
    leveldb::Status status = pdb->Write(fSync ? syncoptions : writeoptions, &batch.batch);
    HandleError(status);
    return true;
}

// Prefixed with null character to avoid collisions with other keys
//
// We must use a string constructor which specifies length so that we copy
// past the null-terminator.
const std::string CDBWrapper::OBFUSCATE_KEY_KEY("\000obfuscate_key", 14);

const unsigned int CDBWrapper::OBFUSCATE_KEY_NUM_BYTES = 8;

/**
 * Returns a string (consisting of 8 random bytes) suitable for use as an
 * obfuscating XOR key.
 */
std::vector<unsigned char> CDBWrapper::CreateObfuscateKey() const
{
    unsigned char buff[OBFUSCATE_KEY_NUM_BYTES];
    GetRandBytes(buff, OBFUSCATE_KEY_NUM_BYTES);
    return std::vector<unsigned char>(&buff[0], &buff[OBFUSCATE_KEY_NUM_BYTES]);
}

bool CDBWrapper::IsEmpty()
{
    boost::scoped_ptr<CDBIterator> it(NewIterator());
    it->SeekToFirst();
    return !(it->Valid());
}


CDBIterator::~CDBIterator() { delete piter; }
bool CDBIterator::Valid() { return piter->Valid(); }
void CDBIterator::SeekToFirst() { piter->SeekToFirst(); }
void CDBIterator::Next() { piter->Next(); }
namespace dbwrapper_private
{
void HandleError(const leveldb::Status &status)
{
    if (status.ok())
    {
        return;
    }
    LogPrintf("%s\n", status.ToString());
    if (status.IsCorruption())
    {
        throw dbwrapper_error("Database corrupted");
    }
    if (status.IsIOError())
    {
        throw dbwrapper_error("Database I/O error");
    }
    if (status.IsNotFound())
    {
        throw dbwrapper_error("Database entry missing");
    }
    throw dbwrapper_error("Unknown database error");
}

const std::vector<uint8_t> &GetObfuscateKey(const CDBWrapper &w) { return w.obfuscate_key; }
}
