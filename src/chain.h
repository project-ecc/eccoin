#ifndef CHEADERCHAIN_H
#define CHEADERCHAIN_H

#include "uint256.h"
#include "main.h"
#include <leveldb/db.h>
#include <leveldb/write_batch.h>

extern leveldb::DB *metadb;

class CHeaderChainDB
{
public:
    CHeaderChainDB(const char* pszMode="r+");
    ~CHeaderChainDB() {
        // Note that this is not the same as Close() because it deletes only
        // data scoped to this TxDB object.
        delete activeBatch;
    }

    // Destroys the underlying shared global state accessed by this TxDB.
    void Close();

private:
    leveldb::DB *pdb;  // Points to the global instance.

    // A batch stores up writes and deletes for atomic application. When this
    // field is non-NULL, writes/deletes go there instead of directly to disk.
    leveldb::WriteBatch *activeBatch;
    leveldb::Options options;
    bool fReadOnly;
    int nVersion;

protected:
    // Returns true and sets (value,false) if activeBatch contains the given key
    // or leaves value alone and sets deleted = true if activeBatch contains a
    // delete for it.
    bool ScanBatch(const CDataStream &key, std::string *value, bool *deleted) const;

    template<typename K, typename T>
    bool Read(const K& key, T& value)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::string strValue;

        bool readFromDb = true;
        if (activeBatch)
        {
            // First we must search for it in the currently pending set of
            // changes to the db. If not found in the batch, go on to read disk.
            bool deleted = false;
            readFromDb = (ScanBatch(ssKey, &strValue, &deleted) == false);
            if (deleted)
            {
                return false;
            }
        }
        if (readFromDb)
        {
            leveldb::Status status = pdb->Get(leveldb::ReadOptions(),ssKey.str(), &strValue);
            if (!status.ok())
            {
                if (status.IsNotFound())
                {
                    return false;
                }
                // Some unexpected error.
                LogPrintf("LevelDB read failure: %s\n", status.ToString().c_str());
                return false;
            }
        }
        // Unserialize value
        try
        {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue >> value;
        }
        catch (std::exception &e)
        {
            return false;
        }
        return true;
    }

    template<typename K, typename T>
    bool Write(const K& key, const T& value)
    {
        if (fReadOnly)
            assert(!"Write called on database in read-only mode");

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.reserve(10000);
        ssValue << value;

        if (activeBatch)
        {
            activeBatch->Put(ssKey.str(), ssValue.str());
            return true;
        }
        leveldb::Status status = pdb->Put(leveldb::WriteOptions(), ssKey.str(), ssValue.str());
        if (!status.ok())
        {
            LogPrintf("LevelDB write failure: %s\n", status.ToString().c_str());
            return false;
        }
        return true;
    }

    template<typename K>
    bool Erase(const K& key)
    {
        if (!pdb)
            return false;
        if (fReadOnly)
            assert(!"Erase called on database in read-only mode");

        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        if (activeBatch) {
            activeBatch->Delete(ssKey.str());
            return true;
        }
        leveldb::Status status = pdb->Delete(leveldb::WriteOptions(), ssKey.str());
        return (status.ok() || status.IsNotFound());
    }

    template<typename K>
    bool Exists(const K& key)
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(1000);
        ssKey << key;
        std::string unused;

        if (activeBatch) {
            bool deleted;
            if (ScanBatch(ssKey, &unused, &deleted) && !deleted) {
                return true;
            }
        }


        leveldb::Status status = pdb->Get(leveldb::ReadOptions(), ssKey.str(), &unused);
        return status.IsNotFound() == false;
    }


public:
    bool TxnBegin();
    bool TxnCommit();
    bool TxnAbort()
    {
        delete activeBatch;
        activeBatch = NULL;
        return true;
    }

    bool ReadVersion(int& nVersion)
    {
        nVersion = 0;
        return Read(std::string("version"), nVersion);
    }

    bool WriteVersion(int nVersion)
    {
        return Write(std::string("version"), nVersion);
    }

    leveldb::DB* getInternalPointer()
    {
        return pdb;  // Points to the global instance.
    }

    bool WriteIndexHeader(const CDiskBlockIndex& blockindex);
    bool EraseIndexHeader(const CDiskBlockIndex& blockindex);
};


///
/// This class is a metadata for the chain
/// It only holds enough information to be able to look up the CBlockIndex
///     for the block with the hash found in this class. This should replace the
///     CBlockIndex chain in memory. This map does however store the theorectical
///     height each of a block index
///
/// it is not currently in use. it will be implented and replace the normal blockchain index map when the map starts to use too much memory for most clients (cut off is 900 MB)
class CHeaderChain
{
public:

    //fields
    uint256 hashBlock;
    uint256 hashPrev;
    uint256 hashNext;
    unsigned int nFile;
    unsigned int nBlockPos;
    int nHeight;
    CBlockIndex* pindex;

    //functions
    CHeaderChain();
    IMPLEMENT_SERIALIZE
    (
        READWRITE(hashBlock);
        READWRITE(hashPrev);
        READWRITE(hashNext);
        READWRITE(nFile);
        READWRITE(nBlockPos);
        READWRITE(nHeight);
    )
    uint256 GetBlockHash() const;
    CBlockIndex* getBlockIndex();
    void SetNull();
    bool WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet);
    bool ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions=true);
    std::string ToString() const;
    void print() const;
};

#endif // CHEADERCHAIN_H
