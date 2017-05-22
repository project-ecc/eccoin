#include "chain.h"
#include "batchscanner.h"

leveldb::DB *metadb; // global pointer for chain meta data

static leveldb::Options GetOptions() {
    leveldb::Options options;
    int nCacheSizeMB = GetArg("-dbcache", 25);
    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    return options;
}

void init_chainheader(leveldb::Options& options, bool fRemoveOld = false)
{
    // First time init.
    filesystem::path directory = GetDataDir() / "metachain";

    if (fRemoveOld)
    {
        filesystem::remove_all(directory); // remove directory
        unsigned int nFile = 1;
        while (true)
        {
            filesystem::path strBlockFile = GetDataDir() / strprintf("blk%04u.dat", nFile);
            // Break if no such file
            if( !filesystem::exists( strBlockFile ) )
                break;
            filesystem::remove(strBlockFile);
            nFile++;
        }
    }
    filesystem::create_directory(directory);
    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &metadb);
    if (!status.ok())
    {
        throw runtime_error(strprintf("init_chainheader(): error opening database environment %s", status.ToString().c_str()));
    }
}


CHeaderChainDB::CHeaderChainDB(const char* pszMode)
{
    assert(pszMode);
    activeBatch = NULL;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));

    if (metadb) {
        pdb = metadb;
        return;
    }

    bool fCreate = strchr(pszMode, 'c');

    options = GetOptions();
    options.create_if_missing = fCreate;
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_chainheader(options); // Init directory
    pdb = metadb;

    if (Exists(string("version")))
    {
        ReadVersion(nVersion);
        if (nVersion < DATABASE_VERSION)
        {
            LogPrintf("Required index version is %d, current version %d, removing old database\n", DATABASE_VERSION, nVersion);

            // Leveldb instance destruction
            delete metadb;
            metadb = pdb = NULL;
            delete activeBatch;
            activeBatch = NULL;
            init_chainheader(options, true); // Remove directory and create new database
            pdb = metadb;
            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(DATABASE_VERSION); // Save transaction index version
            fReadOnly = fTmp;
        }
    }
    else if (fCreate)
    {
        bool fTmp = fReadOnly;
        fReadOnly = false;
        WriteVersion(DATABASE_VERSION);
        fReadOnly = fTmp;
    }
}

void CHeaderChainDB::Close()
{
    delete metadb;
    metadb = pdb = NULL;
    delete options.filter_policy;
    options.filter_policy = NULL;
    delete options.block_cache;
    options.block_cache = NULL;
    delete activeBatch;
    activeBatch = NULL;
}

bool CHeaderChainDB::TxnBegin()
{
    assert(!activeBatch);
    activeBatch = new leveldb::WriteBatch();
    return true;
}

bool CHeaderChainDB::TxnCommit()
{
    assert(activeBatch);
    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    delete activeBatch;
    activeBatch = NULL;
    if (!status.ok())
    {
        LogPrintf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    }
    return true;
}

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool CHeaderChainDB::ScanBatch(const CDataStream &key, string *value, bool *deleted) const {
    assert(activeBatch);
    *deleted = false;
    CBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status status = activeBatch->Iterate(&scanner);
    if (!status.ok())
    {
        throw runtime_error(status.ToString());
    }
    return scanner.foundEntry;
}

bool CHeaderChainDB::WriteIndexHeader(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("indexheader"), blockindex.GetBlockHash()), blockindex);
}

bool CHeaderChainDB::EraseIndexHeader(const CDiskBlockIndex& blockindex)
{
    return Erase(make_pair(string("indexheader"), blockindex.GetBlockHash()));
}




















//////
/// Not used yet, something for later if there is a way to reduce memory usage by storing less index information in memory
//////

CHeaderChain::CHeaderChain()
{
    hashBlock = 0;
    hashPrev = 0;
    hashNext = 0;
    nFile = 0;
    nBlockPos = 0;
    nHeight = 0;
    pindex = NULL;
}

uint256 CHeaderChain::GetBlockHash() const
{
    return hashBlock;
}

CBlockIndex* CHeaderChain::getBlockIndex()
{
    return pindex;
}

void CHeaderChain::SetNull()
{
    hashBlock = 0;
    hashPrev = 0;
    hashNext = 0;
    nFile = 0;
    nBlockPos = 0;
    nHeight = 0;
}

std::string CHeaderChain::ToString() const
{
    return strprintf("CHeaderChain: hashBlock=%s, hashPrev=%s, hashNext=%s, nFile=%u, nBlockPos=%u, nHeight=%d \n",
                     this->hashBlock.ToString().c_str(),
                     this->hashPrev.ToString().c_str(),
                     this->hashNext.ToString().c_str(),
                     this->nFile,
                     this->nBlockPos,
                     this->nHeight
                     );
}

void CHeaderChain::print() const
{
    LogPrintf("%s\n", ToString().c_str());
}
