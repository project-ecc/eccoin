#ifndef BATCHSCANNER_H
#define BATCHSCANNER_H

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <leveldb/db.h>
#include <leveldb/write_batch.h>


class CBatchScanner : public leveldb::WriteBatch::Handler {
public:
    std::string needle;
    bool *deleted;
    std::string *foundValue;
    bool foundEntry;

    CBatchScanner() : foundEntry(false) {}

    virtual void Put(const leveldb::Slice& key, const leveldb::Slice& value) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = false;
            *foundValue = value.ToString();
        }
    }

    virtual void Delete(const leveldb::Slice& key) {
        if (key.ToString() == needle) {
            foundEntry = true;
            *deleted = true;
        }
    }
};

#endif // BATCHSCANNER_H
