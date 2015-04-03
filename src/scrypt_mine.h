#ifndef SCRYPT_MINE_H
#define SCRYPT_MINE_H

#include <stdint.h>
#include <stdlib.h>

#include "net.h"
#include "pbkdf2.h"
#include "util.h"

typedef struct block_header_s
{
    unsigned int version;
    uint256 prev_block;
    uint256 merkle_root;
    unsigned int timestamp;
    unsigned int bits;
    unsigned int nonce;

} block_header;

void *scrypt_buffer_alloc();
void scrypt_buffer_free(void *scratchpad);
void scrypt_hash_mine(const void* input, size_t inputlen, uint32_t *res, void *scratchpad);
uint256 scrypt_salted_multiround_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen, const unsigned int nRounds);
unsigned int scanhash_scrypt(block_header *pdata, void *scratchbuf, uint32_t max_nonce, uint32_t &hash_count, void *result, block_header *res_header);
uint256 scrypt_salted_hash(const void* input, size_t inputlen, const void* salt, size_t saltlen);



#endif // SCRYPT_MINE_H
