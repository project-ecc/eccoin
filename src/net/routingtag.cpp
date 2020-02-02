// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "routingtag.h"

#include "random.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

extern secp256k1_context *secp256k1_context_sign;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */
static int ec_privkey_import_der(const secp256k1_context *ctx,
    unsigned char *out32,
    const unsigned char *privkey,
    size_t privkeylen)
{
    const unsigned char *end = privkey + privkeylen;
    int lenb = 0;
    int len = 0;
    memset(out32, 0, 32);
    /* sequence header */
    if (end < privkey + 1 || *privkey != 0x30)
    {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end < privkey + 1 || !(*privkey & 0x80))
    {
        return 0;
    }
    lenb = *privkey & ~0x80;
    privkey++;
    if (lenb < 1 || lenb > 2)
    {
        return 0;
    }
    if (end < privkey + lenb)
    {
        return 0;
    }
    /* sequence length */
    len = privkey[lenb - 1] | (lenb > 1 ? privkey[lenb - 2] << 8 : 0);
    privkey += lenb;
    if (end < privkey + len)
    {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end < privkey + 3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01)
    {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey + 2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey + 2 + privkey[1])
    {
        return 0;
    }
    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);
    if (!secp256k1_ec_seckey_verify(ctx, out32))
    {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

CPubKey CRoutingTag::GetPubKey() const { return vchPubKey; }
CPrivKey CRoutingTag::GetPrivKey() const { return vchPrivKey; }
bool CRoutingTag::IsPrivate() const { return isPrivate; }
void CRoutingTag::ConvertToPublicTag() { isPrivate = false; }
void CRoutingTag::MakeNewKey()
{
    CKey key;
    key.MakeNewKey(false);
    vchPubKey = key.GetPubKey();
    vchPrivKey = key.GetPrivKey();
}

bool CRoutingTag::VerifyPubKey(const CPubKey &pubkey) const
{
    // tag pubkeys are not compressed
    if (pubkey.IsCompressed() != false)
    {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Bitcoin key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char *)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CRoutingTag::CheckIfValid() const
{
    unsigned char vch[32];
    return ec_privkey_import_der(secp256k1_context_sign, (unsigned char *)vch, &vchPrivKey[0], vchPrivKey.size());
}

bool CRoutingTag::Sign(const uint256 &hash, std::vector<unsigned char> &vchSig, uint32_t test_case) const
{
    if (!CheckIfValid())
    {
        return false;
    }
    unsigned char vch[32];
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char *)vch, &vchPrivKey[0], vchPrivKey.size()))
    {
        return false;
    }
    vchSig.resize(72);
    size_t nSigLen = 72;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), (unsigned char *)&vch,
        secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : NULL);
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char *)&vchSig[0], &nSigLen, &sig);
    vchSig.resize(nSigLen);
    return true;
}

bool CRoutingTag::SignCompact(const uint256 &hash, std::vector<unsigned char> &vchSig) const
{
    unsigned char vch[32];
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char *)vch, &vchPrivKey[0], vchPrivKey.size()))
    {
        return false;
    }
    vchSig.resize(65);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int ret = secp256k1_ecdsa_sign_recoverable(
        secp256k1_context_sign, &sig, hash.begin(), (unsigned char *)&vch, secp256k1_nonce_function_rfc6979, NULL);
    assert(ret);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(
        secp256k1_context_sign, (unsigned char *)&vchSig[1], &rec, &sig);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec;
    return true;
}
