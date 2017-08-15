#include "stakescript.h"
#include <vector>
#include "primitives/transaction.h"
#include "interpreter.h"
#include <openssl/crypto.h>
#include "sigcache.h"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include "sync.h"
#include "util.h"
#include "args.h"
#include "random.h"
#include "key.h"
#include <openssl/ripemd.h>
#include <openssl/sha.h>

static const std::vector<unsigned char> vchFalse(0);
static const std::vector<unsigned char> vchZero(0);
static const std::vector<unsigned char> vchTrue(1, 1);
static const CBigNum bnZero(0);
static const CBigNum bnOne(1);
static const CBigNum bnFalse(0);
static const CBigNum bnTrue(1);
static const size_t nMaxNumSize = 4;



// Valid signature cache, to avoid doing expensive ECDSA signature checking
// twice for every transaction (once when accepted into memory pool, and
// again when accepted into the block chain)

class CStakeSignatureCache
{
private:
     // sigdata_type is (signature hash, signature, public key):
    typedef boost::tuple<uint256, std::vector<unsigned char>, std::vector<unsigned char> > sigdata_type;
    std::set< sigdata_type> setValid;
    CCriticalSection cs_sigcache;

public:
    bool
    Get(uint256 hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& pubKey)
    {
        LOCK(cs_sigcache);

        sigdata_type k(hash, vchSig, pubKey);
        std::set<sigdata_type>::iterator mi = setValid.find(k);
        if (mi != setValid.end())
            return true;
        return false;
    }

    void Set(uint256 hash, const std::vector<unsigned char>& vchSig, const std::vector<unsigned char>& pubKey)
    {
        // DoS prevention: limit cache size to less than 10MB
        // (~200 bytes per cache entry times 50,000 entries)
        // Since there are a maximum of 20,000 signature operations per block
        // 50,000 is a reasonable default.
        int64_t nMaxCacheSize = gArgs.GetArg("-maxsigcachesize", 50000);
        if (nMaxCacheSize <= 0) return;

        LOCK(cs_sigcache);

        while (static_cast<int64_t>(setValid.size()) > nMaxCacheSize)
        {
            // Evict a random entry. Random because that helps
            // foil would-be DoS attackers who might try to pre-generate
            // and re-use a set of valid signatures just-slightly-greater
            // than our cache size.
            uint256 randomHash = GetRandHash();
            std::vector<unsigned char> unused;
            std::set<sigdata_type>::iterator it =
                setValid.lower_bound(sigdata_type(randomHash, unused, unused));
            if (it == setValid.end())
                it = setValid.begin();
            setValid.erase(*it);
        }

        sigdata_type k(hash, vchSig, pubKey);
        setValid.insert(k);
    }
};


bool CheckSig(std::vector<unsigned char> vchSig, std::vector<unsigned char> vchPubKey, CScript scriptCode,
              const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    static CStakeSignatureCache signatureCache;

    // Hash type is one byte tacked on to the end of the signature
    if (vchSig.empty())
        return false;
    if (nHashType == 0)
        nHashType = vchSig.back();
    else if (nHashType != vchSig.back())
        return false;
    vchSig.pop_back();

    uint256 sighash = SignatureHash(scriptCode, txTo, nIn, nHashType);

    if (signatureCache.Get(sighash, vchSig, vchPubKey))
        return true;

    CPubKey key(vchPubKey);

    if (!key.Verify(sighash, vchSig))
        return false;

    signatureCache.Set(sighash, vchSig, vchPubKey);
    return true;
}


//
// WARNING: This does not work as expected for signed integers; the sign-bit
// is left in place as the integer is zero-extended. The correct behavior
// would be to move the most significant bit of the last byte during the
// resize process. MakeSameSize() is currently only used by the disabled
// opcodes OP_AND, OP_OR, and OP_XOR.
//
void MakeSameSize(std::vector<unsigned char>& vch1, std::vector<unsigned char>& vch2)
{
    // Lengthen the shorter one
    if (vch1.size() < vch2.size())
        // PATCH:
        // +unsigned char msb = vch1[vch1.size()-1];
        // +vch1[vch1.size()-1] &= 0x7f;
        //  vch1.resize(vch2.size(), 0);
        // +vch1[vch1.size()-1] = msb;
        vch1.resize(vch2.size(), 0);
    if (vch2.size() < vch1.size())
        // PATCH:
        // +unsigned char msb = vch2[vch2.size()-1];
        // +vch2[vch2.size()-1] &= 0x7f;
        //  vch2.resize(vch1.size(), 0);
        // +vch2[vch2.size()-1] = msb;
        vch2.resize(vch1.size(), 0);
}


//
// Script is a stack machine (like Forth) that evaluates a predicate
// returning a bool indicating valid or not.  There are no loops.
//
#define stacktop(i)  (stack.at(stack.size()+(i)))
#define altstacktop(i)  (altstack.at(altstack.size()+(i)))
static inline void popstack(std::vector<std::vector<unsigned char> >& stack)
{
    if (stack.empty())
        throw std::runtime_error("popstack() : stack empty");
    stack.pop_back();
}

CBigNum CastToBigNum(const std::vector<unsigned char>& vch)
{
    if (vch.size() > nMaxNumSize)
        throw std::runtime_error("CastToBigNum() : overflow");
    // Get rid of extra leading zeros
    return CBigNum(CBigNum(vch).getvch());
}

bool EvalScript(std::vector<std::vector<unsigned char> >& stack, const CScript& script, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    CAutoBN_CTX pctx;
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> vchPushValue;
    std::vector<bool> vfExec;
    std::vector<std::vector<unsigned char> > altstack;
    if (script.size() > 10000)
        return false;
    int nOpCount = 0;


    try
    {
        while (pc < pend)
        {
            bool fExec = !count(vfExec.begin(), vfExec.end(), false);

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue))
                return false;
            if (vchPushValue.size() > 520)
                return false;
            if (opcode > OP_16 && ++nOpCount > 201)
                return false;

            if (opcode == OP_CAT ||
                opcode == OP_SUBSTR ||
                opcode == OP_LEFT ||
                opcode == OP_RIGHT ||
                opcode == OP_INVERT ||
                opcode == OP_AND ||
                opcode == OP_OR ||
                opcode == OP_XOR ||
                opcode == OP_2MUL ||
                opcode == OP_2DIV ||
                opcode == OP_MUL ||
                opcode == OP_DIV ||
                opcode == OP_MOD ||
                opcode == OP_LSHIFT ||
                opcode == OP_RSHIFT)
                return false;

            if (fExec && 0 <= opcode && opcode <= OP_PUSHDATA4)
                stack.push_back(vchPushValue);
            else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
            switch (opcode)
            {
                //
                // Push value
                //
                case OP_1NEGATE:
                case OP_1:
                case OP_2:
                case OP_3:
                case OP_4:
                case OP_5:
                case OP_6:
                case OP_7:
                case OP_8:
                case OP_9:
                case OP_10:
                case OP_11:
                case OP_12:
                case OP_13:
                case OP_14:
                case OP_15:
                case OP_16:
                {
                    // ( -- value)
                    CBigNum bn((int)opcode - (int)(OP_1 - 1));
                    stack.push_back(bn.getvch());
                }
                break;


                //
                // Control
                //
                case OP_NOP:
                case OP_NOP1: case OP_NOP2: case OP_NOP3: case OP_NOP4: case OP_NOP5:
                case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
                break;

                case OP_IF:
                case OP_NOTIF:
                {
                    // <expression> if [statements] [else [statements]] endif
                    bool fValue = false;
                    if (fExec)
                    {
                        if (stack.size() < 1)
                            return false;
                        std::vector<unsigned char>& vch = stacktop(-1);
                        fValue = CastToBool(vch);
                        if (opcode == OP_NOTIF)
                            fValue = !fValue;
                        popstack(stack);
                    }
                    vfExec.push_back(fValue);
                }
                break;

                case OP_ELSE:
                {
                    if (vfExec.empty())
                        return false;
                    vfExec.back() = !vfExec.back();
                }
                break;

                case OP_ENDIF:
                {
                    if (vfExec.empty())
                        return false;
                    vfExec.pop_back();
                }
                break;

                case OP_VERIFY:
                {
                    // (true -- ) or
                    // (false -- false) and return
                    if (stack.size() < 1)
                        return false;
                    bool fValue = CastToBool(stacktop(-1));
                    if (fValue)
                        popstack(stack);
                    else
                        return false;
                }
                break;

                case OP_RETURN:
                {
                    return false;
                }
                break;


                //
                // Stack ops
                //
                case OP_TOALTSTACK:
                {
                    if (stack.size() < 1)
                        return false;
                    altstack.push_back(stacktop(-1));
                    popstack(stack);
                }
                break;

                case OP_FROMALTSTACK:
                {
                    if (altstack.size() < 1)
                        return false;
                    stack.push_back(altstacktop(-1));
                    popstack(altstack);
                }
                break;

                case OP_2DROP:
                {
                    // (x1 x2 -- )
                    if (stack.size() < 2)
                        return false;
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_2DUP:
                {
                    // (x1 x2 -- x1 x2 x1 x2)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char> vch1 = stacktop(-2);
                    std::vector<unsigned char> vch2 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_3DUP:
                {
                    // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                    if (stack.size() < 3)
                        return false;
                    std::vector<unsigned char> vch1 = stacktop(-3);
                    std::vector<unsigned char> vch2 = stacktop(-2);
                    std::vector<unsigned char> vch3 = stacktop(-1);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                    stack.push_back(vch3);
                }
                break;

                case OP_2OVER:
                {
                    // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return false;
                    std::vector<unsigned char> vch1 = stacktop(-4);
                    std::vector<unsigned char> vch2 = stacktop(-3);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2ROT:
                {
                    // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                    if (stack.size() < 6)
                        return false;
                    std::vector<unsigned char> vch1 = stacktop(-6);
                    std::vector<unsigned char> vch2 = stacktop(-5);
                    stack.erase(stack.end()-6, stack.end()-4);
                    stack.push_back(vch1);
                    stack.push_back(vch2);
                }
                break;

                case OP_2SWAP:
                {
                    // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                    if (stack.size() < 4)
                        return false;
                    swap(stacktop(-4), stacktop(-2));
                    swap(stacktop(-3), stacktop(-1));
                }
                break;

                case OP_IFDUP:
                {
                    // (x - 0 | x x)
                    if (stack.size() < 1)
                        return false;
                    std::vector<unsigned char> vch = stacktop(-1);
                    if (CastToBool(vch))
                        stack.push_back(vch);
                }
                break;

                case OP_DEPTH:
                {
                    // -- stacksize
                    CBigNum bn(stack.size());
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_DROP:
                {
                    // (x -- )
                    if (stack.size() < 1)
                        return false;
                    popstack(stack);
                }
                break;

                case OP_DUP:
                {
                    // (x -- x x)
                    if (stack.size() < 1)
                        return false;
                    std::vector<unsigned char> vch = stacktop(-1);
                    stack.push_back(vch);
                }
                break;

                case OP_NIP:
                {
                    // (x1 x2 -- x2)
                    if (stack.size() < 2)
                        return false;
                    stack.erase(stack.end() - 2);
                }
                break;

                case OP_OVER:
                {
                    // (x1 x2 -- x1 x2 x1)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char> vch = stacktop(-2);
                    stack.push_back(vch);
                }
                break;

                case OP_PICK:
                case OP_ROLL:
                {
                    // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                    // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                    if (stack.size() < 2)
                        return false;
                    int n = CastToBigNum(stacktop(-1)).getint();
                    popstack(stack);
                    if (n < 0 || n >= (int)stack.size())
                        return false;
                    std::vector<unsigned char> vch = stacktop(-n-1);
                    if (opcode == OP_ROLL)
                        stack.erase(stack.end()-n-1);
                    stack.push_back(vch);
                }
                break;

                case OP_ROT:
                {
                    // (x1 x2 x3 -- x2 x3 x1)
                    //  x2 x1 x3  after first swap
                    //  x2 x3 x1  after second swap
                    if (stack.size() < 3)
                        return false;
                    swap(stacktop(-3), stacktop(-2));
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_SWAP:
                {
                    // (x1 x2 -- x2 x1)
                    if (stack.size() < 2)
                        return false;
                    swap(stacktop(-2), stacktop(-1));
                }
                break;

                case OP_TUCK:
                {
                    // (x1 x2 -- x2 x1 x2)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char> vch = stacktop(-1);
                    stack.insert(stack.end()-2, vch);
                }
                break;


                //
                // Splice ops
                //
                case OP_CAT:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char>& vch1 = stacktop(-2);
                    std::vector<unsigned char>& vch2 = stacktop(-1);
                    vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                    popstack(stack);
                    if (stacktop(-1).size() > 520)
                        return false;
                }
                break;

                case OP_SUBSTR:
                {
                    // (in begin size -- out)
                    if (stack.size() < 3)
                        return false;
                    std::vector<unsigned char>& vch = stacktop(-3);
                    int nBegin = CastToBigNum(stacktop(-2)).getint();
                    int nEnd = nBegin + CastToBigNum(stacktop(-1)).getint();
                    if (nBegin < 0 || nEnd < nBegin)
                        return false;
                    if (nBegin > (int)vch.size())
                        nBegin = vch.size();
                    if (nEnd > (int)vch.size())
                        nEnd = vch.size();
                    vch.erase(vch.begin() + nEnd, vch.end());
                    vch.erase(vch.begin(), vch.begin() + nBegin);
                    popstack(stack);
                    popstack(stack);
                }
                break;

                case OP_LEFT:
                case OP_RIGHT:
                {
                    // (in size -- out)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char>& vch = stacktop(-2);
                    int nSize = CastToBigNum(stacktop(-1)).getint();
                    if (nSize < 0)
                        return false;
                    if (nSize > (int)vch.size())
                        nSize = vch.size();
                    if (opcode == OP_LEFT)
                        vch.erase(vch.begin() + nSize, vch.end());
                    else
                        vch.erase(vch.begin(), vch.end() - nSize);
                    popstack(stack);
                }
                break;

                case OP_SIZE:
                {
                    // (in -- in size)
                    if (stack.size() < 1)
                        return false;
                    CBigNum bn(stacktop(-1).size());
                    stack.push_back(bn.getvch());
                }
                break;


                //
                // Bitwise logic
                //
                case OP_INVERT:
                {
                    // (in - out)
                    if (stack.size() < 1)
                        return false;
                    std::vector<unsigned char>& vch = stacktop(-1);
                    for (unsigned int i = 0; i < vch.size(); i++)
                        vch[i] = ~vch[i];
                }
                break;

                //
                // WARNING: These disabled opcodes exhibit unexpected behavior
                // when used on signed integers due to a bug in MakeSameSize()
                // [see definition of MakeSameSize() above].
                //
                case OP_AND:
                case OP_OR:
                case OP_XOR:
                {
                    // (x1 x2 - out)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char>& vch1 = stacktop(-2);
                    std::vector<unsigned char>& vch2 = stacktop(-1);
                    MakeSameSize(vch1, vch2); // <-- NOT SAFE FOR SIGNED VALUES
                    if (opcode == OP_AND)
                    {
                        for (unsigned int i = 0; i < vch1.size(); i++)
                            vch1[i] &= vch2[i];
                    }
                    else if (opcode == OP_OR)
                    {
                        for (unsigned int i = 0; i < vch1.size(); i++)
                            vch1[i] |= vch2[i];
                    }
                    else if (opcode == OP_XOR)
                    {
                        for (unsigned int i = 0; i < vch1.size(); i++)
                            vch1[i] ^= vch2[i];
                    }
                    popstack(stack);
                }
                break;

                case OP_EQUAL:
                case OP_EQUALVERIFY:
                //case OP_NOTEQUAL: // use OP_NUMNOTEQUAL
                {
                    // (x1 x2 - bool)
                    if (stack.size() < 2)
                        return false;
                    std::vector<unsigned char>& vch1 = stacktop(-2);
                    std::vector<unsigned char>& vch2 = stacktop(-1);
                    bool fEqual = (vch1 == vch2);
                    // OP_NOTEQUAL is disabled because it would be too easy to say
                    // something like n != 1 and have some wiseguy pass in 1 with extra
                    // zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
                    //if (opcode == OP_NOTEQUAL)
                    //    fEqual = !fEqual;
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fEqual ? vchTrue : vchFalse);
                    if (opcode == OP_EQUALVERIFY)
                    {
                        if (fEqual)
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;


                //
                // Numeric
                //
                case OP_1ADD:
                case OP_1SUB:
                case OP_2MUL:
                case OP_2DIV:
                case OP_NEGATE:
                case OP_ABS:
                case OP_NOT:
                case OP_0NOTEQUAL:
                {
                    // (in -- out)
                    if (stack.size() < 1)
                        return false;
                    CBigNum bn = CastToBigNum(stacktop(-1));
                    switch (opcode)
                    {
                    case OP_1ADD:       bn += bnOne; break;
                    case OP_1SUB:       bn -= bnOne; break;
                    case OP_2MUL:       bn <<= 1; break;
                    case OP_2DIV:       bn >>= 1; break;
                    case OP_NEGATE:     bn = -bn; break;
                    case OP_ABS:        if (bn < bnZero) bn = -bn; break;
                    case OP_NOT:        bn = (bn == bnZero); break;
                    case OP_0NOTEQUAL:  bn = (bn != bnZero); break;
                    default:            assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    stack.push_back(bn.getvch());
                }
                break;

                case OP_ADD:
                case OP_SUB:
                case OP_MUL:
                case OP_DIV:
                case OP_MOD:
                case OP_LSHIFT:
                case OP_RSHIFT:
                case OP_BOOLAND:
                case OP_BOOLOR:
                case OP_NUMEQUAL:
                case OP_NUMEQUALVERIFY:
                case OP_NUMNOTEQUAL:
                case OP_LESSTHAN:
                case OP_GREATERTHAN:
                case OP_LESSTHANOREQUAL:
                case OP_GREATERTHANOREQUAL:
                case OP_MIN:
                case OP_MAX:
                {
                    // (x1 x2 -- out)
                    if (stack.size() < 2)
                        return false;
                    CBigNum bn1 = CastToBigNum(stacktop(-2));
                    CBigNum bn2 = CastToBigNum(stacktop(-1));
                    CBigNum bn;
                    switch (opcode)
                    {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_MUL:
                        if (!BN_mul(&bn, &bn1, &bn2, pctx))
                            return false;
                        break;

                    case OP_DIV:
                        if (!BN_div(&bn, NULL, &bn1, &bn2, pctx))
                            return false;
                        break;

                    case OP_MOD:
                        if (!BN_mod(&bn, &bn1, &bn2, pctx))
                            return false;
                        break;

                    case OP_LSHIFT:
                        if (bn2 < bnZero || bn2 > CBigNum(2048))
                            return false;
                        bn = bn1 << bn2.getulong();
                        break;

                    case OP_RSHIFT:
                        if (bn2 < bnZero || bn2 > CBigNum(2048))
                            return false;
                        bn = bn1 >> bn2.getulong();
                        break;

                    case OP_BOOLAND:             bn = (bn1 != bnZero && bn2 != bnZero); break;
                    case OP_BOOLOR:              bn = (bn1 != bnZero || bn2 != bnZero); break;
                    case OP_NUMEQUAL:            bn = (bn1 == bn2); break;
                    case OP_NUMEQUALVERIFY:      bn = (bn1 == bn2); break;
                    case OP_NUMNOTEQUAL:         bn = (bn1 != bn2); break;
                    case OP_LESSTHAN:            bn = (bn1 < bn2); break;
                    case OP_GREATERTHAN:         bn = (bn1 > bn2); break;
                    case OP_LESSTHANOREQUAL:     bn = (bn1 <= bn2); break;
                    case OP_GREATERTHANOREQUAL:  bn = (bn1 >= bn2); break;
                    case OP_MIN:                 bn = (bn1 < bn2 ? bn1 : bn2); break;
                    case OP_MAX:                 bn = (bn1 > bn2 ? bn1 : bn2); break;
                    default:                     assert(!"invalid opcode"); break;
                    }
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(bn.getvch());

                    if (opcode == OP_NUMEQUALVERIFY)
                    {
                        if (CastToBool(stacktop(-1)))
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;

                case OP_WITHIN:
                {
                    // (x min max -- out)
                    if (stack.size() < 3)
                        return false;
                    CBigNum bn1 = CastToBigNum(stacktop(-3));
                    CBigNum bn2 = CastToBigNum(stacktop(-2));
                    CBigNum bn3 = CastToBigNum(stacktop(-1));
                    bool fValue = (bn2 <= bn1 && bn1 < bn3);
                    popstack(stack);
                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fValue ? vchTrue : vchFalse);
                }
                break;


                //
                // Crypto
                //
                case OP_RIPEMD160:
                case OP_SHA1:
                case OP_SHA256:
                case OP_HASH160:
                case OP_HASH256:
                {
                    // (in -- hash)
                    if (stack.size() < 1)
                        return false;
                    std::vector<unsigned char>& vch = stacktop(-1);
                    std::vector<unsigned char> vchHash((opcode == OP_RIPEMD160 || opcode == OP_SHA1 || opcode == OP_HASH160) ? 20 : 32);
                    if (opcode == OP_RIPEMD160)
                        RIPEMD160(&vch[0], vch.size(), &vchHash[0]);
                    else if (opcode == OP_SHA1)
                        SHA1(&vch[0], vch.size(), &vchHash[0]);
                    else if (opcode == OP_SHA256)
                        SHA256(&vch[0], vch.size(), &vchHash[0]);
                    else if (opcode == OP_HASH160)
                    {
                        uint160 hash160 = Hash160(vch);
                        memcpy(&vchHash[0], &hash160, sizeof(hash160));
                    }
                    else if (opcode == OP_HASH256)
                    {
                        uint256 hash = Hash(vch.begin(), vch.end());
                        memcpy(&vchHash[0], &hash, sizeof(hash));
                    }
                    popstack(stack);
                    stack.push_back(vchHash);
                }
                break;

                case OP_CODESEPARATOR:
                {
                    // Hash starts after the code separator
                    pbegincodehash = pc;
                }
                break;

                case OP_CHECKSIG:
                case OP_CHECKSIGVERIFY:
                {
                    // (sig pubkey -- bool)
                    if (stack.size() < 2)
                        return false;

                    std::vector<unsigned char>& vchSig    = stacktop(-2);
                    std::vector<unsigned char>& vchPubKey = stacktop(-1);

                    ////// debug print
                    //PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
                    //PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signature, since there's no way for a signature to sign itself
                    scriptCode.FindAndDelete(CScript(vchSig));
                    bool fSuccess;

                    fSuccess = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);

                    popstack(stack);
                    popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);
                    if (opcode == OP_CHECKSIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;

                case OP_CHECKMULTISIG:
                case OP_CHECKMULTISIGVERIFY:
                {
                    // ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

                    int i = 1;
                    if ((int)stack.size() < i)
                        return false;

                    int nKeysCount = CastToBigNum(stacktop(-i)).getint();
                    if (nKeysCount < 0 || nKeysCount > 20)
                        return false;
                    nOpCount += nKeysCount;
                    if (nOpCount > 201)
                        return false;
                    int ikey = ++i;
                    i += nKeysCount;
                    if ((int)stack.size() < i)
                        return false;

                    int nSigsCount = CastToBigNum(stacktop(-i)).getint();
                    if (nSigsCount < 0 || nSigsCount > nKeysCount)
                        return false;
                    int isig = ++i;
                    i += nSigsCount;
                    if ((int)stack.size() < i)
                        return false;

                    // Subset of script starting at the most recent codeseparator
                    CScript scriptCode(pbegincodehash, pend);

                    // Drop the signatures, since there's no way for a signature to sign itself
                    for (int k = 0; k < nSigsCount; k++)
                    {
                        std::vector<unsigned char>& vchSig = stacktop(-isig-k);
                        scriptCode.FindAndDelete(CScript(vchSig));
                    }

                    bool fSuccess = true;
                    while (fSuccess && nSigsCount > 0)
                    {
                        std::vector<unsigned char>& vchSig    = stacktop(-isig);
                        std::vector<unsigned char>& vchPubKey = stacktop(-ikey);

                        // Check signature
                        bool fOk;

                        fOk = CheckSig(vchSig, vchPubKey, scriptCode, txTo, nIn, nHashType);

                        if (fOk)
                        {
                            isig++;
                            nSigsCount--;
                        }
                        ikey++;
                        nKeysCount--;

                        // If there are more signatures left than keys left,
                        // then too many signatures have failed
                        if (nSigsCount > nKeysCount)
                            fSuccess = false;
                    }

                    while (i-- > 0)
                        popstack(stack);
                    stack.push_back(fSuccess ? vchTrue : vchFalse);

                    if (opcode == OP_CHECKMULTISIGVERIFY)
                    {
                        if (fSuccess)
                            popstack(stack);
                        else
                            return false;
                    }
                }
                break;

                default:
                    return false;
            }

            // Size limits
            if (stack.size() + altstack.size() > 1000)
                return false;
        }
    }
    catch (...)
    {
        return false;
    }


    if (!vfExec.empty())
        return false;

    return true;
}

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,int nHashType)
{
    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, txTo, nIn, nHashType))
        return false;
    stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, txTo, nIn, nHashType))
        return false;
    if (stack.empty())
        return false;

    if (CastToBool(stack.back()) == false)
        return false;

    // Additional validation for spend-to-script-hash transactions:
    if (scriptPubKey.IsPayToScriptHash())
    {
        if (!scriptSig.IsPushOnly()) // scriptSig must be literals-only
            return false;            // or validation fails

        const std::vector<unsigned char>& pubKeySerialized = stackCopy.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stackCopy);

        if (!EvalScript(stackCopy, pubKey2, txTo, nIn, nHashType))
            return false;
        if (stackCopy.empty())
            return false;
        return CastToBool(stackCopy.back());
    }

    return true;
}

bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn,
                  bool fValidatePayToScriptHash, int nHashType)
{
    std::vector<std::vector<unsigned char> > stack, stackCopy;
    if (!EvalScript(stack, scriptSig, txTo, nIn, nHashType))
        return false;
    if (fValidatePayToScriptHash)
        stackCopy = stack;
    if (!EvalScript(stack, scriptPubKey, txTo, nIn, nHashType))
        return false;
    if (stack.empty())
        return false;

    if (CastToBool(stack.back()) == false)
        return false;

    // Additional validation for spend-to-script-hash transactions:
    if (fValidatePayToScriptHash && scriptPubKey.IsPayToScriptHash())
    {
        if (!scriptSig.IsPushOnly()) // scriptSig must be literals-only
            return false;            // or validation fails

        const std::vector<unsigned char>& pubKeySerialized = stackCopy.back();
        CScript pubKey2(pubKeySerialized.begin(), pubKeySerialized.end());
        popstack(stackCopy);

        if (!EvalScript(stackCopy, pubKey2, txTo, nIn, nHashType))
            return false;
        if (stackCopy.empty())
            return false;
        return CastToBool(stackCopy.back());
    }

    return true;
}

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, int nHashType)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    return VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, nHashType);
}

bool VerifySignature(const CTransaction& txFrom, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash, int nHashType)
{
    assert(nIn < txTo.vin.size());
    const CTxIn& txin = txTo.vin[nIn];
    if (txin.prevout.n >= txFrom.vout.size())
        return false;
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    if (txin.prevout.hash != txFrom.GetHash())
        return false;

    return VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, fValidatePayToScriptHash, nHashType);
}
