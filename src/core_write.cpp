// This file is part of the Eccoin project
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "base58.h"
#include "chain/tx.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include "util/util.h"
#include "util/utilmoneystr.h"
#include "util/utilstrencodings.h"

#include <boost/assign/list_of.hpp>

std::string FormatScript(const CScript &script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end())
    {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch))
        {
            if (op == OP_0)
            {
                ret += "0 ";
                continue;
            }
            else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE)
            {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            }
            else if (op >= OP_NOP && op <= OP_CHECKMULTISIGVERIFY)
            {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_"))
                {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0)
            {
                ret += strprintf("0x%x 0x%x ", HexStr(it2, it - vch.size()), HexStr(it - vch.size(), it));
            }
            else
            {
                ret += strprintf("0x%x", HexStr(it2, it));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(it2, script.end()));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

const std::map<unsigned char, std::string> mapSigHashTypes =
    boost::assign::map_list_of(static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL"))(
        static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
        std::string("ALL|ANYONECANPAY"))(static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE"))(
        static_cast<unsigned char>(SIGHASH_NONE | SIGHASH_ANYONECANPAY),
        std::string("NONE|ANYONECANPAY"))(static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE"))(
        static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
        std::string("SINGLE|ANYONECANPAY"));

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches
 * the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures.
 * For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript &script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end())
    {
        if (!str.empty())
        {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch))
        {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4)
        {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4))
            {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            }
            else
            {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a
                // signature
                if (fAttemptSighashDecode && !script.IsUnspendable())
                {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within
                    // a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous
                    // with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, NULL))
                    {
                        const unsigned char chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType))
                        {
                            strSigHashDecode = "[" + mapSigHashTypes.find(chSigHashType)->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                }
                else
                {
                    str += HexStr(vch);
                }
            }
        }
        else
        {
            str += GetOpName(opcode);
        }
    }
    return str;
}

std::string EncodeHexTx(const CTransaction &tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}
