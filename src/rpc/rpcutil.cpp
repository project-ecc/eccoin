#include "rpcutil.h"
#include "jsonrpc.h"
#include "rpcprotocol.h"
#include "util/utilstrencodings.h"
#include "tinyformat.h"
#include "util/util.h"

int64_t AmountFromValue(const Value& value)
{
    double dAmount = value.get_real();
    if (dAmount <= 0.0 || dAmount > 50000000.0)
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    int64_t nAmount = roundint64(dAmount * COIN);
    if (!MoneyRange(nAmount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    return nAmount;
}

json_spirit::Value ValueFromAmount(const CAmount& amount)
{
    return (double)amount / (double)COIN;
}

int64_t ValueFromAmountAsInt(int64_t amount)
{
    return amount / COIN;
}

uint256 ParseHashV(const Value& v, std::string strName)
{
    std::string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    uint256 result;
    result.SetHex(strHex);
    return result;
}

uint256 ParseHashO(const Object& o, std::string strKey)
{
    return ParseHashV(find_value(o, strKey), strKey);
}

std::vector<unsigned char> ParseHexV(const Value& v, std::string strName)
{
    std::string strHex;
    if (v.type() == str_type)
        strHex = v.get_str();
    if (!IsHex(strHex))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName+" must be hexadecimal string (not '"+strHex+"')");
    return ParseHex(strHex);
}

std::vector<unsigned char> ParseHexO(const Object& o, std::string strKey)
{
    return ParseHexV(find_value(o, strKey), strKey);
}

std::string HexBits(unsigned int nBits)
{
    union {
        int32_t nBits;
        char cBits[4];
    } uBits;
    uBits.nBits = htonl((int32_t)nBits);
    return HexStr(BEGIN(uBits.cBits), END(uBits.cBits));
}

