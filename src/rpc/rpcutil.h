#ifndef RPCUTIL_H
#define RPCUTIL_H

#include "amount.h"
#include "uint256.h"
#include <vector>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

/**
 * Utilities: convert hex-encoded Values
 * (throws error if not hex).
 */
uint256 ParseHashV(const json_spirit::Value& v, std::string strName);
uint256 ParseHashO(const json_spirit::Object& o, std::string strKey);
std::vector<unsigned char> ParseHexV(const json_spirit::Value& v, std::string strName);
std::vector<unsigned char> ParseHexO(const json_spirit::Object& o, std::string strKey);

CAmount AmountFromValue(const json_spirit::Value& value);
json_spirit::Value ValueFromAmount(const CAmount& amount);
std::string HexBits(unsigned int nBits);

inline std::string leftTrim(std::string src, char chr)
{
    std::string::size_type pos = src.find_first_not_of(chr, 0);

    if(pos > 0)
        src.erase(0, pos);

    return src;
}


#endif // RPCUTIL_H
