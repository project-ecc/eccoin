#ifndef JSONRPC_H
#define JSONRPC_H

#include <unordered_map>
#include <boost/algorithm/string.hpp>
#include "rpcprotocol.h"
#include <string>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

using namespace json_spirit;

class JSONRequest
{
public:
    Value id;
    std::string strMethod;
    Array params;

    JSONRequest() { id = Value::null; }
    void parse(const Value& valRequest);
};

std::string JSONRPCRequest(const std::string& strMethod, const Array& params, const Value& id);
void ErrorReply(std::ostream& stream, const Object& objError, const Value& id);


#endif // JSONRPC_H
