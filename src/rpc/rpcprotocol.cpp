
#include "rpc/rpcprotocol.h"

#include "random.h"
#include "tinyformat.h"
#include "util/util.h"
#include "util/utilstrencodings.h"
#include "version.h"

#include <stdint.h>
#include <fstream>

#include "json/json_spirit_reader_template.h"
#include "json/json_spirit_writer_template.h"
#include "json/json_spirit_utils.h"

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 *
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 */

json_spirit::Object JSONRPCReplyObj(const json_spirit::Value& result, const json_spirit::Value& error, const json_spirit::Value& id)
{
    json_spirit::Object reply;
    if (error.type() != json_spirit::null_type)
        reply.push_back(json_spirit::Pair("result", json_spirit::Value::null));
    else
        reply.push_back(json_spirit::Pair("result", result));
    reply.push_back(json_spirit::Pair("error", error));
    reply.push_back(json_spirit::Pair("id", id));
    return reply;
}

std::string JSONRPCReply(const json_spirit::Value& result, const json_spirit::Value& error, const json_spirit::Value& id)
{
    json_spirit::Object reply = JSONRPCReplyObj(result, error, id);
    return write_string(json_spirit::Value(reply), false) + "\n";
}

json_spirit::Object JSONRPCError(int code, const std::string& message)
{
    json_spirit::Object error;
    error.push_back(json_spirit::Pair("code", code));
    error.push_back(json_spirit::Pair("message", message));
    return error;
}

