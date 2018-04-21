/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "rpcprotocol.h"

#include "random.h"
#include "tinyformat.h"
#include "util/util.h"
#include "args.h"
#include "util/utilstrencodings.h"
#include "util/utiltime.h"
#include "version.h"

#include <stdint.h>
#include <fstream>

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 * 
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 */

UniValue JSONRPCRequestObj(const std::string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ);
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return request;
}

std::string JSONRPCRequest(const std::string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ);
    request.push_back(Pair("method", strMethod));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", id));
    return request.write() + "\n";
}

UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply(UniValue::VOBJ);
    if (!error.isNull())
        reply.push_back(Pair("result", NullUniValue));
    else
        reply.push_back(Pair("result", result));
    reply.push_back(Pair("error", error));
    reply.push_back(Pair("id", id));
    return reply;
}

std::string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply = JSONRPCReplyObj(result, error, id);
    return reply.write() + "\n";
}

UniValue JSONRPCError(int code, const std::string& message)
{
    UniValue error(UniValue::VOBJ);
    error.push_back(Pair("code", code));
    error.push_back(Pair("message", message));
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";
/** Default name for auth cookie file */
static const std::string COOKIEAUTH_FILE = ".cookie";

boost::filesystem::path GetAuthCookieFile()
{
    boost::filesystem::path path(gArgs.GetArg("-rpccookiefile", COOKIEAUTH_FILE));
    if (!path.is_complete()) path = GetDataDir() / path;
    return path;
}

bool GenerateAuthCookie(std::string *cookie_out)
{
    unsigned char rand_pwd[32];
    GetRandBytes(rand_pwd, 32);
    std::string cookie = COOKIEAUTH_USER + ":" + EncodeBase64(&rand_pwd[0],32);

    /** the umask determines what permissions are used to create this file -
     * these are set to 077 in init.cpp unless overridden with -sysperms.
     */
    std::ofstream file;
    boost::filesystem::path filepath = GetAuthCookieFile();
    file.open(filepath.string().c_str());
    if (!file.is_open()) {
        LogPrintf("Unable to open cookie authentication file %s for writing\n", filepath.string());
        return false;
    }
    file << cookie;
    file.close();
    LogPrintf("Generated RPC authentication cookie %s\n", filepath.string());

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    boost::filesystem::path filepath = GetAuthCookieFile();
    file.open(filepath.string().c_str());
    if (!file.is_open())
        return false;
    std::getline(file, cookie);
    file.close();

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

void DeleteAuthCookie()
{
    try {
        boost::filesystem::remove(GetAuthCookieFile());
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, e.what());
    }
}

std::vector<UniValue> JSONRPCProcessBatchReply(const UniValue &in, size_t num)
{
    if (!in.isArray()) {
        throw std::runtime_error("Batch must be an array");
    }
    std::vector<UniValue> batch(num);
    for (size_t i=0; i<in.size(); ++i) {
        const UniValue &rec = in[i];
        if (!rec.isObject()) {
            throw std::runtime_error("Batch member must be object");
        }
        size_t id = rec["id"].get_int();
        if (id >= num) {
            throw std::runtime_error("Batch member id larger than size");
        }
        batch[id] = rec;
    }
    return batch;
}
