#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <map>
#include <string>
#include <stdint.h>
#include <functional>

extern std::string strRPCUserColonPass;

std::string HTTPPost(const std::string& strMsg, const std::map<std::string,std::string>& mapRequestHeaders);
int ReadHTTPStatus(std::basic_istream<char>& stream, int &proto);
int ReadHTTPHeader(std::basic_istream<char>& stream, std::map<std::string, std::string>& mapHeadersRet);
int ReadHTTP(std::basic_istream<char>& stream, std::map<std::string, std::string>& mapHeadersRet, std::string& strMessageRet);
bool HTTPAuthorized(std::map<std::string, std::string>& mapHeaders);
std::string HTTPReply(int nStatus, const std::string& strMsg, bool keepalive);


#endif // HTTPSERVER_H
