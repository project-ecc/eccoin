#include <stdint.h>
#include <univalue.h>

#include "ans/ans.h"
#include "rpcserver.h"

AnsRecordTypes resolveRecordType(std::string strRecordType)
{
    AnsRecordTypes recordtype;
    if(strRecordType == "A" || strRecordType == "a")
    {
        recordtype = AnsRecordTypes::A_RECORD;
    }
    else if(strRecordType == "CNAME" || strRecordType == "cname")
    {
        recordtype = AnsRecordTypes::CNAME_RECORD;
    }
    else if(strRecordType == "PTR" || strRecordType == "ptr")
    {
        recordtype = AnsRecordTypes::PTR_RECORD;
    }
    else
    {
        recordtype = AnsRecordTypes::UNKNOWN_RECORD;
    }
    return recordtype;
}

UniValue getansrecordset(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getansrecordset \"recordType\"\n"
            "\nReturn the records in the requested record set.\n"
            "\nArguments:\n"
            "1. \"record type\"     (string, required) The record set to fetch. recordTypes are A, CNAME, PTR\n"
            "\nResult:\n"
            "{\n                  (json array of name-address pairs)\n"
            "  \"name, address\"  (string) a bitcoin address associated with the given account\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getansrecordset", "\"A\"")
            + HelpExampleRpc("getansrecordset", "\"CNAME\"")
        );
    std::string strRecordType = params[0].get_str();
    AnsRecordTypes recordtype = resolveRecordType(strRecordType);
    UniValue ret(UniValue::VOBJ);
    if(recordtype == AnsRecordTypes::UNKNOWN_RECORD)
    {
        ret.push_back(Pair("ERROR", "invalid record type requested. Valid record types are: A, CNAME, PTR"));
        return ret;
    }
    recordSet records = pansMain->getRecordSet(recordtype);
    if(records.size() == 0)
    {
        ret.push_back(Pair("ERROR", "the record set requested contains no records"));
        return ret;
    }
    for ( recordSet::iterator iter = records.begin(); iter != records.end(); ++iter )
    {
        ret.push_back(Pair(iter->first, iter->second.getValue()));
    }
    return ret;
}


UniValue getansrecord(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getansrecord \"record name\" \"record type\" \n"
            "\nReturn the full record with the record name.\n"
            "\nArguments:\n"
            "1. \"record name\"     (string, required) The fetch the record with the provided record name\n"
            "2. \"record type\"     (string, optional) Search only this recordset for the provided record name\n"
            "\nResult:\n"
            "{\n                  (json array of name-address pairs)\n"
            "  \"name, address\"  (string) a bitcoin address associated with the given account\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getansrecordset", "\"A\"")
            + HelpExampleRpc("getansrecordset", "\"CNAME\"")
        );
    std::string strRecordName = params[0].get_str();
    AnsRecordTypes recordtype = AnsRecordTypes::UNKNOWN_RECORD;
    CAnsRecord record = CAnsRecord();
    UniValue ret(UniValue::VOBJ);
    if(params.size() == 2)
    {
        recordtype = resolveRecordType(params[1].get_str());
        record = pansMain->getRecord(recordtype, strRecordName);
    }
    else
    {
        if(strRecordName.size() <= 25)
        {
            recordSet Arecords = pansMain->getRecordSet(AnsRecordTypes::A_RECORD);
            recordSet::iterator Aiter = Arecords.find(strRecordName);
            if(Aiter != Arecords.end())
            {
                record = Aiter->second;
            }
            else
            {
                recordSet CNAMErecords = pansMain->getRecordSet(AnsRecordTypes::CNAME_RECORD);
                recordSet::iterator CNAMEiter = CNAMErecords.find(strRecordName);
                if(CNAMEiter != CNAMErecords.end())
                {
                    record = CNAMEiter->second;
                }
            }
        }
        else
        {
            recordSet records = pansMain->getRecordSet(AnsRecordTypes::PTR_RECORD);
            for ( recordSet::iterator iter = records.begin(); iter != records.end(); ++iter )
            {
                ret.push_back(Pair(iter->first, iter->second.getValue()));
            }
        }
    }
    if(record == CAnsRecord())
    {
        ret.push_back(Pair("ERROR", "there is no record with that record name"));
        return ret;
    }
    ret.push_back(Pair("Key"        , strRecordName                    ));
    ret.push_back(Pair("Value"      , record.getValue()                ));
    ret.push_back(Pair("ExpireTime" , record.getExpireTime()           ));
    ret.push_back(Pair("paymentHash", record.getPaymentHash().GetHex() ));
    ret.push_back(Pair("ServiceHash", record.getServiceHash().GetHex() ));
    return ret;
}
