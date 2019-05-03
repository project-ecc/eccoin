// Copyright (c) 2012-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/rpcclient.h"
#include "rpc/rpcserver.h"

#include "base58.h"
#include "net/netbase.h"

#include "test/test_bitcoin.h"

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

UniValue CallRPC(std::string args)
{
    std::vector<std::string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    UniValue params = RPCConvertValues(strMethod, vArgs);
    // calling boost_check here sets the last checkpoint to a useless position
    if (!tableRPC[strMethod])
        BOOST_CHECK(tableRPC[strMethod]);
    rpcfn_type method = tableRPC[strMethod]->actor;
    try
    {
        UniValue result = (*method)(params, false);
        return result;
    }
    catch (const UniValue &objError)
    {
        throw std::runtime_error(find_value(objError, "message").get_str());
    }
}

BOOST_FIXTURE_TEST_SUITE(rpc_tests, TestingSetup)

/*
BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction "
                              "a3b807410df0b60fcb9736768df5823938b2f838694939ba"
                              "45f3c0a1bff150ed not_int"),
        std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] []"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {} extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), std::runtime_error);
    std::string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a9"
                        "9ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0ef"
                        "e71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b17"
                        "36ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc31071"
                        "1c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b383"
                        "9e2bbf32d826a1e222031fd888ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ") + rawtx));
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "size").get_int(), 193);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "version").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "locktime").get_int(), 0);
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ") + rawtx + " extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("signrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction ff00"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC(std::string("signrawtransaction ") + rawtx));
    BOOST_CHECK_NO_THROW(CallRPC(std::string("signrawtransaction ") + rawtx + " null null NONE|ANYONECANPAY"));
    BOOST_CHECK_NO_THROW(CallRPC(std::string("signrawtransaction ") + rawtx + " [] [] NONE|ANYONECANPAY"));
    BOOST_CHECK_THROW(CallRPC(std::string("signrawtransaction ") + rawtx + " null null badenum"), std::runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to
    // send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(std::string("sendrawtransaction ") + rawtx + " extra"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    // input is a 1-of-2 multisig (so is output):
    std::string prevout = "[{\"txid\":"
                          "\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b724"
                          "8f50977c8493f3\","
                          "\"vout\":1,\"scriptPubKey\":"
                          "\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
                          "\"amount\":3.14159,"
                          "\"redeemScript\":"
                          "\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998"
                          "abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ece"
                          "fca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    r = CallRPC(std::string("createrawtransaction ") + prevout + " " + "{\"EZTeaB5K4zBE9J2NmptRSdZxcZRZM6ahqe\":11}");
    std::string notsigned = r.get_str();
    std::string privkey1 = "\"QwmG4wQZ3d2tREdYGd8sKGK5dgU1LoFqZia8ShU7XKSF5YocpV2Z\"";
    std::string privkey2 = "\"QtxuJ7ZkQzjmCoFNmiJsuu6BMwc3xpWV2ppKaXhq2yo8Tz8DfXTe\"";
    r = CallRPC(std::string("signrawtransaction ") + notsigned + " " + prevout + " " + "[]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == false);
    r = CallRPC(
        std::string("signrawtransaction ") + notsigned + " " + prevout + " " + "[" + privkey1 + "," + privkey2 + "]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign_missing_amount)
{
    // Old format, missing amount parameter for prevout should generate
    // an RPC error.  This is because of new replay-protected tx's require
    // nonzero amount present in signed tx.
    // See: https://github.com/Bitcoin-ABC/bitcoin-abc/issues/63
    // (We will re-use the tx + keys from the above rpc_rawsign test for
    // simplicity.)
    UniValue r;
    std::string prevout = "[{\"txid\":"
                          "\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b724"
                          "8f50977c8493f3\","
                          "\"vout\":1,\"scriptPubKey\":"
                          "\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
                          "\"redeemScript\":"
                          "\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998"
                          "abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ece"
                          "fca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    r = CallRPC(std::string("createrawtransaction ") + prevout + " " + "{\"EZTeaB5K4zBE9J2NmptRSdZxcZRZM6ahqe\":11}");
    std::string notsigned = r.get_str();
    std::string privkey1 = "\"KzsXybp9jX64P5ekX1KUxRQ79Jht9uzW7LorgwE65i5rWACL6LQe\"";
    std::string privkey2 = "\"Kyhdf5LuKTRx4ge69ybABsiUAWjVRK4XGxAKk2FQLp2HjGMy87Z4\"";
    bool exceptionThrownDueToMissingAmount = false, errorWasMissingAmount = false;
    try
    {
        r = CallRPC(std::string("signrawtransaction ") + notsigned + " " + prevout + " " + "[" + privkey1 + "," +
                    privkey2 + "]");
    }
    catch (const std::runtime_error &e)
    {
        exceptionThrownDueToMissingAmount = true;
        if (std::string(e.what()).find("amount") != std::string::npos)
        {
            errorWasMissingAmount = true;
        }
    }
    BOOST_CHECK(exceptionThrownDueToMissingAmount == true);
    BOOST_CHECK(errorWasMissingAmount == true);
}
*/

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction "
                                 "[{\"txid\":"
                                 "\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff1"
                                 "50ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\"}"));

    // Allow more than one data transaction output
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction "
                                 "[{\"txid\":"
                                 "\"a3b807410df0b60fcb9736768df5823938b2f838694"
                                 "939ba45f3c0a1bff150ed\",\"vout\":0}] "
                                 "{\"data\":\"68656c6c6f776f726c64\",\"data\":"
                                 "\"68656c6c6f776f726c64\"}"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"txid\":"
                              "\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff1"
                              "50ed\",\"vout\":0}] {\"somedata\":\"68656c6c6f776f726c64\"}"),
        std::runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"txid\":"
                              "\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff1"
                              "50ed\",\"vout\":0}] {\"data\":\"12345\"}"),
        std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction "
                              "[{\"txid\":"
                              "\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff1"
                              "50ed\",\"vout\":0}] {\"data\":\"12345g\"}"),
        std::runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction "
                                 "[{\"txid\":"
                                 "\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff1"
                                 "50ed\",\"vout\":0}] "
                                 "{\"data\":"
                                 "\"010203040506070809101112131415161718192021222324252627282930"
                                 "31323334353637383940414243444546474849505152535455565758596061"
                                 "6263646566676869707172737475767778798081\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(CAmount(0LL)).write() == "0.000000");
    BOOST_CHECK(ValueFromAmount(CAmount(1LL)).write() == "0.000001");
    BOOST_CHECK(ValueFromAmount(CAmount(17622195LL)).write() == "17.622195");
    BOOST_CHECK(ValueFromAmount(CAmount(50000000LL)).write() == "50.000000");
    BOOST_CHECK(ValueFromAmount(CAmount(89898989LL)).write() == "89.898989");
    BOOST_CHECK(ValueFromAmount(CAmount(100000000LL)).write() == "100.000000");
    BOOST_CHECK(ValueFromAmount(CAmount(2099999999999990LL)).write() == "2099999999.999990");
    BOOST_CHECK(ValueFromAmount(CAmount(2099999999999999LL)).write() == "2099999999.999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(CAmount(0)).write(), "0.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(123456789 * (COIN / 10000)).write(), "12345.678900");
    BOOST_CHECK_EQUAL(ValueFromAmount(-1 * COIN).write(), "-1.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-1 * COIN / 10).write(), "-0.100000");

    BOOST_CHECK_EQUAL(ValueFromAmount(100000000 * COIN).write(), "100000000.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(10000000 * COIN).write(), "10000000.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(1000000 * COIN).write(), "1000000.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(100000 * COIN).write(), "100000.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(10000 * COIN).write(), "10000.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(1000 * COIN).write(), "1000.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(100 * COIN).write(), "100.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(10 * COIN).write(), "10.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 10).write(), "0.100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 100).write(), "0.010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 1000).write(), "0.001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 10000).write(), "0.000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 100000).write(), "0.000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 1000000).write(), "0.000001");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 10000000).write(), "0.000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN / 100000000).write(), "0.000000");
}

static UniValue ValueFromString(const std::string &str)
{
    UniValue value;
    BOOST_CHECK(value.setNumStr(str));
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), CAmount(0LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000")), CAmount(0LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000001")), CAmount(1LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.176221")), CAmount(176221LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), CAmount(500000LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("50.000000")), CAmount(50000000LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("89.898989")), CAmount(89898989LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("100.000000")), CAmount(100000000LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("2099999999.99999")), CAmount(2099999999999990LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("2099999999.999999")), CAmount(2099999999999999LL));
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-6")), SATOSHI);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-5")), SATOSHI);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-4")), SATOSHI);
    BOOST_CHECK_EQUAL(AmountFromValue_Original(ValueFromString("0.00000"
                                                               "00000000000000000000000000000000000000000000000000"
                                                               "0000000000001e+62")),
        SATOSHI);
    BOOST_CHECK_EQUAL(AmountFromValue_Original(ValueFromString("10000000000000000000000000000000000000"
                                                               "0000000000000000000000000e-62")),
        COIN);
    BOOST_CHECK_EQUAL(
        AmountFromValue_Original(ValueFromString("0."
                                                 "000000000000000000000000000000000000000000000000000000000000010000"
                                                 "00000000000000000000000000000000000000000000000000000e62")),
        COIN);

    // should fail
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("1e-9")), UniValue);
    // should fail
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("0.000000019")), UniValue);
    // should pass, cut trailing 0
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000100000000")), CAmount(1LL));
    // should fail
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("19e-9")), UniValue);
    // should pass, leading 0 is present
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-4")), CAmount(19));

    // overflow error
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("92233720368.54775808")), UniValue);
    // overflow error
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("1e+11")), UniValue);
    // overflow error signless
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("1e11")), UniValue);
    // overflow error
    BOOST_CHECK_THROW(AmountFromValue_Original(ValueFromString("93e+9")), UniValue);
}

BOOST_AUTO_TEST_CASE(json_parse_errors)
{
    // Valid
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0").get_real(), 1.0);
    // Valid, with leading or trailing whitespace
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue(" 1.0").get_real(), 1.0);
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0 ").get_real(), 1.0);

    // should fail, missing leading 0, therefore invalid JSON
    BOOST_CHECK_THROW(AmountFromValue(ParseNonRFCJSONValue(".19e-6")), std::runtime_error);
    BOOST_CHECK_EQUAL(
        AmountFromValue(ParseNonRFCJSONValue("0.00000000000000000000000000000000000001e+30 ")), CAmount(0));
    // Invalid, initial garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("[1.0"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("a1.0"), std::runtime_error);
    // Invalid, trailing garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0sds"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0]"), std::runtime_error);
    // BCH addresses should fail parsing
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0 add")));
    // portnumber for setban not allowed
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.0:8334")), std::runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 1607731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    UniValue banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    // absolute time check
    BOOST_CHECK_EQUAL(banned_until.get_int64(), 1607731200);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 200")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    int64_t now = GetTime();
    BOOST_CHECK(banned_until.get_int64() > now);
    BOOST_CHECK(banned_until.get_int64() - now <= 200);

    // must throw an exception because 127.0.0.1 is in already banned subnet
    // range
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.1.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0UL);

    // invalid IP
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban test add")), std::runtime_error);

    // IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_convert_values_generatetoaddress)
{
    UniValue result;

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");

    BOOST_CHECK_NO_THROW(result = RPCConvertValues("generatetoaddress", {"101", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 101);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");

    BOOST_CHECK_NO_THROW(
        result = RPCConvertValues("generatetoaddress", {"1", "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a", "9"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mkESjLZW66TmHhiFX8MCaBjrhZ543PPh9a");
    BOOST_CHECK_EQUAL(result[2].get_int(), 9);

    BOOST_CHECK_NO_THROW(
        result = RPCConvertValues("generatetoaddress", {"1", "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU", "9"}));
    BOOST_CHECK_EQUAL(result[0].get_int(), 1);
    BOOST_CHECK_EQUAL(result[1].get_str(), "mhMbmE2tE9xzJYCV9aNC8jKWN31vtGrguU");
    BOOST_CHECK_EQUAL(result[2].get_int(), 9);
}

BOOST_AUTO_TEST_SUITE_END()
