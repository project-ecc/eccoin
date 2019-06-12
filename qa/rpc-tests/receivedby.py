#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# Exercise the listreceivedbyaddress API

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


def get_sub_array_from_array(object_array, to_match):
    '''
        Finds and returns a sub array from an array of arrays.
        to_match should be a unique idetifier of a sub array
    '''
    num_matched = 0
    for item in object_array:
        all_match = True
        for key,value in to_match.items():
            if item[key] != value:
                all_match = False
        if not all_match:
            continue
        return item
    return []

class ReceivedByTest(BitcoinTestFramework):

    def setup_nodes(self):
        enable_mocktime()
        return start_nodes(4, self.options.tmpdir)

    def run_test(self):
        '''
        listreceivedbyaddress Test
        '''
        # Send from node 0 to 1
        addr = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress(addr, 0.1)
        self.sync_all()

        #Check not listed in listreceivedbyaddress because has 0 confirmations
        assert_array_result(self.nodes[1].listreceivedbyaddress(),
                           {"address":addr},
                           { },
                           True)
        #Bury Tx under 10 block so it will be returned by listreceivedbyaddress
        self.nodes[1].generate(10)
        self.sync_all()
        assert_array_result(self.nodes[1].listreceivedbyaddress(),
                           {"address":addr},
                           {"address":addr, "amount":Decimal("0.1"), "confirmations":10, "txids":[txid,]})
        #With min confidence < 10
        assert_array_result(self.nodes[1].listreceivedbyaddress(5),
                           {"address":addr},
                           {"address":addr, "amount":Decimal("0.1"), "confirmations":10, "txids":[txid,]})
        #With min confidence > 10, should not find Tx
        assert_array_result(self.nodes[1].listreceivedbyaddress(11),{"address":addr},{ },True)

        #Empty Tx
        addr = self.nodes[1].getnewaddress()
        assert_array_result(self.nodes[1].listreceivedbyaddress(0,True),
                           {"address":addr},
                           {"address":addr, "amount":0, "confirmations":0, "txids":[]})

        '''
            getreceivedbyaddress Test
        '''
        # Send from node 0 to 1
        addr = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress(addr, 0.1)
        self.sync_all()

        #Check balance is 0 because of 0 confirmations
        balance = self.nodes[1].getreceivedbyaddress(addr)
        if balance != Decimal("0.0"):
            raise AssertionError("Wrong balance returned by getreceivedbyaddress, %0.2f"%(balance))

        #Check balance is 0.1
        balance = self.nodes[1].getreceivedbyaddress(addr,0)
        if balance != Decimal("0.1"):
            raise AssertionError("Wrong balance returned by getreceivedbyaddress, %0.2f"%(balance))

        #Bury Tx under 10 block so it will be returned by the default getreceivedbyaddress
        self.nodes[1].generate(10)
        self.sync_all()
        balance = self.nodes[1].getreceivedbyaddress(addr)
        if balance != Decimal("0.1"):
            raise AssertionError("Wrong balance returned by getreceivedbyaddress, %0.2f"%(balance))

if __name__ == '__main__':
    ReceivedByTest().main()
