#!/usr/bin/env python3
# Copyright (c) 2014-2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import binascii
from test_framework.script import *
from test_framework.nodemessages import *
from random import randint

class VerifyDbTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.node_args = [['-usehd=0'], ['-usehd=0']]
        self.nodes = start_nodes(2, self.options.tmpdir, self.node_args)
        connect_nodes_bi(self.nodes,0,1)
        self.is_network_split=False
        self.sync_all()

    def run_test (self):

        # Check that there's no UTXO on none of the nodes
        assert_equal(len(self.nodes[0].listunspent()), 0)
        assert_equal(len(self.nodes[1].listunspent()), 0)

        logging.info("Mining blocks...")

        self.nodes[0].generate(1)

        walletinfo = self.nodes[0].getwalletinfo()
        assert_equal(walletinfo['immature_balance'], 50)
        assert_equal(walletinfo['balance'], 0)

        self.sync_all()
        self.nodes[1].generate(31)
        self.sync_all()

        # get to 100 blocks
        for i in range (68):
            self.nodes[1].generate(1)
            if i % 15 == 0:
                j = randint(1, 5)
                for k in range(j):
                    self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
                self.sync_all()
        self.sync_all()

        #get to 500 blocks
        for i in range (100):
            self.nodes[0].generate(1)
            if i % 15 == 0:
                j = randint(1, 5)
                for k in range(j):
                    self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
                self.sync_all()
        self.sync_all()

        for i in range (100):
            self.nodes[1].generate(1)
            if i % 25 == 0:
                self.sync_all()
        self.sync_all()

        for i in range (100):
            self.nodes[0].generate(1)
            if i % 25 == 0:
                self.sync_all()
        self.sync_all()

        for i in range (100):
            self.nodes[1].generate(1)
            if i % 25 == 0:
                j = randint(1, 5)
                for k in range(j):
                    self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
                self.sync_all()
        self.sync_all()
        #pos blocks
        for i in range (100):
            self.nodes[1].generatepos(1)
            if i % 25 == 0:
                j = randint(1, 5)
                for k in range(j):
                    self.nodes[1].sendtoaddress(self.nodes[0].getnewaddress(), 1)
                self.sync_all()
        self.sync_all()

        #stop the nodes
        stop_nodes(self.nodes)
        wait_bitcoinds()

        # start the nodes again with high db checks
        self.node_args = [['-checklevel=4', '-checkblocks=0'], ['-checklevel=4', '-checkblocks=0']]
        self.nodes = start_nodes(2, self.options.tmpdir, self.node_args)
        
        #stop the nodes
        stop_nodes(self.nodes)
        wait_bitcoinds()




if __name__ == '__main__':
    VerifyDbTest ().main ()

def Test():
    t = VerifyDbTest()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],  # "lck"
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }
    # "--tmppfx=/ramdisk/test", "--srcdir=../../debug/src"
    t.main(["--nocleanup", "--noshutdown"], bitcoinConf, None)
