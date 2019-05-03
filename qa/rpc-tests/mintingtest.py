#!/usr/bin/env python3
# Copyright (c) 2015-2018 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Test the block storage methods
WARNING:
This test may take 10 mins or more to complete if not in fastRun mode
"""

import test_framework.loginit

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from random import randint


class MintingTest (BitcoinTestFramework):

    def __init__(self):
        self.generatedblocks = 500
        self.mintedblocks = 3
        self.blockstotest = 5
        self.maxtxperblock = 3

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 3, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ))
        self.nodes.append(start_node(1, self.options.tmpdir, ))
        self.nodes.append(start_node(2, self.options.tmpdir, ))
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):

        self.sync_blocks()

        # generate non-empty blocks on the mining node
        for x in range(0, self.generatedblocks):
            self.nodes[0].generate(1)
            if x % 25 == 0:
                self.sync_blocks()

        self.sync_blocks()
        time.sleep(25)

        # check that nodes across different db's have the same data
        for x in range(0, self.blockstotest):
            randblocknum = randint(1, self.generatedblocks)
            assert_equal(self.nodes[0].getblock(self.nodes[0].getblockhash(randblocknum), False),
                         self.nodes[1].getblock(self.nodes[1].getblockhash(randblocknum), False))
            assert_equal(self.nodes[1].getblock(self.nodes[1].getblockhash(randblocknum), False),
                         self.nodes[2].getblock(self.nodes[2].getblockhash(randblocknum), False))

        # test to make sure tips are equal
        assert_equal(self.nodes[0].getblockhash(self.generatedblocks), self.nodes[1].getblockhash(self.generatedblocks))
        assert_equal(self.nodes[1].getblockhash(self.generatedblocks), self.nodes[2].getblockhash(self.generatedblocks))

        # generate empty pos blocks on the mining node
        for x in range(0, self.mintedblocks):
            self.nodes[0].generatepos(1)
            self.sync_blocks()

        self.sync_blocks()

        # check that nodes across different db's have the same data
        for x in range(0, self.blockstotest):
            randblocknum = randint(1, self.generatedblocks + self.mintedblocks)
            assert_equal(self.nodes[0].getblock(self.nodes[0].getblockhash(randblocknum), False),
                         self.nodes[1].getblock(self.nodes[1].getblockhash(randblocknum), False))
            assert_equal(self.nodes[1].getblock(self.nodes[1].getblockhash(randblocknum), False),
                         self.nodes[2].getblock(self.nodes[2].getblockhash(randblocknum), False))

        # test to make sure tips are equal
        assert_equal(self.nodes[0].getblockhash(self.generatedblocks), self.nodes[1].getblockhash(self.generatedblocks))
        assert_equal(self.nodes[1].getblockhash(self.generatedblocks), self.nodes[2].getblockhash(self.generatedblocks))

        # generate not empty pos blocks on the mining node
        for x in range(0, self.mintedblocks):
            for y in range(1, self.maxtxperblock):
                self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
            self.nodes[0].generatepos(1)
            self.sync_blocks()

        self.sync_blocks()

        # check that nodes across different db's have the same data
        for x in range(0, self.blockstotest):
            randblocknum = randint(1, self.generatedblocks + (self.mintedblocks * 2))
            assert_equal(self.nodes[0].getblock(self.nodes[0].getblockhash(randblocknum), False),
                         self.nodes[1].getblock(self.nodes[1].getblockhash(randblocknum), False))
            assert_equal(self.nodes[1].getblock(self.nodes[1].getblockhash(randblocknum), False),
                         self.nodes[2].getblock(self.nodes[2].getblockhash(randblocknum), False))

        # test to make sure tips are equal
        assert_equal(self.nodes[0].getblockhash(self.generatedblocks), self.nodes[1].getblockhash(self.generatedblocks))
        assert_equal(self.nodes[1].getblockhash(self.generatedblocks), self.nodes[2].getblockhash(self.generatedblocks))



if __name__ == '__main__':
    MintingTest().main()


def Test():
    t = MintingTest()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000  # we don't want any transactions rejected due to insufficient fees...
    }

    flags = []
    # you may want these additional flags:
    # flags.append("--nocleanup")
    # flags.append("--noshutdown")

    # Execution is much faster if a ramdisk is used, so use it if one exists in a typical location
    if os.path.isdir("/ramdisk/test"):
        flags.append("--tmpdir=/ramdisk/test")

    # Out-of-source builds are awkward to start because they need an additional flag
    # automatically add this flag during testing for common out-of-source locations
    here = os.path.dirname(os.path.abspath(__file__))
    if not os.path.exists(os.path.abspath(here + "/../../src/eccoind")):
        dbg = os.path.abspath(here + "/../../debug/src/eccoind")
        rel = os.path.abspath(here + "/../../release/src/eccoind")
        if os.path.exists(dbg):
            print("Running from the debug directory (%s)" % dbg)
            flags.append("--srcdir=%s" % os.path.dirname(dbg))
        elif os.path.exists(rel):
            print("Running from the release directory (%s)" % rel)
            flags.append("--srcdir=%s" % os.path.dirname(rel))

t.main(flags, bitcoinConf, None)
