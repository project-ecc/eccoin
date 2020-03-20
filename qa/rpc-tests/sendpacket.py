#!/usr/bin/env python3
# Copyright (c) 2019 Greg Griffith
# Copyright (c) 2019 The Eccoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
# This is a template to make creating new QA tests easy.
# You can also use this template to quickly start and connect a few regtest nodes.

import time
import sys
if sys.version_info[0] < 3:
    raise "Use Python 3"
import logging

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class SendPacketTest (BitcoinTestFramework):

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        # pick this one to start from the cached 4 node 100 blocks mined configuration
        # initialize_chain(self.options.tmpdir)
        # pick this one to start at 0 mined blocks
        initialize_chain_clean(self.options.tmpdir, 6, bitcoinConfDict, wallets)
        # Number of nodes to initialize ----------> ^

    def setup_network(self, split=False):
        self.nodes = start_nodes(6, self.options.tmpdir)
        connect_nodes_bi(self.nodes,0,1)
        connect_nodes_bi(self.nodes,1,2)
        connect_nodes_bi(self.nodes,2,3)
        connect_nodes_bi(self.nodes,4,5)
        connect_nodes_bi(self.nodes,3,4)
        self.is_network_split=False
        self.sync_all()

    def run_test (self):
        self.sync_blocks()

        for x in range(0, 1):
            self.nodes[0].generate(1);
            self.sync_blocks()

        assert_not_equal(self.nodes[0].getconnectioncount(), 3)
        assert_not_equal(self.nodes[1].getconnectioncount(), 3)
        assert_not_equal(self.nodes[2].getconnectioncount(), 3)
        assert_not_equal(self.nodes[3].getconnectioncount(), 3)

        key0 = self.nodes[0].getroutingpubkey()
        key1 = self.nodes[1].getroutingpubkey()
        key2 = self.nodes[2].getroutingpubkey()
        key3 = self.nodes[3].getroutingpubkey()
        key4 = self.nodes[4].getroutingpubkey()
        key5 = self.nodes[5].getroutingpubkey()
        self.nodes[0].findroute(key5)
        time.sleep(1)
        assert_equal(self.nodes[0].haveroute(key5), True)
        time.sleep(1)
        sent = self.nodes[0].sendpacket(key5, 0, 0, "test string1")
        time.sleep(1)
        assert_equal(sent, True)
        sent = self.nodes[0].sendpacket(key5, 0, 0, "test string2")
        time.sleep(1)
        assert_equal(sent, True)
        sent = self.nodes[0].sendpacket(key5, 0, 0, "test string3")
        time.sleep(1)
        assert_equal(sent, True)
        buffer = self.nodes[5].getbuffer(0)
        assert_equal(buffer['0'], "7465737420737472696e6731")
        assert_equal(buffer['1'], "7465737420737472696e6732")
        assert_equal(buffer['2'], "7465737420737472696e6733")


if __name__ == '__main__':
    SendPacketTest().main(bitcoinConfDict={"beta": 1})

# Create a convenient function for an interactive python debugging session
def Test():
    t = SendPacketTest()
    bitcoinConf = {
        "debug": ["net", "blk", "thin", "mempool", "req", "bench", "evict"],
        "blockprioritysize": 2000000,  # we don't want any transactions rejected due to insufficient fees...
        "beta": 1
    }


    flags = []
    # you may want these additional flags:
    # flags.append("--nocleanup")
    # flags.append("--noshutdown")

    # Execution is much faster if a ramdisk is used, so use it if one exists in a typical location
    if os.path.isdir("/ramdisk/test"):
        flags.append("--tmppfx=/ramdisk/test")

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
