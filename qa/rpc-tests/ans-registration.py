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


class AnsRegistrationTest (BitcoinTestFramework):

    def __init__(self, fastRun=True):
        self.generatedblocks = 100

    def setup_chain(self, bitcoinConfDict=None, wallets=None):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, bitcoinConfDict, wallets)

    def setup_network(self, split=False):
        self.nodes = []
        # Start 3 nodes, 0 will be mining and connected to a leveldb node(1)
        # the leveldb node will be connected to a third node running sequential(2)
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.nodes.append(start_node(1, self.options.tmpdir, []))
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):

        self.sync_blocks()

        # generate blocks on the mining node
        for x in range(0, self.generatedblocks):
            self.nodes[0].generate(1)

        sync_blocks(self.nodes[0:2])

        addrgrps = self.nodes[0].listaddressgroupings()
        coinaddr = addrgrps[0][0][0]

        #try to register ans addr
        registrationTx = self.nodes[0].registerans(coinaddr, "testname")
        # mine another few blocks for validity
        self.nodes[0].generate(5)
        self.sync_blocks()

        #the synced blocks should have propogated the ans name by now
        #try to fetch it
        records = self.nodes[1].getansrecord("testname", "A");
        assert(records[0]["Code"] == '11-1')
        assert(records[0]["Address"] != '')
        assert(records[0]["paymentHash"] != '')
        assert(records[0]["ServiceHash"] != '')
        

        


if __name__ == '__main__':
    AnsRegistrationTest().main()


def Test():
    t = AnsRegistrationTest(False)
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
