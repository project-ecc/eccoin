#!/usr/bin/env python3
# Copyright (c) 2015 The Bitcoin Core developers
# Copyright (c) 2015-2017 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import test_framework.loginit
#
# Test ZMQ interface system messages
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import zmq
import struct

import http.client
import urllib.parse

class ZMQTest (BitcoinTestFramework):

    port = 28332

    def setup_nodes(self):
        self.zmqContext = zmq.Context()
        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"system")
        self.zmqSubSocket.linger = 500
        self.zmqSubSocket.connect("tcp://127.0.0.1:%i" % self.port)
        return start_nodes(1, self.options.tmpdir, extra_args=[
            ['-zmqpubsystem=tcp://127.0.0.1:'+str(self.port)],
            [],
            [],
            []
            ])

    def run_test(self):
        try:
            self.sync_all()

            print("listen...")
            msg = self.zmqSubSocket.recv_multipart()
            topic = msg[0]
            body = msg[1]

            assert_equal(msg[1], "STARTUP: RPC AVAILABLE")

        finally:
            self.zmqSubSocket.close()
            self.zmqSubSocket = None
            self.zmqContext.destroy()
            self.zmqContext = None


if __name__ == '__main__':
    ZMQTest ().main ()

def Test():
    ZMQTest ().main ()
 
