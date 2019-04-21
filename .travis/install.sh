#!/bin/bash
#
# Copyright (c) 2019 The Eccoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

if [ -n "$PPA" ]; then for i in `seq 0 4`; do sudo add-apt-repository "$PPA" -y 2>&1|tee /dev/stderr|grep -q "imported" && break; sleep 30; done; fi
if [ -n "$DPKG_ADD_ARCH" ]; then sudo dpkg --add-architecture "$DPKG_ADD_ARCH" ; fi
if [ -n "$PACKAGES" ]; then travis_retry sudo apt-get update; fi
if [ -n "$PACKAGES" ]; then travis_retry sudo apt-get install --no-install-recommends --no-upgrade -qq libdb4.8-dev libdb4.8++-dev $PACKAGES; fi
if [ -n "$PACKAGES" ]; then travis_retry sudo apt-get install -y -qq libboost1.58-dev ; fi
if [ -n "$PACKAGES" ]; then travis_retry sudo apt-get install -y -qq libboost1.58-tools-dev libboost-system1.58-dev libboost-filesystem1.58-dev libboost-program-options1.58-dev libboost-thread1.58-dev libboost-test1.58-dev; fi
