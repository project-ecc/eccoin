#!/bin/bash
#
# Copyright (c) 2019 The Eccoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export PATH=$(echo $PATH | tr ':' "\n" | sed '/\/opt\/python/d' | tr "\n" ":" | sed "s|::|:|g")
#  temp fix with riak repo, by the way we don't need riak at all
sudo rm -vf /etc/apt/sources.list.d/*riak*
sudo apt-get update
