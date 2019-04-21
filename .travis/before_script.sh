#!/bin/bash
#
# Copyright (c) 2019 The Eccoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

unset CC; unset CXX
if [ "$CHECK_DOC" = 1 ]; then contrib/devtools/check-doc.py; fi
mkdir -p depends/SDKs depends/sdk-sources
if [ -n "$OSX_SDK" -a ! -f depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz ]; then curl --location --fail $SDK_URL/MacOSX${OSX_SDK}.sdk.tar.gz -o depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz; fi
if [ -n "$OSX_SDK" -a -f depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz ]; then tar -C depends/SDKs -xf depends/sdk-sources/MacOSX${OSX_SDK}.sdk.tar.gz; fi
echo "USE_CLANG=$USE_CLANG"
if [[ $HOST = *-mingw32 ]]; then sudo update-alternatives --set $HOST-g++ $(which $HOST-g++-posix); fi
if [ "$USE_CLANG" = "false" ]; then make $MAKEJOBS -C depends HOST=$HOST $DEP_OPTS; fi
