// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CORE_IO_H
#define BITCOIN_CORE_IO_H

#include <string>
#include <vector>

class CBlock;
class CScript;
class CTransaction;
class uint256;

// core_read.cpp
extern CScript ParseScript(const std::string &s);
extern std::string ScriptToAsmStr(const CScript &script, const bool fAttemptSighashDecode = false);
extern bool DecodeHexTx(CTransaction &tx, const std::string &strHexTx);
extern bool DecodeHexBlk(CBlock &, const std::string &strHexBlk);
extern uint256 ParseHashStr(const std::string &, const std::string &strName);

// core_write.cpp
extern std::string FormatScript(const CScript &script);
extern std::string EncodeHexTx(const CTransaction &tx);

#endif // BITCOIN_CORE_IO_H
