E-Currency Coin RPC Commands
=====================================

abandontransaction
------------------
Mark in-wallet transaction <txid> as abandoned

This will mark this transaction and all its in-wallet descendants as abandoned which will allow for their inputs to be respent.  It can be used to replace "stuck" or evicted transactions. It only works on transactions which are not included in a block and are not currently in the mempool. It has no effect on transactions which are already conflicted or abandoned.

Syntax:
abandontransaction "txid"

Arguments:
1. "txid"    (string, required) The transaction id

Result:
none

Examples:
1. Abandon a transaction with txid 1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d
	abandontransaction "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d"


addmultisigaddress
------------------
Add a nrequired-to-sign multisignature address to the wallet.

Each key is a Bitcoin address or hex-encoded public key. If 'account' is specified (DEPRECATED), assign address to that account.

Syntax:
addmultisigaddress nrequired ["key",...] "account"

Arguments:
1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.
2. keysobject     (string,  required) A json array of bitcoin addresses or hex-encoded public keys
     [
       "address"  (string) bitcoin address or hex-encoded public key
       ...,
     ]
3. account        (string, OPTIONAL) DEPRECATED. An account to assign the addresses to.

Result:
bitcoinaddress  (string) A bitcoin address associated with the keys.

Examples:
1. Add a multisig address from 2 addresses
	addmultisigaddress 2 "["16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5", "171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV"]"


addnode
-------
Attempts add or remove a node from the addnode list. Or try a connection to a node once.

Syntax:
addnode "node" "add|remove|onetry"

Arguments:
1. "node"     (string, required) The node (see getpeerinfo for nodes)
2. "command"  (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once

Result:
none

Examples:
1. Add a node to the node list
	addnode "192.168.0.6:8333" "add"
2. Remove a node from the node list
	addnode "192.168.0.6:8333" "remove"
3. Try a connection to a node once
	addnode "192.168.0.6:8333" "onetry"


backupwallet
------------
Safely copies wallet.dat to destination, which can be a directory or a path with filename.

Syntax:
backupwallet "destination"

Arguments:
1. "destination"   (string) The destination directory or file

Result:
no output, but a file with the name given should appear in the desired directory

Examples:
1. Backup wallet to the same folder with the name backup.dat
	backupwallet "backup.dat"


clearbanned
-----------
Clear all banned IPs.

Syntax:
clearbanned

Arguments:
none

Result:
none

Examples:
1. Delete the list of nodes that are banned from connecting to our node
	clearbanned


createmultisig
--------------
Creates a multi-signature address with n signature of m keys required. It returns a json object with the address and redeemScript.

Syntax:
createmultisig nrequired ["key",...]

Arguments:
1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.
2. "keys"       (string, required) A json array of keys which are E-CurrencyCoin addresses or hex-encoded public keys
     [
       "key"    (string) E-CurrencyCoin address or hex-encoded public key
       ,...
     ]

Result:
JSON object in the following format
{
  "address:"multisigaddress",  (string) The value of the new multisig address.
  "redeemScript":"script"       (string) The std::string value of the hex-encoded redemption script.
}

Examples:
1. Create a multisig address from 2 addresses
	createmultisig 2 ["16sSauSf5pF2UkUwvKGq4qjNRzBZYqgEL5","171sgjn4YtPu27adkKGrdDwzRTxnRkBfKV"]



decodescript
------------
Decode a hex-encoded script.

Syntax:
decodescript "hex"

Arguments:
1. "hex"     (string) the hex encoded script

Result:
JSON object in the following format
{
  "asm":"asm",     (string) Script public key
  "hex":"hex",     (string) hex encoded public key
  "type":"type",   (string) The output type
  "reqSigs": n,    (numeric) The required signatures
  "addresses": [   (json array of string)
     "address"     (string) E-CurrencyCoin address
     ,...
  ],
  "p2sh",
  "address" (string) script address
}

nExamples:
1. decode the script hexstring
	decodescript "hexstring"


disconnectnode
--------------
Immediately disconnects from the specified node.

Syntax:
disconnectnode "node"

Arguments:
1. "node"     (string, required) The node (see getpeerinfo for nodes)

Result:
none

Examples:
1. Disconnect from the node 192.168.0.6
	disconnectnode "192.168.0.6"


dumpprivkey
-----------
Reveals the private key corresponding to 'address'. Then the importprivkey can be used with this output.

Syntax:
dumpprivkey "address"

Arguments:
1. "address"   (string, required) The E-CurrencyCoin address for the private key

Result:
key            (string) The private key

Examples:
1. Dump the private key for "myaddress"
	dumpprivkey "myaddress"


dumpwallet
----------
Dumps all wallet keys in a human-readable format.

Syntax:
dumpwallet "filename"

Arguments:
1. "filename"    (string, required) The filename

Result:
no output, but it should create a new file with the name specified

Examples:
1. dump the wallet to a file named test
dumpwallet "test"


encryptwallet
-------------
Encrypts the wallet with 'passphrase'. This is for first time encryption. After this, any calls that interact with private keys such as sending or signing will require the passphrase to be set prior the making these calls. Use the walletpassphrase call for this, and then walletlock call. If the wallet is already encrypted, use the walletpassphrasechange call. Note that this will shutdown the server.

Syntax:			
encryptwallet "passphrase"

Arguments:
            "1. "passphrase"    (string) The pass phrase to encrypt the wallet with. It must be at least 1 character, but should be long.

Result:
no output, but it will shut down the server to finish the process			

Examples:
1. Encrypt you wallet with the password 123abc
	encryptwallet "123abc"


generate
--------
Mine blocks immediately (before the RPC call returns). Note: this function can only be used on the regtest network

Syntax:			
generate numblocks

Arguments:
1. numblocks    (numeric, required) How many blocks are generated immediately.

Result
[ blockhashes ]     (array) hashes of blocks generated

Examples:
1. Generate 11 blocks
	generate 11


getaccount
----------
DEPRECATED. Returns the account associated with the given address.

Syntax:
getaccount "bitcoinaddress"

Arguments:
1. "bitcoinaddress"  (string, required) The bitcoin address for account lookup.

Result:
"accountname"        (string) the account address

Examples:
1. Get the account for the address ED1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ
	getaccount "ED1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XZ"


getaccountaddress
-----------------
DEPRECATED. Returns the current Bitcoin address for receiving payments to this account.

Syntax:
"getaccountaddress "account"

Arguments:
"1. "account"       (string, required) The account name for the address. It can also be set to the empty string "" to represent the default account. The account does not need to exist, it will be created and a new address created  if there is no account by the given name.

Result:
            "bitcoinaddress"   (string) The account bitcoin address

Examples:
1. Get address for account myaccount
	getaccountaddress "myaccount"


getaddednodeinfo
----------------
Returns information about the given added node, or all added nodes (note that onetry addnodes are not listed here) If dns is false, only a list of added nodes will be provided, otherwise connected information will also be available.

Syntax:			
getaddednodeinfo dns ( "node" )

Arguments:
1. dns        (boolean, required) If false, only a list of added nodes will be provided, otherwise connected information will also be available.
2. "node"   (string, optional) If provided, return information about this specific node, otherwise all nodes are returned.

Result:
[
  {
    "addednode" : "192.168.0.201",   (string) The node ip address
    "connected" : true|false,          (boolean) If connected
    "addresses" : [
      {
         "address" : "192.168.0.201:8333",  (string) The bitcoin server host and port
         "connected" : "outbound"           (string) connection, inbound or outbound
      }
       ,...
    ]
  }
  ,...
]

Examples:
1. Get information about all connected nodes
	getaddednodeinfo "true"
2. Get information about the node with ip address 192.168.0.201
	getaddednodeinfo" "true "192.168.0.201"


getaddressesbyaccount
---------------------
DEPRECATED. Returns the list of addresses for the given account.

Syntax:
getaddressesbyaccount "account"

Arguments:
1. "account"  (string, required) The account name.

Result: JSON array of string
[                     
  "bitcoinaddress"  (string) a bitcoin address associated with the given account
  ,...
]

Examples:
1. Get the address of the account tabby
	getaddressesbyaccount "tabby"


getbalance
----------
If account is not specified, returns the server's total available balance. If account is specified (DEPRECATED), returns the balance in the account. Note that the account "" is not the same as leaving the parameter out. The server total may be different to the balance in the default "" account.

Syntax:
getbalance ( "account" minconf includeWatchonly )

Arguments:
1. "account"      (string, optional) DEPRECATED. The selected account, or "*" for entire wallet. It may be the default account using "".
2. minconf          (numeric, optional, default=1) Only include transactions confirmed at least this many times.
3. includeWatchonly (bool, optional, default=false) Also include balance in watchonly addresses (see 'importaddress')

Result:
amount              (numeric) The total amount in " + CURRENCY_UNIT + " received for this account.

Examples:
1. The total amount in the wallet
	getbalance ""
2. The total amount in the wallet at least 5 blocks confirmed
	getbalance "*" 6


getbestblockhash
----------------
Returns the hash of the best (tip) block in the longest block chain.

Syntax:
getbestblockhash

Arguments:
none

Result
"hex"      (string) the block hash hex encoded

Examples
1. Get the best block hash on the longest chain
	getbestblockhash


getblock
--------
If verbose is false, returns a string that is serialized, hex-encoded data for block 'hash'. If verbose is true, returns an Object with information about block <hash>.

Syntax:
"getblock "hash" ( verbose )

Arguments:
"1. "hash"          (string, required) The block hash
"2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data

Result (for verbose = true):
{
  "hash" : "hash",               (string) the block hash (same as provided)
  "confirmations" : n,           (numeric) The number of confirmations, or -1 if the block is not on the main chain
  "size" : n,                    (numeric) The block size
  "height" : n,                  (numeric) The block height or index
  "version" : n,                 (numeric) The block version
  "merkleroot" : "xxxx",         (string) The merkle root
  "tx" : [                       (array of string) The transaction ids
     "transactionid"             (string) The transaction id
     ,...
  ],
  "time" : ttt,                  (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
  "mediantime" : ttt,            (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)
  "nonce" : n,                   (numeric) The nonce
  "bits" : "1d00ffff",           (string) The bits
  "difficulty" : x.xxx,          (numeric) The difficulty
  "chainwork" : "xxxx",          (string) Expected number of hashes required to produce the chain up to this block (in hex)
  "previousblockhash" : "hash",  (string) The hash of the previous block
  "nextblockhash" : "hash"       (string) The hash of the next block
}

Result (for verbose=false):
"data"             (string) A string that is serialized, hex-encoded data for block 'hash'.

Examples:
1. get block with hash 00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09
	getblock "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"


getblockchaininfo
-----------------
            "getblockchaininfo
            "Returns an object containing various state info regarding block chain processing.
            Result:
            "{
            "  "chain": "xxxx",        (string) current network name as defined in BIP70 (main, test, regtest)
            "  "blocks": xxxxxx,         (numeric) the current number of blocks processed in the server
            "  "headers": xxxxxx,        (numeric) the current number of headers we have validated
            "  "bestblockhash": "...", (string) the hash of the currently best block
            "  "difficulty": xxxxxx,     (numeric) the current difficulty
            "  "mediantime": xxxxxx,     (numeric) median time for the current best block
            "  "chainwork": "xxxx"     (string) total amount of work in active chain, in hexadecimal
            "  "pruned": xx,             (boolean) if the blocks are subject to pruning
            "  "pruneheight": xxxxxx,    (numeric) heighest block available
            "  "softforks": [            (array) status of softforks in progress
            "     {
            "        "id": "xxxx",        (string) name of softfork
            "        "version": xx,         (numeric) block version
            "        "enforce": {           (object) progress toward enforcing the softfork rules for new-version blocks
            "           "status": xx,       (boolean) true if threshold reached
            "           "found": xx,        (numeric) number of blocks with the new version found
            "           "required": xx,     (numeric) number of blocks required to trigger
            "           "window": xx,       (numeric) maximum size of examined window of recent blocks
            "        },
            "        "reject": { ... }      (object) progress toward rejecting pre-softfork blocks (same fields as "enforce")
            "     }, ...
            "  ],
            "  "bip9_softforks": [       (array) status of BIP9 softforks in progress
            "     {
            "        "id": "xxxx",        (string) name of the softfork
            "        "status": "xxxx",    (string) one of "defined", "started", "lockedin", "active", "failed"
            "     }
            "  ]
            "}
            Examples:
            + HelpExampleCli("getblockchaininfo", "")


getblockcount
-------------
           Returns the number of blocks in the longest block chain.
            Result:
            "n    (numeric) The current block count
            Examples:
            + HelpExampleCli("getblockcount", "")


getblockhash
------------
            "getblockhash index
            Returns hash of block in best-block-chain at index provided.
            Arguments:
            "1. index         (numeric, required) The block index
            Result:
            ""hash"         (string) The block hash
            Examples:
            + HelpExampleCli("getblockhash", "1000")


getblockheader
--------------
            "getblockheader "hash" ( verbose )
            If verbose is false, returns a string that is serialized, hex-encoded data for blockheader 'hash'.
            "If verbose is true, returns an Object with information about blockheader <hash>.
            Arguments:
            "1. "hash"          (string, required) The block hash
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data
            Result (for verbose = true):
            "{
            "  "hash" : "hash",     (string) the block hash (same as provided)
            "  "confirmations" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain
            "  "height" : n,          (numeric) The block height or index
            "  "version" : n,         (numeric) The block version
            "  "merkleroot" : "xxxx", (string) The merkle root
            "  "time" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)
            "  "mediantime" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)
            "  "nonce" : n,           (numeric) The nonce
            "  "bits" : "1d00ffff", (string) The bits
            "  "difficulty" : x.xxx,  (numeric) The difficulty
            "  "previousblockhash" : "hash",  (string) The hash of the previous block
            "  "nextblockhash" : "hash",      (string) The hash of the next block
            "  "chainwork" : "0000...1f3"     (string) Expected number of hashes required to produce the current chain (in hex)
            "}
            Result (for verbose=false):
            ""data"             (string) A string that is serialized, hex-encoded data for block 'hash'.
            Examples:
            + HelpExampleCli("getblockheader", ""00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"")


getblocktemplate
----------------
            "getblocktemplate ( "jsonrequestobject" )
            If the request parameters include a 'mode' key, that is used to explicitly select between the default 'template' request or a 'proposal'.
            "It returns data needed to construct a block to work on.
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.

            Arguments:
            "1. "jsonrequestobject"       (string, optional) A json object in the following spec
            "     {
            "       "mode":"template"    (string, optional) This must be set to "template" or omitted
            "       "capabilities":[       (array, optional) A list of strings
            "           "support"           (string) client side supported feature, 'longpoll', 'coinbasetxn', 'coinbasevalue', 'proposal', 'serverlist', 'workid'
            "           ,...
            "         ]
            "     }
            "

            Result:
            "{
            "  "version" : n,                    (numeric) The block version
            "  "previousblockhash" : "xxxx",    (string) The hash of current highest block
            "  "transactions" : [                (array) contents of non-coinbase transactions that should be included in the next block
            "      {
            "         "data" : "xxxx",          (string) transaction data encoded in hexadecimal (byte-for-byte)
            "         "hash" : "xxxx",          (string) hash/id encoded in little-endian hexadecimal
            "         "depends" : [              (array) array of numbers
            "             n                        (numeric) transactions before this one (by 1-based index in 'transactions' list) that must be present in the final block if this one is
            "             ,...
            "         ],
            "         "fee": n,                   (numeric) difference in value between transaction inputs and outputs (in Satoshis); for coinbase transactions, this is a negative Number of the total collected block fees (ie, not including the block subsidy); if key is not present, fee is unknown and clients MUST NOT assume there isn't one
            "         "sigops" : n,               (numeric) total number of SigOps, as counted for purposes of block limits; if key is not present, sigop count is unknown and clients MUST NOT assume there aren't any
            "         "required" : true|false     (boolean) if provided and true, this transaction must be in the final block
            "      }
            "      ,...
            "  ],
            "  "coinbaseaux" : {                  (json object) data that should be included in the coinbase's scriptSig content
            "      "flags" : "flags"            (string)
            "  },
            "  "coinbasevalue" : n,               (numeric) maximum allowable input to coinbase transaction, including the generation award and transaction fees (in Satoshis)
            "  "coinbasetxn" : { ... },           (json object) information for coinbase transaction
            "  "target" : "xxxx",               (string) The hash target
            "  "mintime" : xxx,                   (numeric) The minimum timestamp appropriate for next block time in seconds since epoch (Jan 1 1970 GMT)
            "  "mutable" : [                      (array of string) list of ways the block template may be changed
            "     "value"                         (string) A way the block template may be changed, e.g. 'time', 'transactions', 'prevblock'
            "     ,...
            "  ],
            "  "noncerange" : "00000000ffffffff",   (string) A range of valid nonces
            "  "sigoplimit" : n,                 (numeric) limit of sigops in blocks
            "  "sizelimit" : n,                  (numeric) limit of block size
            "  "curtime" : ttt,                  (numeric) current timestamp in seconds since epoch (Jan 1 1970 GMT)
            "  "bits" : "xxx",                 (string) compressed target of next block
            "  "height" : n                      (numeric) The height of the next block
            "}

            Examples:
            + HelpExampleCli("getblocktemplate", "")


getchaintips
------------
            "getchaintips
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.
            Result:
            "[
            "  {
            "    "height": xxxx,         (numeric) height of the chain tip
            "    "hash": "xxxx",         (string) block hash of the tip
            "    "branchlen": 0          (numeric) zero for main chain
            "    "status": "active"      (string) "active" for the main chain
            "  },
            "  {
            "    "height": xxxx,
            "    "hash": "xxxx",
            "    "branchlen": 1          (numeric) length of branch connecting the tip to the main chain
            "    "status": "xxxx"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)
            "  }
            "]
            "Possible values for status:
            "1.  "invalid"               This branch contains at least one invalid block
            "2.  "headers-only"          Not all blocks for this branch are available, but the headers are valid
            "3.  "valid-headers"         All blocks are available for this branch, but they were never fully validated
            "4.  "valid-fork"            This branch is not part of the active chain, but is fully validated
            "5.  "active"                This is the tip of the active main chain, which is certainly valid
            Examples:
            + HelpExampleCli("getchaintips", "")


getconnectioncount
------------------
            "getconnectioncount
            Returns the number of connections to other nodes.
            Result:
            "n          (numeric) The connection count
            Examples:
            + HelpExampleCli("getconnectioncount", "")


getdifficulty
-------------
            "getdifficulty
            Returns the proof-of-work difficulty as a multiple of the minimum difficulty.
            Result:
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.
            Examples:
            + HelpExampleCli("getdifficulty", "")


getgenerate
-----------
            "getgenerate
            Return if the server is set to generate coins or not. The default is false.
            "It is set with the command line argument -gen (or " + std::string(CONF_FILENAME) + " setting gen)
            "It can also be set with the setgenerate call.
            Result
            "true|false      (boolean) If the server is set to generate coins or not
            Examples:
            + HelpExampleCli("getgenerate", "")


getinfo
-------
            "getinfo
            "Returns an object containing various state info.
            Result:
            "{
            "  "version": xxxxx,           (numeric) the server version
            "  "protocolversion": xxxxx,   (numeric) the protocol version
            "  "walletversion": xxxxx,     (numeric) the wallet version
            "  "balance": xxxxxxx,         (numeric) the total E-CurrencyCoin balance of the wallet
            "  "blocks": xxxxxx,           (numeric) the current number of blocks processed in the server
            "  "timeoffset": xxxxx,        (numeric) the time offset
            "  "connections": xxxxx,       (numeric) the number of connections
            "  "proxy": "host:port",     (string, optional) the proxy used by the server
            "  "difficulty": xxxxxx,       (numeric) the current difficulty
            "  "testnet": true|false,      (boolean) if the server is using testnet or not
            "  "keypoololdest": xxxxxx,    (numeric) the timestamp (seconds since GMT epoch) of the oldest pre-generated key in the key pool
            "  "keypoolsize": xxxx,        (numeric) how many new keys are pre-generated
            "  "unlocked_until": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked
            "  "paytxfee": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB
            "  "relayfee": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB
            "  "errors": "..."           (string) any error messages
            "}
            Examples:
            + HelpExampleCli("getinfo", "")


getmempoolinfo
--------------



getmininginfo
-------------



getnewaddress
-------------



getnettotals
------------

getnetworkhashps
----------------

getnetworkinfo
--------------

getpeerinfo
-----------

getrawchangeaddress
-------------------

getrawtransaction
-----------------

getreceivedbyaccount
--------------------

getreceivedbyaddress
--------------------

getrawmempool
-------------

gettransaction
--------------

gettxout
--------

gettxoutproof
-------------

gettxoutsetinfo
---------------

getunconfirmedbalance
---------------------

getwalletinfo
-------------

importaddress
-------------

importprivkey
-------------

importpubkey
------------

importwallet
------------

invalidateblock
---------------

keypoolrefill
-------------

listaccounts
------------

listaddressgroupings
--------------------

listbanned
----------

listlockunspent
---------------

listsinceblock
--------------

listreceivedbyaccount
---------------------

listreceivedbyaddress
---------------------

listtransactions
----------------

listunspent
-----------

lockunspent
-----------

movecmd
-------

ping
----

prioritisetransaction
---------------------

reconsiderblock
---------------

resendwallettransactions
------------------------

setaccount
----------

setban
------

setgenerate
-----------

sendfrom
--------

sendmany
--------

sendrawtransaction
------------------

sendtoaddress
-------------

signmessage
-----------

signrawtransaction
------------------

setmocktime
-----------

settxfee
--------

submitblock
-----------

walletlock
----------

walletpassphrase
----------------

walletpassphrasechange
----------------------

validateaddress
---------------

verifychain
-----------

verifymessage
-------------

verifytxoutproof
----------------
