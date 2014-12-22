#include "donation.h"
#include "util.h"
#include "main.h"
#include <math.h>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <vector>
#include "wallet.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "base58.h"

using namespace json_spirit;
using namespace std;

std::map<uint256,double> ConfirmedBlocksWaitingOnDonate;

double CalcDonationAmount()
{
    double nDonAmnt = 0;

    double nPercent = nDonatePercent;
    if (nPercent < 0.0)
    {
        nPercent = 0.0;
    }
    else if (nPercent > 100.0)
    {
        nPercent = 100.0;
    }
    double dbPDV = (double)PDV;

    nDonAmnt =  ((dbPDV - MIN_TX_FEE )* (nPercent * 0.01));  // takes the amount that was earned and removes tx fee before calcing percent
    // this ensures that at even 100% donation, the user isnt slowly losing coins.

    return nDonAmnt;
}

std::string getUsableAddress(double amountRequired)
{
    int nMinDepth = 1000;
    std::string sAccount;
    map<string, int64_t> mapAccountBalances;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, string)& entry, pwalletMain->mapAddressBook)
    {
        if (IsMine(*pwalletMain, entry.first)) // This address belongs to me
        {
            mapAccountBalances[entry.second] = 0;
        }
    }
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it)
    {
        const CWalletTx& wtx = (*it).second;
        int64_t nFee;
        string strSentAccount;
        list<pair<CTxDestination, int64_t> > listReceived;
        list<pair<CTxDestination, int64_t> > listSent;
        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < 0)
        {
            continue;
        }
        wtx.GetAmounts(listReceived, listSent, nFee, strSentAccount);
        mapAccountBalances[strSentAccount] -= nFee;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64_t)& s, listSent)
            mapAccountBalances[strSentAccount] -= s.second;
        if (nDepth >= nMinDepth && wtx.GetBlocksToMaturity() == 0)
        {
            BOOST_FOREACH(const PAIRTYPE(CTxDestination, int64_t)& r, listReceived)
            {
                if (pwalletMain->mapAddressBook.count(r.first))
                {
                    mapAccountBalances[pwalletMain->mapAddressBook[r.first]] += r.second;
                }
                else
                {
                    mapAccountBalances[""] += r.second;
                }
            }
        }
    }
    list<CAccountingEntry> acentries;
    CWalletDB(pwalletMain->strWalletFile).ListAccountCreditDebit("*", acentries);
    BOOST_FOREACH(const CAccountingEntry& entry, acentries)
    {
        mapAccountBalances[entry.strAccount] += entry.nCreditDebit;
    }

    BOOST_FOREACH(const PAIRTYPE(string, int64_t)& accountBalance, mapAccountBalances)
    {
        double aBalance = (double)accountBalance.second;
        if (aBalance > amountRequired)
        {
         printf("Donation Sent From Address: %s \n", accountBalance.first.c_str());
         sAccount = accountBalance.first;
         break;
        }
    }

    CWalletDB walletdb(pwalletMain->strWalletFile);
    CAccount account;
    walletdb.ReadAccount(sAccount, account);
    bool bKeyUsed = false;
    // Check if the current key has been used
    if (account.vchPubKey.IsValid())
    {
        CScript scriptPubKey;
        scriptPubKey.SetDestination(account.vchPubKey.GetID());
        for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end() && account.vchPubKey.IsValid(); ++it)
        {
            const CWalletTx& wtx = (*it).second;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if (txout.scriptPubKey == scriptPubKey)
                    bKeyUsed = true;
        }
    }
    // Generate a new key
    if (!account.vchPubKey.IsValid() || bKeyUsed)
    {
        if (!pwalletMain->GetKeyFromPool(account.vchPubKey, false))
            throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");

        pwalletMain->SetAddressBookName(account.vchPubKey.GetID(), sAccount);
        walletdb.WriteAccount(sAccount, account);
    }
    return CBitcoinAddress(account.vchPubKey.GetID()).ToString();
}




bool CreateDonation(double nAmount)
{
    std::string SourceAddress = getUsableAddress(nAmount);
    CBitcoinAddress Destaddress = "EXzt3cDJGdR5jHaAqphQo6GhAWwmGxBd2h";


    //tx comnments and such
    CWalletTx wtx;
    wtx.strFromAccount = SourceAddress;
    wtx.mapValue["comment"] = "Donation to ECCoin dev";
    wtx.mapValue["to"] = Destaddress.ToString().c_str();

    if (!Destaddress.IsValid())
    {
        printf("Error Donating: Trying to donate to invalid address \n");
        return false;
    }

    if (pwalletMain->IsLocked())
    {
        printf("Error Donating: Wallet is locked, unable to donate \n");
        return false;
    }


    // Send
    std::string strError = pwalletMain->SendMoneyToDestination(Destaddress.Get(), nAmount, wtx);
    if (strcmp(strError.c_str(), "") != 0)
    {
        printf("Error Donating: %s \n", strError.c_str());
        return false;
    }
    std::string DonationTx = wtx.GetHash().GetHex();
    printf("Donation Transaction ID = %s \n", DonationTx.c_str());
    return true;
}

void CheckForStakedBlock()
{
    if(ConfirmedBlocksWaitingOnDonate.size() == 0)
    {
        return;
    }

    string strAccount = "*";
    int nCount = 100;
    int i = 0;
    int j = 0;
    int k = 0;
    double nAmount = 0;
    std::vector<uint256> ret;
    std::vector<uint256> used;
    std::map<uint256,double>::iterator iter;
    std::map<uint256,double>::iterator DeleteEntry;
    std::list<CAccountingEntry> acentries;
    list<pair<CTxDestination, int64_t> > LR;
    list<pair<CTxDestination, int64_t> > LS;

    CWallet::TxItems txOrdered = pwalletMain->OrderedTxItems(acentries, strAccount);

    // iterate backwards until we have nCount items to return:
    for (CWallet::TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx != 0)
        {
            string strSentAccount;
            int64_t nFee = 0;
            pwtx->GetAmounts(LR, LS, nFee, strSentAccount);
            if (LR.size() > 0)
            {
                if(pwtx->GetBlocksToMaturity() == 0)
                {
                    ret.push_back(pwtx->GetHash());
                }
            }
        }
        if ((int)ret.size() >= (nCount))
        {
            break;
        }
    }

    for(i = 0; i < ret.size(); ++i)
    {
       iter = ConfirmedBlocksWaitingOnDonate.find(ret[i]);
       if(iter != ConfirmedBlocksWaitingOnDonate.end())
       {
           used.push_back(ret[i]);
           nAmount = nAmount + iter->second;
       }
    }



    for(k = 0; k < used.size(); ++k)
    {
        DeleteEntry = ConfirmedBlocksWaitingOnDonate.find(used[j]);
        ConfirmedBlocksWaitingOnDonate.erase(DeleteEntry);
    }

    bool success = CreateDonation(nAmount);
    if(success == true)
    {
        printf("Donation Success \n");
    }
    else
    {
        printf("Donation Faled \n");
    }
}
