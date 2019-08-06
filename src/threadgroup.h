// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_THREAD_GROUP_H
#define ECCOIN_THREAD_GROUP_H

#include <atomic>
#include <thread>
#include <vector>


extern std::atomic<bool> shutdown_threads;

class thread_group
{
private:
    std::vector<std::thread> threads;
    std::atomic<bool> *killswitch;
    // disable default constructor
    thread_group() {}
public:
    thread_group(std::atomic<bool> *_killswitch)
    {
        threads.clear();
        killswitch = _killswitch;
    }
    void interrupt_all() { killswitch->store(true); }
    template <class Fn, class... Args>
    void create_thread(Fn &&f, Args &&... args)
    {
        threads.push_back(std::thread(f, args...));
    }

    bool empty() { return threads.empty(); }
    void join_all()
    {
        for (size_t i = 0; i < threads.size(); i++)
        {
            if (threads[i].joinable())
            {
                threads[i].join();
            }
        }
        threads.clear();
    }

    ~thread_group()
    {
        interrupt_all();
        join_all();
    }
};

#endif
