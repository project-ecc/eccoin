#ifndef ECCOIN_THREAD_GROUP_H
#define ECCOIN_THREAD_GROUP_H

#include <thread>
#include <vector>
#include <atomic>


static std::atomic<bool> shutdown_threads(false);

class thread_group
{
private:
    std::vector<std::thread> threads;

public:
    void interrupt_all()
    {
        shutdown_threads.store(true);
        for(size_t i = 0; i < threads.size(); i++)
        {
            threads[i].join();
        }
    }

    template< class Fn, class... Args >
    void create_thread(Fn&& f, Args&&... args)
    {
        threads.push_back(std::thread(f, args...));
    }

    bool empty()
    {
        return threads.size();
    }

};

#endif
