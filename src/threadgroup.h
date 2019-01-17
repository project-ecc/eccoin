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
    std::vector<std::string> names;
    std::atomic<bool> *killswitch;

public:
    thread_group(std::atomic<bool> *_killswitch) { killswitch = _killswitch; }
    void interrupt_all() { killswitch->store(true); }
    template <class Fn, class... Args>
    void create_thread(std::string name, Fn &&f, Args &&... args)
    {
        threads.push_back(std::thread(f, args...));
        names.push_back(name);
    }

    void clear()
    {
        interrupt_all();
        join_all();
        threads.clear();
        names.clear();
    }

    bool empty() { return threads.empty(); }
    void join_all()
    {
        // printf("num threads = %u \n", threads.size());
        for (size_t i = 0; i < threads.size(); i++)
        {
            // printf("trying to join thread %s \n", names[i].c_str());
            if (threads[i].joinable())
            {
                threads[i].join();
            }
            // printf("joined thread %s \n", names[i].c_str());
        }
    }
};

#endif
