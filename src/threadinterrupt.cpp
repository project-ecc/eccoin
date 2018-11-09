/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "threadinterrupt.h"

CThreadInterrupt::operator bool() const { return flag.load(std::memory_order_acquire); }
void CThreadInterrupt::reset() { flag.store(false, std::memory_order_release); }
void CThreadInterrupt::operator()()
{
    {
        std::unique_lock<std::mutex> lock(mut);
        flag.store(true, std::memory_order_release);
    }
    cond.notify_all();
}

bool CThreadInterrupt::sleep_for(std::chrono::milliseconds rel_time)
{
    std::unique_lock<std::mutex> lock(mut);
    return !cond.wait_for(lock, rel_time, [this]() { return flag.load(std::memory_order_acquire); });
}

bool CThreadInterrupt::sleep_for(std::chrono::seconds rel_time)
{
    return sleep_for(std::chrono::duration_cast<std::chrono::milliseconds>(rel_time));
}

bool CThreadInterrupt::sleep_for(std::chrono::minutes rel_time)
{
    return sleep_for(std::chrono::duration_cast<std::chrono::milliseconds>(rel_time));
}
