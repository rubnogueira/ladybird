/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteString.h>
#include <AK/ConditionVariable.h>
#include <AK/Function.h>
#include <AK/Mutex.h>
#include <AK/Queue.h>
#include <AK/Vector.h>
#include <AK/kmalloc.h>
#include <LibThreading/Thread.h>

namespace Threading {

class ThreadPool {
public:
    AK_ALLOC_WITH_KMALLOC;

    static ThreadPool& the();

    // For work that spends its time waiting rather than computing, such as a getaddrinfo() call waiting on a DNS
    // server. Such work holds a thread for as long as it waits, so it gets threads of its own, and more of them, than
    // the pool above: many waits can then overlap, and none holds up the computations of the pool above.
    static ThreadPool& for_blocking_waits();

    void submit(Function<void()>);

private:
    ThreadPool(StringView name, size_t initial_thread_count, size_t maximum_thread_count);

    void start_thread();
    intptr_t worker_thread_func();

    ByteString m_name;
    size_t m_maximum_thread_count { 0 };

    Mutex m_mutex;
    ConditionVariable m_condition { m_mutex };
    Queue<Function<void()>> m_work_queue;
    Vector<NonnullRefPtr<Thread>> m_threads;
    size_t m_idle_thread_count { 0 };
};

}
