/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Time.h>
#include <AK/kmalloc.h>
#include <LibThreading/ThreadPool.h>

static constexpr size_t THREAD_COUNT = 4;
// A getaddrinfo() call can wait for a DNS server for hundreds of milliseconds, and a page can bring a few dozen hosts
// to look up at once.
static constexpr size_t MAXIMUM_BLOCKING_WAIT_THREAD_COUNT = 32;
static constexpr size_t THREAD_STACK_SIZE = 8 * MiB;
static constexpr auto THREAD_IDLE_MEMORY_COLLECTION_DELAY = AK::Duration::from_seconds(1);

namespace Threading {

ThreadPool& ThreadPool::the()
{
    static ThreadPool* instance = new ThreadPool("Pool"sv, THREAD_COUNT, THREAD_COUNT);
    return *instance;
}

ThreadPool& ThreadPool::for_blocking_waits()
{
    // NB: This pool starts its threads as work comes in, since most processes never wait on anything through it.
    static ThreadPool* instance = new ThreadPool("Wait"sv, 0, MAXIMUM_BLOCKING_WAIT_THREAD_COUNT);
    return *instance;
}

ThreadPool::ThreadPool(StringView name, size_t initial_thread_count, size_t maximum_thread_count)
    : m_name(name)
    , m_maximum_thread_count(maximum_thread_count)
{
    MutexLocker locker(m_mutex);
    for (size_t i = 0; i < initial_thread_count; ++i)
        start_thread();
}

// NB: This is called with m_mutex held.
void ThreadPool::start_thread()
{
    auto name = ByteString::formatted("{}/{}", m_name, m_threads.size());
    auto thread = Thread::construct(name, [this]() -> intptr_t {
        return worker_thread_func();
    });
    thread->set_stack_size(THREAD_STACK_SIZE);
    thread->start();
    m_threads.append(move(thread));
}

intptr_t ThreadPool::worker_thread_func()
{
    bool collected_since_last_work = false;

    while (true) {
        Function<void()> work;
        bool should_collect = false;
        {
            MutexLocker locker(m_mutex);

            ++m_idle_thread_count;
            while (m_work_queue.is_empty()) {
                if (collected_since_last_work) {
                    m_condition.wait();
                } else if (!m_condition.wait_for(THREAD_IDLE_MEMORY_COLLECTION_DELAY) && m_work_queue.is_empty()) {
                    should_collect = true;
                    break;
                }
            }
            --m_idle_thread_count;

            if (!should_collect)
                work = m_work_queue.dequeue();
        }

        if (should_collect) {
            ak_release_idle_thread_memory();
            ak_kmalloc_collect();
            collected_since_last_work = true;
            continue;
        }

        collected_since_last_work = false;
        work();
    }
}

void ThreadPool::submit(Function<void()> work)
{
    MutexLocker locker(m_mutex);
    m_work_queue.enqueue(move(work));

    // Work waits for a thread only once the pool has as many threads as it may have, and all of them are busy.
    if (m_work_queue.size() > m_idle_thread_count && m_threads.size() < m_maximum_thread_count)
        start_thread();

    m_condition.signal();
}

}
