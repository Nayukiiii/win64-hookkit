#include "hookkit/session_ring.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#else
#include <chrono>
#include <thread>
#endif

#include <new>

namespace hookkit {
namespace {

std::uint64_t query_qpc_now() noexcept {
#ifdef _WIN32
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return static_cast<std::uint64_t>(value.QuadPart);
#else
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
#endif
}

std::uint64_t query_tick_ms() noexcept {
#ifdef _WIN32
    return GetTickCount64();
#else
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
#endif
}

std::uint32_t query_current_tid() noexcept {
#ifdef _WIN32
    return static_cast<std::uint32_t>(GetCurrentThreadId());
#else
    return 0;
#endif
}

void yield_cpu() noexcept {
#ifdef _WIN32
    Sleep(0);
#else
    std::this_thread::yield();
#endif
}

void sleep_ms(std::uint32_t ms) noexcept {
#ifdef _WIN32
    Sleep(ms);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#endif
}

} // namespace

SessionRing::SessionRing() noexcept
    : events_(new (std::nothrow) EventCell[kEventCapacity]{}),
      notices_(new (std::nothrow) NoticeCell[kNoticeCapacity]{}) {}

void SessionRing::reset() noexcept {
    accepting_.store(false, std::memory_order_release);
    if (events_) {
        const std::uint64_t count = used();
        for (std::uint64_t i = 0; i < count; ++i) {
            events_[i].published.store(0, std::memory_order_relaxed);
            events_[i].value = EventRecord{};
        }
    }
    if (notices_) {
        const std::uint32_t ncount = notices();
        for (std::uint32_t i = 0; i < ncount; ++i) {
            notices_[i].published.store(0, std::memory_order_relaxed);
            notices_[i].value = ThreadNotice{};
        }
    }
    for (std::size_t i = 0; i < kMaxHelpers; ++i) {
        helpers_[i].published.store(0, std::memory_order_relaxed);
        helpers_[i].tid = 0;
        helpers_[i].creation_time = 0;
    }

    used_.store(0, std::memory_order_relaxed);
    generation_.store(1, std::memory_order_relaxed);
    early_notices_.store(0, std::memory_order_relaxed);
    notices_used_.store(0, std::memory_order_relaxed);
    helper_reserved_.store(0, std::memory_order_relaxed);
    spawn_gate_.store(0, std::memory_order_relaxed);
    emitting_.store(0, std::memory_order_relaxed);
    active_callbacks_.store(0, std::memory_order_relaxed);
    discovering_.store(false, std::memory_order_relaxed);
    overflowed_.store(false, std::memory_order_relaxed);
    sealed_.store(false, std::memory_order_relaxed);
    sealed_generation_ = 0;
    accepting_.store(true, std::memory_order_release);
}

void SessionRing::enter_spawn() noexcept {
    std::uint32_t expected = 0;
    while (!spawn_gate_.compare_exchange_weak(
        expected, 1u, std::memory_order_acquire, std::memory_order_relaxed)) {
        expected = 0;
        yield_cpu();
    }
}

bool SessionRing::try_enter_spawn(std::uint32_t timeout_ms) noexcept {
    const std::uint64_t start = query_tick_ms();
    std::uint32_t expected = 0;
    while (!spawn_gate_.compare_exchange_weak(
        expected, 1u, std::memory_order_acquire, std::memory_order_relaxed)) {
        if (query_tick_ms() - start >= timeout_ms) {
            return false;
        }
        expected = 0;
        sleep_ms(1);
    }
    return true;
}

void SessionRing::leave_spawn() noexcept {
    spawn_gate_.store(0u, std::memory_order_release);
}

bool SessionRing::register_helper(std::uint32_t tid, std::uint64_t creation_time) noexcept {
    if (tid == 0 || creation_time == 0 || is_helper_tid(tid)) {
        return false;
    }
    const std::uint32_t idx = helper_reserved_.fetch_add(1u, std::memory_order_acq_rel);
    if (idx >= kMaxHelpers) {
        return false;
    }
    helpers_[idx].tid = tid;
    helpers_[idx].creation_time = creation_time;
    helpers_[idx].published.store(1u, std::memory_order_release);
    return true;
}

bool SessionRing::is_helper_tid(std::uint32_t tid) const noexcept {
    const std::uint32_t count = helper_count();
    for (std::uint32_t i = 0; i < count; ++i) {
        if (helpers_[i].published.load(std::memory_order_acquire) == 1u &&
            helpers_[i].tid == tid) {
            return true;
        }
    }
    return false;
}

bool SessionRing::is_helper(std::uint32_t tid, std::uint64_t creation_time) const noexcept {
    const std::uint32_t count = helper_count();
    for (std::uint32_t i = 0; i < count; ++i) {
        if (helpers_[i].published.load(std::memory_order_acquire) != 0u &&
            helpers_[i].tid == tid) {
            return helpers_[i].creation_time == creation_time;
        }
    }
    return false;
}

void SessionRing::enter_callback() noexcept {
    active_callbacks_.fetch_add(1u, std::memory_order_acq_rel);
}

void SessionRing::leave_callback() noexcept {
    active_callbacks_.fetch_sub(1u, std::memory_order_release);
}

bool SessionRing::emit(EventRecord record) noexcept {
    if (!events_ || !accepting_.load(std::memory_order_acquire)) {
        return false;
    }
    emitting_.fetch_add(1u, std::memory_order_acq_rel);
    if (!accepting_.load(std::memory_order_acquire)) {
        emitting_.fetch_sub(1u, std::memory_order_release);
        return false;
    }

    const std::uint64_t slot = used_.fetch_add(1ULL, std::memory_order_acq_rel);
    if (slot >= kEventCapacity) {
        overflowed_.store(true, std::memory_order_release);
        emitting_.fetch_sub(1u, std::memory_order_release);
        return false;
    }

    record.sequence = slot + 1ULL;
    if (record.tid == 0) {
        record.tid = query_current_tid();
    }
    if (record.timestamp_qpc == 0) {
        record.timestamp_qpc = query_qpc_now();
    }
    record.generation = generation_.load(std::memory_order_acquire);

    events_[slot].value = record;
    events_[slot].published.store(1u, std::memory_order_release);
    emitting_.fetch_sub(1u, std::memory_order_release);
    return true;
}

void SessionRing::notify_thread(std::uint32_t tid, std::uint32_t reason) noexcept {
    if (tid == 0) {
        tid = query_current_tid();
    }

    // Registered helper threads do not contribute to target-thread generation changes.
    // Retire on detach (reason == 0 or DLL_THREAD_DETACH == 3) so TID reuse is never aliased.
    if (is_helper_tid(tid)) {
#ifdef _WIN32
        constexpr std::uint32_t kDetachReason = DLL_THREAD_DETACH;
#else
        constexpr std::uint32_t kDetachReason = 3u;
#endif
        if (reason == 0u || reason == kDetachReason) {
            const std::uint32_t count = helper_count();
            for (std::uint32_t i = 0; i < count; ++i) {
                if (helpers_[i].published.load(std::memory_order_acquire) == 1u &&
                    helpers_[i].tid == tid) {
                    helpers_[i].published.store(2u, std::memory_order_release);
                }
            }
        }
        return;
    }

    const std::uint64_t notice_gen = generation_.fetch_add(1ULL, std::memory_order_acq_rel) + 1ULL;
    if (!discovering_.load(std::memory_order_acquire)) {
        early_notices_.fetch_add(1ULL, std::memory_order_acq_rel);
        return;
    }

    if (!notices_) {
        return;
    }
    const std::uint32_t slot = notices_used_.fetch_add(1u, std::memory_order_acq_rel);
    if (slot < kNoticeCapacity) {
        ThreadNotice notice{};
        notice.tid = tid;
        notice.reason = reason;
        notice.sequence = static_cast<std::uint64_t>(slot) + 1ULL;
        notice.generation = notice_gen;
        notice.timestamp_qpc = query_qpc_now();
        notices_[slot].value = notice;
        notices_[slot].published.store(1u, std::memory_order_release);
    } else {
        overflowed_.store(true, std::memory_order_release);
    }
}

bool SessionRing::seal(std::uint32_t timeout_ms) noexcept {
    if (sealed()) {
        return true;
    }
    accepting_.store(false, std::memory_order_release);
    const std::uint64_t start = query_tick_ms();
    while (emitting_.load(std::memory_order_acquire) != 0u ||
           active_callbacks_.load(std::memory_order_acquire) != 0u) {
        if (query_tick_ms() - start >= timeout_ms) {
            return false;
        }
        sleep_ms(1);
    }
    sealed_generation_ = generation_.load(std::memory_order_acquire);
    sealed_.store(true, std::memory_order_release);
    return true;
}

} // namespace hookkit
