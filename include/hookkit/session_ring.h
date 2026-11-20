#pragma once

#include "hookkit/context_capture.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace hookkit {

static_assert(
    std::atomic<std::uint64_t>::is_always_lock_free &&
        std::atomic<std::uint32_t>::is_always_lock_free,
    "64-bit and 32-bit atomics must be lock-free");

enum class EventKind : std::uint32_t {
    Generic = 0,
    CallEnter = 1,
    CallExit = 2,
    SiteObserve = 3,
    ThreadNotice = 4,
    Diagnostic = 5,
};

struct EventRecord {
    std::uint32_t kind{};
    std::uint32_t site_id{};
    std::uint32_t tid{};
    std::uint32_t flags{};
    std::uint64_t sequence{};
    std::uint64_t timestamp_qpc{};
    std::uint64_t generation{};
    std::uint64_t payload[4]{};
    std::uint32_t has_regs{};
    CapturedRegisters regs{};
};

struct EventCell {
    std::atomic<std::uint32_t> published{0};
    EventRecord value{};
};

struct ThreadNotice {
    std::uint32_t tid{};
    std::uint32_t reason{};
    std::uint64_t sequence{};
    std::uint64_t generation{};
    std::uint64_t timestamp_qpc{};
};

struct NoticeCell {
    std::atomic<std::uint32_t> published{0};
    ThreadNotice value{};
};

class SessionRing {
public:
    static constexpr std::size_t kEventCapacity = 131072;
    static constexpr std::size_t kNoticeCapacity = 4096;
    static constexpr std::size_t kMaxHelpers = 32;

    SessionRing() noexcept;
    ~SessionRing() = default;

    SessionRing(const SessionRing&) = delete;
    SessionRing& operator=(const SessionRing&) = delete;

    bool is_allocated() const noexcept {
        return events_ != nullptr && notices_ != nullptr;
    }

    void reset() noexcept;

    // Helper-thread spawn exclusion gate and registry.
    void enter_spawn() noexcept;
    bool try_enter_spawn(std::uint32_t timeout_ms) noexcept;
    void leave_spawn() noexcept;

    bool register_helper(std::uint32_t tid, std::uint64_t creation_time) noexcept;
    bool is_helper_tid(std::uint32_t tid) const noexcept;
    bool is_helper(std::uint32_t tid, std::uint64_t creation_time) const noexcept;
    std::uint32_t helper_count() const noexcept {
        const std::uint32_t n = helper_reserved_.load(std::memory_order_acquire);
        return n < kMaxHelpers ? n : static_cast<std::uint32_t>(kMaxHelpers);
    }

    // Active callback reference count for quiescence drain before unload.
    void enter_callback() noexcept;
    void leave_callback() noexcept;
    std::uint32_t active_callbacks() const noexcept {
        return active_callbacks_.load(std::memory_order_acquire);
    }

    // Lock-free event emission into the 131,072-slot ring.
    bool emit(EventRecord record) noexcept;

    // Thread attach/detach notification ring (4,096 slots).
    void begin_discovery() noexcept {
        discovering_.store(true, std::memory_order_release);
    }
    bool discovery_enabled() const noexcept {
        return discovering_.load(std::memory_order_acquire);
    }
    void notify_thread(std::uint32_t tid, std::uint32_t reason) noexcept;

    // Quiescence drain barrier: stops accepting new events and waits until
    // all active emitters and active callbacks reach zero.
    void set_accepting(bool value) noexcept {
        accepting_.store(value, std::memory_order_release);
    }
    bool accepting() const noexcept {
        return accepting_.load(std::memory_order_acquire);
    }
    bool seal(std::uint32_t timeout_ms = 5000) noexcept;
    bool sealed() const noexcept {
        return sealed_.load(std::memory_order_acquire);
    }

    std::uint64_t used() const noexcept {
        const std::uint64_t raw = used_.load(std::memory_order_acquire);
        return raw < kEventCapacity ? raw : static_cast<std::uint64_t>(kEventCapacity);
    }
    std::uint64_t total_attempted() const noexcept {
        return used_.load(std::memory_order_acquire);
    }
    std::uint64_t dropped_events() const noexcept {
        const std::uint64_t raw = used_.load(std::memory_order_acquire);
        return raw > kEventCapacity ? raw - kEventCapacity : 0ULL;
    }
    bool overflowed() const noexcept {
        return overflowed_.load(std::memory_order_acquire);
    }

    std::uint32_t notices() const noexcept {
        const std::uint32_t raw = notices_used_.load(std::memory_order_acquire);
        return raw < kNoticeCapacity ? raw : static_cast<std::uint32_t>(kNoticeCapacity);
    }
    std::uint64_t early_notices() const noexcept {
        return early_notices_.load(std::memory_order_acquire);
    }
    std::uint64_t generation() const noexcept {
        return generation_.load(std::memory_order_acquire);
    }
    std::uint64_t sealed_generation() const noexcept {
        return sealed_generation_;
    }

    const EventCell* cell(std::size_t index) const noexcept {
        if (!events_ || index >= kEventCapacity) {
            return nullptr;
        }
        return &events_[index];
    }

    const NoticeCell* notice(std::size_t index) const noexcept {
        if (!notices_ || index >= kNoticeCapacity) {
            return nullptr;
        }
        return &notices_[index];
    }

    class CallbackScope {
    public:
        explicit CallbackScope(SessionRing& ring) noexcept : ring_(ring) {
            ring_.enter_callback();
        }
        ~CallbackScope() noexcept {
            ring_.leave_callback();
        }
        CallbackScope(const CallbackScope&) = delete;
        CallbackScope& operator=(const CallbackScope&) = delete;

    private:
        SessionRing& ring_;
    };

private:
    struct HelperCell {
        std::atomic<std::uint32_t> published{0};
        std::uint32_t tid{0};
        std::uint64_t creation_time{0};
    };

    std::unique_ptr<EventCell[]> events_;
    std::unique_ptr<NoticeCell[]> notices_;
    HelperCell helpers_[kMaxHelpers]{};

    std::atomic<std::uint64_t> used_{0};
    std::atomic<std::uint64_t> generation_{1};
    std::atomic<std::uint64_t> early_notices_{0};

    std::atomic<std::uint32_t> notices_used_{0};
    std::atomic<std::uint32_t> helper_reserved_{0};
    std::atomic<std::uint32_t> spawn_gate_{0};
    std::atomic<std::uint32_t> emitting_{0};
    std::atomic<std::uint32_t> active_callbacks_{0};

    std::atomic<bool> accepting_{true};
    std::atomic<bool> discovering_{false};
    std::atomic<bool> overflowed_{false};
    std::atomic<bool> sealed_{false};
    std::uint64_t sealed_generation_{0};
};

} // namespace hookkit
