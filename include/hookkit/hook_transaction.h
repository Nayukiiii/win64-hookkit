#pragma once

#include "hookkit/patch_core.h"
#include <cstddef>
#include <cstdint>

namespace hookkit {

enum class TransactionFailureReason : std::uint32_t {
    None = 0,
    InvalidState = 1,
    PlanPreparationFailed = 2,
    ThreadCensusFailed = 3,
    ThreadSuspendFailed = 4,
    ThreadContextFailed = 5,
    RipInsideHazardWindow = 6,
    CallbackNotQuiescent = 7,
    MemoryProtectFailed = 8,
    BeforeBytesMismatch = 9,
    AfterBytesMismatch = 10,
    ProtectRestoreFailed = 11,
    InstructionCacheFlushFailed = 12,
    ContextDriftedWhileStopped = 13,
    ThreadResumeFailed = 14,
};

enum class FaultInjectionMode : std::uint32_t {
    None = 0,
    FailThreadSuspend = 1,
    ForceRipHazard = 2,
    ForceCallbackBusy = 3,
    FailProtectRWX = 4,
    CorruptMidWrite = 5,
    FailProtectRestore = 6,
    ForceContextDrift = 7,
    FailThreadResume = 8,
};

struct StoppedThreadSnapshot {
    std::uint32_t tid;
    std::uintptr_t rip;
    std::uint8_t context_digest[32];
    bool suspended;
};

struct TransactionReport {
    TransactionFailureReason reason;
    std::size_t stopped_threads;
    std::size_t patched_targets;
    std::size_t rip_retry_rounds;
    bool rolled_back;
    bool cleanly_resumed;
};

class IPlatformHookOps {
public:
    virtual ~IPlatformHookOps() = default;
    virtual bool suspend_other_threads(
        StoppedThreadSnapshot* out_threads,
        std::size_t max_threads,
        std::size_t* out_count) noexcept = 0;
    virtual bool recapture_and_verify_contexts(
        const StoppedThreadSnapshot* baseline,
        std::size_t count) noexcept = 0;
    virtual bool resume_threads(
        const StoppedThreadSnapshot* threads,
        std::size_t count) noexcept = 0;
    virtual bool make_writable(void* addr, std::size_t size, std::uint32_t* old_protect) noexcept = 0;
    virtual bool restore_protection(void* addr, std::size_t size, std::uint32_t old_protect) noexcept = 0;
    virtual bool flush_icache(void* addr, std::size_t size) noexcept = 0;
    virtual std::uint32_t active_callback_count() const noexcept = 0;
    virtual void sleep_backoff_ms(std::uint32_t ms) noexcept = 0;
};

class HookTransactionEngine {
public:
    static constexpr std::size_t kMaxThreads = 512;
    static constexpr std::size_t kMaxRipRetries = 20;

    explicit HookTransactionEngine(IPlatformHookOps* ops) noexcept;

    void set_fault_injection(FaultInjectionMode mode) noexcept { fault_mode_ = mode; }

    TransactionReport execute_attach(const PreparedPatchPlan& plan) noexcept;
    TransactionReport execute_detach(const PreparedPatchPlan& detach_plan) noexcept;

private:
    bool any_thread_in_hazard_window(
        const StoppedThreadSnapshot* threads,
        std::size_t thread_count,
        const PreparedPatchPlan& plan) const noexcept;

    TransactionReport execute_common(const PreparedPatchPlan& plan, bool is_attach) noexcept;

    IPlatformHookOps* ops_;
    FaultInjectionMode fault_mode_;
};

} // namespace hookkit
