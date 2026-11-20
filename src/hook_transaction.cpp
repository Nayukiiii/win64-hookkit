#include "hookkit/hook_transaction.h"
#include "patch_core.inc"

namespace hookkit {

HookTransactionEngine::HookTransactionEngine(IPlatformHookOps* ops) noexcept
    : ops_(ops), fault_mode_(FaultInjectionMode::None) {}

bool HookTransactionEngine::any_thread_in_hazard_window(
    const StoppedThreadSnapshot* threads,
    std::size_t thread_count,
    const PreparedPatchPlan& plan) const noexcept {
    for (std::size_t t = 0; t < thread_count; ++t) {
        const std::uintptr_t rip = threads[t].rip;
        for (std::size_t i = 0; i < plan.target_count; ++i) {
            const auto start = reinterpret_cast<std::uintptr_t>(plan.ops[i].write_addr);
            const auto end = start + plan.ops[i].write_size;
            if (rip >= start && rip < end) {
                return true;
            }
            if (plan.ops[i].trampoline != nullptr) {
                const auto tramp_start = reinterpret_cast<std::uintptr_t>(plan.ops[i].trampoline);
                const auto tramp_end = tramp_start + 64u;
                if (rip >= tramp_start && rip < tramp_end) {
                    return true;
                }
            }
        }
    }
    return false;
}

TransactionReport HookTransactionEngine::execute_attach(const PreparedPatchPlan& plan) noexcept {
    return execute_common(plan, true);
}

TransactionReport HookTransactionEngine::execute_detach(const PreparedPatchPlan& detach_plan) noexcept {
    return execute_common(detach_plan, false);
}

TransactionReport HookTransactionEngine::execute_common(
    const PreparedPatchPlan& plan,
    bool is_attach) noexcept {
    TransactionReport report{};
    report.reason = TransactionFailureReason::None;
    report.stopped_threads = 0;
    report.patched_targets = 0;
    report.rip_retry_rounds = 0;
    report.rolled_back = false;
    report.cleanly_resumed = false;

    if (ops_ == nullptr || plan.target_count == 0 || plan.target_count > 512) {
        report.reason = TransactionFailureReason::InvalidState;
        return report;
    }

    StoppedThreadSnapshot stopped[kMaxThreads]{};
    std::size_t stopped_count = 0;

    for (std::size_t attempt = 0; attempt <= kMaxRipRetries; ++attempt) {
        report.rip_retry_rounds = attempt;
        if (fault_mode_ == FaultInjectionMode::FailThreadSuspend) {
            report.reason = TransactionFailureReason::ThreadSuspendFailed;
            return report;
        }
        if (!ops_->suspend_other_threads(stopped, kMaxThreads, &stopped_count)) {
            report.reason = TransactionFailureReason::ThreadSuspendFailed;
            return report;
        }
        report.stopped_threads = stopped_count;

        const bool in_hazard = (fault_mode_ == FaultInjectionMode::ForceRipHazard) ||
                               any_thread_in_hazard_window(stopped, stopped_count, plan);
        const bool busy_callbacks = !is_attach &&
                                    ((fault_mode_ == FaultInjectionMode::ForceCallbackBusy) ||
                                     (ops_->active_callback_count() != 0));

        if (!in_hazard && !busy_callbacks) {
            break;
        }

        ops_->resume_threads(stopped, stopped_count);
        if (attempt == kMaxRipRetries) {
            report.reason = in_hazard
                                ? TransactionFailureReason::RipInsideHazardWindow
                                : TransactionFailureReason::CallbackNotQuiescent;
            return report;
        }
        ops_->sleep_backoff_ms(1);
    }

    std::size_t mismatch_idx = 0;
    if (!verify_plan_before_bytes(plan, &mismatch_idx)) {
        ops_->resume_threads(stopped, stopped_count);
        report.reason = TransactionFailureReason::BeforeBytesMismatch;
        return report;
    }

    std::uint32_t old_protects[512]{};
    std::size_t protected_count = 0;

    if (fault_mode_ == FaultInjectionMode::FailProtectRWX) {
        ops_->resume_threads(stopped, stopped_count);
        report.reason = TransactionFailureReason::MemoryProtectFailed;
        return report;
    }

    for (std::size_t i = 0; i < plan.target_count; ++i) {
        if (!ops_->make_writable(
                plan.ops[i].write_addr,
                plan.ops[i].write_size,
                &old_protects[i])) {
            for (std::size_t j = protected_count; j > 0; --j) {
                ops_->restore_protection(
                    plan.ops[j - 1].write_addr,
                    plan.ops[j - 1].write_size,
                    old_protects[j - 1]);
            }
            ops_->resume_threads(stopped, stopped_count);
            report.reason = TransactionFailureReason::MemoryProtectFailed;
            return report;
        }
        ++protected_count;
    }

    if (is_attach) {
        publish_trampolines(plan);
    }

    apply_plan_bytes(plan, plan.target_count);
    report.patched_targets = plan.target_count;

    if (fault_mode_ == FaultInjectionMode::CorruptMidWrite ||
        !verify_plan_after_bytes(plan, &mismatch_idx)) {
        rollback_plan_bytes(plan, plan.target_count);
        if (is_attach) {
            clear_trampolines(plan);
        }
        for (std::size_t j = protected_count; j > 0; --j) {
            ops_->restore_protection(
                plan.ops[j - 1].write_addr,
                plan.ops[j - 1].write_size,
                old_protects[j - 1]);
        }
        ops_->resume_threads(stopped, stopped_count);
        report.rolled_back = true;
        report.reason = TransactionFailureReason::AfterBytesMismatch;
        return report;
    }

    bool restore_ok = (fault_mode_ != FaultInjectionMode::FailProtectRestore);
    for (std::size_t i = 0; i < protected_count && restore_ok; ++i) {
        if (!ops_->restore_protection(
                plan.ops[i].write_addr,
                plan.ops[i].write_size,
                old_protects[i])) {
            restore_ok = false;
        }
    }

    auto rollback_and_abort = [&](TransactionFailureReason reason) noexcept -> TransactionReport {
        for (std::size_t i = 0; i < plan.target_count; ++i) {
            std::uint32_t dummy = 0;
            ops_->make_writable(plan.ops[i].write_addr, plan.ops[i].write_size, &dummy);
        }
        rollback_plan_bytes(plan, plan.target_count);
        if (is_attach) {
            clear_trampolines(plan);
        }
        for (std::size_t i = 0; i < protected_count; ++i) {
            ops_->restore_protection(
                plan.ops[i].write_addr,
                plan.ops[i].write_size,
                old_protects[i]);
        }
        ops_->resume_threads(stopped, stopped_count);
        report.patched_targets = 0;
        report.rolled_back = true;
        report.reason = reason;
        return report;
    };

    if (!restore_ok) {
        return rollback_and_abort(TransactionFailureReason::ProtectRestoreFailed);
    }

    for (std::size_t i = 0; i < plan.target_count; ++i) {
        if (!ops_->flush_icache(plan.ops[i].write_addr, plan.ops[i].write_size)) {
            return rollback_and_abort(TransactionFailureReason::InstructionCacheFlushFailed);
        }
    }

    if (fault_mode_ == FaultInjectionMode::ForceContextDrift ||
        !ops_->recapture_and_verify_contexts(stopped, stopped_count)) {
        return rollback_and_abort(TransactionFailureReason::ContextDriftedWhileStopped);
    }

    if (!is_attach) {
        clear_trampolines(plan);
    }

    if (fault_mode_ == FaultInjectionMode::FailThreadResume ||
        !ops_->resume_threads(stopped, stopped_count)) {
        report.reason = TransactionFailureReason::ThreadResumeFailed;
        return report;
    }

    report.cleanly_resumed = true;
    return report;
}

} // namespace hookkit
