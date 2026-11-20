#include "hookkit/context_capture.h"
#include "hookkit/health.h"
#include "hookkit/hook_transaction.h"
#include "hookkit/int3_guard.h"
#include "hookkit/patch_core.h"
#include "hookkit/patch_receipt.h"
#include "hookkit/session_ring.h"
#include "hookkit/system_routes.h"
#include "hookkit/thread_admission.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define HKIT_ASSERT(cond)                                                                      \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "ASSERT FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                                          \
        }                                                                                      \
    } while (0)

namespace {

std::uint32_t g_pair_enter_hits = 0;
std::uint32_t g_pair_exit_hits = 0;
std::uint64_t g_observed_arg0 = 0;
std::uint64_t g_observed_ret = 0;

void observe_pair_cb(std::uint32_t site_id, std::uint32_t is_exit, hookkit::CapturedRegisters* regs) {
    if (site_id != 0 || regs == nullptr) {
        return;
    }
    if (is_exit == 0) {
        ++g_pair_enter_hits;
        g_observed_arg0 = regs->gpr[static_cast<std::size_t>(hookkit::GprIndex::Rcx)];
    } else {
        ++g_pair_exit_hits;
        g_observed_ret = regs->gpr[static_cast<std::size_t>(hookkit::GprIndex::Rax)];
    }
}

extern "C" std::uint64_t sample_target_fn(std::uint64_t x, std::uint64_t y) {
    return x * 10 + y;
}

class MockPlatformOps final : public hookkit::IPlatformHookOps {
public:
    bool fail_icache{false};

    bool suspend_other_threads(
        hookkit::StoppedThreadSnapshot* out_threads,
        std::size_t max_threads,
        std::size_t* out_count) noexcept override {
        if (max_threads < 1) {
            return false;
        }
        out_threads[0] = hookkit::StoppedThreadSnapshot{101, 0x7FF00000ULL, {1}, true};
        *out_count = 1;
        return true;
    }

    bool recapture_and_verify_contexts(
        const hookkit::StoppedThreadSnapshot*,
        std::size_t) noexcept override {
        return true;
    }

    bool resume_threads(
        const hookkit::StoppedThreadSnapshot*,
        std::size_t) noexcept override {
        return true;
    }

    bool make_writable(void*, std::size_t, std::uint32_t* old_protect) noexcept override {
        *old_protect = 0x20;
        return true;
    }

    bool restore_protection(void*, std::size_t, std::uint32_t) noexcept override {
        return true;
    }

    bool flush_icache(void*, std::size_t) noexcept override {
        return !fail_icache;
    }

    std::uint32_t active_callback_count() const noexcept override {
        return 0;
    }

    void sleep_backoff_ms(std::uint32_t) noexcept override {}
};

int test_context_trampoline() {
    g_pair_enter_hits = 0;
    g_pair_exit_hits = 0;
    g_observed_arg0 = 0;
    g_observed_ret = 0;

    hookkit::clear_site_originals();
    HKIT_ASSERT(hookkit::register_site_original(0, reinterpret_cast<void*>(&sample_target_fn)));
    hookkit::set_pair_observer(&observe_pair_cb);

    using Fn = std::uint64_t (*)(std::uint64_t, std::uint64_t);
    auto tramp = reinterpret_cast<Fn>(hookkit::pair_trampoline_address(0));
    HKIT_ASSERT(tramp != nullptr);

    const std::uint64_t res = tramp(7, 3);
    HKIT_ASSERT(res == 73);
    HKIT_ASSERT(g_pair_enter_hits == 1);
    HKIT_ASSERT(g_pair_exit_hits == 1);
    HKIT_ASSERT(g_observed_arg0 == 7);
    HKIT_ASSERT(g_observed_ret == 73);

    hookkit::set_pair_observer(nullptr);
    hookkit::clear_site_originals();
    return 0;
}

int test_transaction_and_rollback() {
    std::uint8_t buf[16] = {0x10, 0x20, 0x30, 0x40, 0x50};
    void* orig_slot = nullptr;

    hookkit::PreparedPatchPlan plan{};
    plan.target_count = 1;
    plan.ops[0].name = "site_a";
    plan.ops[0].write_addr = buf;
    plan.ops[0].write_size = 5;
    std::memcpy(plan.ops[0].before_bytes, buf, 5);
    const std::uint8_t patched[5] = {0xE9, 0x01, 0x02, 0x03, 0x04};
    std::memcpy(plan.ops[0].after_bytes, patched, 5);
    plan.ops[0].trampoline = reinterpret_cast<void*>(0x12345678ULL);
    plan.ops[0].original_slot = &orig_slot;

    MockPlatformOps ops;
    hookkit::HookTransactionEngine engine(&ops);

    // 1. ContextDriftedWhileStopped must roll back patch bytes and clear trampoline
    engine.set_fault_injection(hookkit::FaultInjectionMode::ForceContextDrift);
    auto rep_drift = engine.execute_attach(plan);
    HKIT_ASSERT(rep_drift.reason == hookkit::TransactionFailureReason::ContextDriftedWhileStopped);
    HKIT_ASSERT(rep_drift.rolled_back);
    HKIT_ASSERT(rep_drift.patched_targets == 0);
    HKIT_ASSERT(buf[0] == 0x10 && buf[4] == 0x50);
    HKIT_ASSERT(orig_slot == nullptr);

    // 2. InstructionCacheFlushFailed must also roll back
    engine.set_fault_injection(hookkit::FaultInjectionMode::None);
    ops.fail_icache = true;
    auto rep_icache = engine.execute_attach(plan);
    HKIT_ASSERT(rep_icache.reason == hookkit::TransactionFailureReason::InstructionCacheFlushFailed);
    HKIT_ASSERT(rep_icache.rolled_back);
    HKIT_ASSERT(buf[0] == 0x10 && buf[4] == 0x50);
    HKIT_ASSERT(orig_slot == nullptr);

    // 3. Clean attach succeeds
    ops.fail_icache = false;
    auto rep_ok = engine.execute_attach(plan);
    HKIT_ASSERT(rep_ok.reason == hookkit::TransactionFailureReason::None);
    HKIT_ASSERT(!rep_ok.rolled_back);
    HKIT_ASSERT(rep_ok.cleanly_resumed);
    HKIT_ASSERT(rep_ok.patched_targets == 1);
    HKIT_ASSERT(std::memcmp(buf, patched, 5) == 0);
    HKIT_ASSERT(orig_slot == plan.ops[0].trampoline);
    return 0;
}

int test_thread_admission_and_health() {
    hookkit::SystemRoutes routes;
    HKIT_ASSERT(routes.register_thread(10, reinterpret_cast<void*>(1), 1000));
    HKIT_ASSERT(routes.register_thread(20, reinterpret_cast<void*>(2), 2000));

    // Thread 20 exited, Thread 30 newly spawned
    const hookkit::LiveThreadInfo snap[2] = {
        {10, 1000, reinterpret_cast<void*>(1)},
        {30, 3000, reinterpret_cast<void*>(3)},
    };
    auto adm = hookkit::admit_live_threads(&routes, 99, snap, 2);
    HKIT_ASSERT(adm.status == hookkit::AdmissionStatus::Ok);
    HKIT_ASSERT(adm.retained_threads == 1);
    HKIT_ASSERT(adm.exited_threads_marked_dead == 1);
    HKIT_ASSERT(adm.newly_admitted_threads == 1);

    // Order-independent two-pass census check
    const hookkit::LiveThreadInfo pass_b[2] = {
        {30, 3000, reinterpret_cast<void*>(3)},
        {10, 1000, reinterpret_cast<void*>(1)},
    };
    HKIT_ASSERT(hookkit::verify_two_pass_census_equal(snap, 2, pass_b, 2));

    hookkit::SeqlockHealthBlock health;
    health.publish(2, 0, 111, 222, 5, 4);
    hookkit::HealthSnapshot hs{};
    HKIT_ASSERT(health.read_consistent(&hs));
    HKIT_ASSERT(hs.magic == hookkit::kHealthMagic);
    HKIT_ASSERT(hs.state == 2);
    HKIT_ASSERT(hs.callback_enter_count == 5);
    return 0;
}

int test_session_ring_receipt_and_int3() {
    hookkit::SessionRing ring;
    HKIT_ASSERT(ring.is_allocated());
    hookkit::EventRecord ev{};
    ev.kind = static_cast<std::uint32_t>(hookkit::EventKind::SiteObserve);
    ev.site_id = 3;
    ev.tid = 42;
    HKIT_ASSERT(ring.emit(ev));
    HKIT_ASSERT(ring.used() == 1);
    HKIT_ASSERT(ring.cell(0)->published.load() == 1);
    HKIT_ASSERT(ring.seal(100));
    HKIT_ASSERT(ring.sealed());

    // PatchReceipt CRC covers reserved field and verifies integrity
    hookkit::TargetPatchRecord rec{};
    std::snprintf(rec.name, sizeof(rec.name), "unit_site");
    rec.target_address = 0x1000;
    rec.write_size = 5;
    hookkit::PatchReceipt receipt{};
    HKIT_ASSERT(hookkit::PatchWitness::capture_manual(hookkit::ReceiptPhase::PostInstall, &rec, 1, &receipt));
    HKIT_ASSERT(hookkit::PatchWitness::verify_receipt_integrity(receipt));
    receipt.reserved ^= 1;
    HKIT_ASSERT(!hookkit::PatchWitness::verify_receipt_integrity(receipt));

    // Arithmetic flag emulation (add & sub)
    const std::uint32_t add_fl = hookkit::emulate_add_flags(0xFFFFFFFFFFFFFFFFULL, 1ULL, 8);
    HKIT_ASSERT((add_fl & 0x1u) != 0);  // CF
    HKIT_ASSERT((add_fl & 0x40u) != 0); // ZF
    const std::uint32_t sub_fl = hookkit::emulate_sub_flags(5ULL, 5ULL, 8);
    HKIT_ASSERT((sub_fl & 0x1u) == 0);  // no borrow
    HKIT_ASSERT((sub_fl & 0x40u) != 0); // ZF
    return 0;
}

} // namespace

int main() {
    if (test_context_trampoline() != 0) return 1;
    if (test_transaction_and_rollback() != 0) return 1;
    if (test_thread_admission_and_health() != 0) return 1;
    if (test_session_ring_receipt_and_int3() != 0) return 1;
    std::printf("ALL WIN64-HOOKKIT NATIVE TESTS PASSED\n");
    return 0;
}
