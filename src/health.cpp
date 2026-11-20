#include "hookkit/health.h"

namespace hookkit {

SeqlockHealthBlock::SeqlockHealthBlock() noexcept
    : seq_(0),
      payload_{kHealthMagic, 0, 0, 0, 0, 0, 0, 0} {}

void SeqlockHealthBlock::publish(
    std::uint32_t state,
    std::uint32_t last_failure_reason,
    std::uint64_t attach_qpc,
    std::uint64_t detach_qpc,
    std::uint64_t cb_enter,
    std::uint64_t cb_exit) noexcept {
    const std::uint64_t prev = seq_.load(std::memory_order_relaxed);
    const std::uint64_t odd = prev + 1;
    seq_.store(odd, std::memory_order_release);

    payload_.magic = kHealthMagic;
    payload_.seq = odd + 1;
    payload_.state = state;
    payload_.last_failure_reason = last_failure_reason;
    payload_.attach_qpc = attach_qpc;
    payload_.detach_qpc = detach_qpc;
    payload_.callback_enter_count = cb_enter;
    payload_.callback_exit_count = cb_exit;

    seq_.store(odd + 1, std::memory_order_release);
}

bool SeqlockHealthBlock::read_consistent(HealthSnapshot* out) const noexcept {
    if (out == nullptr) {
        return false;
    }
    for (int attempt = 0; attempt < 64; ++attempt) {
        const std::uint64_t s1 = seq_.load(std::memory_order_acquire);
        if ((s1 & 1ULL) != 0ULL) {
            continue;
        }
        const HealthSnapshot copy = payload_;
        std::atomic_thread_fence(std::memory_order_acquire);
        const std::uint64_t s2 = seq_.load(std::memory_order_acquire);
        if (s1 == s2 && copy.magic == kHealthMagic) {
            *out = copy;
            return true;
        }
    }
    return false;
}

} // namespace hookkit
