#pragma once

#include <atomic>
#include <cstdint>

namespace hookkit {

static constexpr std::uint64_t kHealthMagic = 0x3130485F54494B48ULL; // "HKIT_H01"
static constexpr std::uint64_t kRouteMagic  = 0x3130585F54494B48ULL; // "HKIT_X01"

struct HealthSnapshot {
    std::uint64_t magic;
    std::uint64_t seq;
    std::uint32_t state;
    std::uint32_t last_failure_reason;
    std::uint64_t attach_qpc;
    std::uint64_t detach_qpc;
    std::uint64_t callback_enter_count;
    std::uint64_t callback_exit_count;
};

class SeqlockHealthBlock {
public:
    SeqlockHealthBlock() noexcept;

    void publish(
        std::uint32_t state,
        std::uint32_t last_failure_reason,
        std::uint64_t attach_qpc,
        std::uint64_t detach_qpc,
        std::uint64_t cb_enter,
        std::uint64_t cb_exit) noexcept;

    bool read_consistent(HealthSnapshot* out) const noexcept;

private:
    std::atomic<std::uint64_t> seq_;
    HealthSnapshot payload_;
};

} // namespace hookkit
