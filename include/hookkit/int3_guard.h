#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

namespace hookkit {

inline constexpr std::uint32_t kStatusFlagsMask = 0x8D5u; // CF, PF, AF, ZF, SF, OF

enum class CpuReg : std::uint8_t {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rsp = 4,
    Rbp = 5,
    Rsi = 6,
    Rdi = 7,
    R8  = 8,
    R9  = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
};

struct Int3Context {
    std::uint64_t gpr[16]{};
    std::uint64_t rip{};
    std::uint32_t eflags{};
};

enum class Int3EmulationOp : std::uint32_t {
    None = 0,
    Nop = 1,
    AddImm64 = 2,
    MovReg32 = 3,
    MovReg64 = 4,
    LoadReg64FromMem = 5,
    Custom = 6,
};

struct Int3Site;

using MemoryReadFn = bool (*)(std::uint64_t address, void* out_buf, std::size_t size, void* user_data);
using CustomEmulateFn = bool (*)(const Int3Site& site, Int3Context* ctx, void* user_data);

struct Int3Site {
    static constexpr std::size_t kMaxInstructionBytes = 16;

    std::uint64_t address{};
    std::uint32_t length{};
    std::uint8_t original_bytes[kMaxInstructionBytes]{};
    Int3EmulationOp op{Int3EmulationOp::None};
    CpuReg dst_reg{CpuReg::Rax};
    CpuReg src_reg{CpuReg::Rax};
    std::int64_t immediate{};
    CustomEmulateFn custom_fn{nullptr};
    void* custom_user_data{nullptr};
};

std::uint32_t parity_flag(std::uint8_t value) noexcept;

std::uint32_t emulate_add_flags(
    std::uint64_t a,
    std::uint64_t b,
    std::uint8_t width_bytes = 8) noexcept;

std::uint32_t emulate_sub_flags(
    std::uint64_t a,
    std::uint64_t b,
    std::uint8_t width_bytes = 8) noexcept;

inline void apply_status_flags(std::uint32_t* eflags, std::uint32_t status_flags) noexcept {
    if (eflags != nullptr) {
        *eflags = (*eflags & ~kStatusFlagsMask) | (status_flags & kStatusFlagsMask);
    }
}

bool emulate_site_instruction(
    const Int3Site& site,
    std::uint64_t exception_address,
    Int3Context* ctx,
    MemoryReadFn read_fn = nullptr,
    void* read_user_data = nullptr) noexcept;

// Installs full-instruction 0xCC overlays across [site.address, site.address + site.length).
// Validates that all sites match original_bytes before modifying any code bytes.
// If process_handle is nullptr, operates on the current process.
bool install_full_int3_overlay(
    const Int3Site* sites,
    std::size_t count,
    void* process_handle = nullptr) noexcept;

// Restores original_bytes for sites that hold either all-0xCC or original_bytes.
// Refuses to overwrite bytes modified by an external writer.
// If process_handle is nullptr, operates on the current process.
bool restore_int3_overlay(
    const Int3Site* sites,
    std::size_t count,
    void* process_handle = nullptr) noexcept;

class OrphanSelfHealGuard {
public:
    OrphanSelfHealGuard() noexcept = default;
    OrphanSelfHealGuard(
        void* controller_process_handle,
        std::vector<Int3Site> sites,
        bool clear_debug_regs = false) noexcept;
    ~OrphanSelfHealGuard() noexcept;

    OrphanSelfHealGuard(const OrphanSelfHealGuard&) = delete;
    OrphanSelfHealGuard& operator=(const OrphanSelfHealGuard&) = delete;

    void configure(
        void* controller_process_handle,
        std::vector<Int3Site> sites,
        bool clear_debug_regs = false) noexcept;

    bool arm() noexcept;
    void disarm() noexcept;

    bool start_monitor(std::uint32_t poll_interval_ms = 20) noexcept;
    void stop_monitor() noexcept;

    // Blocks up to timeout_ms on controller_process_handle via WaitForSingleObject.
    // If signaled while armed, runs recover_now() and returns true.
    bool wait_and_heal(std::uint32_t timeout_ms = 0xFFFFFFFFu) noexcept;

    // Suspends all other threads in the current process, rewinds any thread with
    // RIP in (site.address, site.address + site.length] back to site.address,
    // optionally clears debug registers, restores original instruction bytes +
    // flushes instruction cache, and resumes suspended threads.
    bool recover_now() noexcept;

    // Rewinds RIP for an in-flight breakpoint caught during teardown.
    bool handle_orphan_breakpoint(std::uint64_t exception_address, Int3Context* ctx) const noexcept;

    bool is_active() const noexcept { return active_.load(std::memory_order_acquire); }
    bool is_code_restored() const noexcept { return code_restored_.load(std::memory_order_acquire); }
    std::uint32_t rewound_threads() const noexcept { return rewound_threads_.load(std::memory_order_acquire); }
    std::uint32_t code_restores() const noexcept { return code_restores_.load(std::memory_order_acquire); }
    std::uint32_t cleared_debug_contexts() const noexcept { return cleared_debug_contexts_.load(std::memory_order_acquire); }

private:
    static std::uint64_t find_rewind_target(
        const std::vector<Int3Site>& sites,
        std::uint64_t rip) noexcept;

    void* controller_handle_{nullptr};
    std::vector<Int3Site> sites_{};
    bool clear_debug_regs_{false};

    std::atomic<bool> active_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> code_restored_{false};
    std::atomic<std::uint32_t> rewound_threads_{0};
    std::atomic<std::uint32_t> code_restores_{0};
    std::atomic<std::uint32_t> cleared_debug_contexts_{0};

    std::thread monitor_thread_{};
};

} // namespace hookkit
