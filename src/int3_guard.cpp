#include "hookkit/int3_guard.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <TlHelp32.h>
#else
#include <chrono>
#endif

#include <cstring>

namespace hookkit {
namespace {

constexpr std::uint8_t kInt3Opcode = 0xCCu;

std::uint64_t width_mask(std::uint8_t width_bytes) noexcept {
    switch (width_bytes) {
        case 1: return 0xFFULL;
        case 2: return 0xFFFFULL;
        case 4: return 0xFFFFFFFFULL;
        case 8: return 0xFFFFFFFFFFFFFFFFULL;
        default: return 0ULL;
    }
}

std::uint64_t width_sign_bit(std::uint8_t width_bytes) noexcept {
    switch (width_bytes) {
        case 1: return 1ULL << 7;
        case 2: return 1ULL << 15;
        case 4: return 1ULL << 31;
        case 8: return 1ULL << 63;
        default: return 0ULL;
    }
}

bool read_target_memory(
    void* process_handle,
    std::uint64_t address,
    void* out_buf,
    std::size_t size) noexcept {
    if (address == 0 || out_buf == nullptr || size == 0) {
        return false;
    }
#ifdef _WIN32
    if (process_handle != nullptr) {
        SIZE_T got = 0;
        return ReadProcessMemory(
                   process_handle,
                   reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
                   out_buf,
                   size,
                   &got) != FALSE &&
               got == size;
    }
#if defined(_MSC_VER)
    __try {
        std::memcpy(
            out_buf,
            reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
            size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    std::memcpy(
        out_buf,
        reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
        size);
    return true;
#endif
#else
    (void)process_handle;
    std::memcpy(
        out_buf,
        reinterpret_cast<const void*>(static_cast<std::uintptr_t>(address)),
        size);
    return true;
#endif
}

bool write_target_memory(
    void* process_handle,
    std::uint64_t address,
    const void* bytes,
    std::size_t size) noexcept {
    if (address == 0 || bytes == nullptr || size == 0) {
        return false;
    }
#ifdef _WIN32
    auto* ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(address));
    DWORD old_protect = 0;
    DWORD discard = 0;
    if (process_handle != nullptr) {
        if (!VirtualProtectEx(process_handle, ptr, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
            return false;
        }
        SIZE_T written = 0;
        const bool wrote =
            WriteProcessMemory(process_handle, ptr, bytes, size, &written) != FALSE &&
            written == size;
        const bool restored =
            VirtualProtectEx(process_handle, ptr, size, old_protect, &discard) != FALSE;
        const bool flushed =
            FlushInstructionCache(process_handle, ptr, size) != FALSE;
        std::uint8_t verify[Int3Site::kMaxInstructionBytes]{};
        return wrote && restored && flushed &&
               size <= sizeof(verify) &&
               read_target_memory(process_handle, address, verify, size) &&
               std::memcmp(verify, bytes, size) == 0;
    }

    if (!VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }
    std::memcpy(ptr, bytes, size);
    const bool restored = VirtualProtect(ptr, size, old_protect, &discard) != FALSE;
    const bool flushed = FlushInstructionCache(GetCurrentProcess(), ptr, size) != FALSE;
    return restored && flushed;
#else
    (void)process_handle;
    std::memcpy(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(address)),
        bytes,
        size);
    return true;
#endif
}

bool site_matches_bytes(
    void* process_handle,
    const Int3Site& site,
    bool expect_int3) noexcept {
    if (site.address == 0 || site.length == 0 || site.length > Int3Site::kMaxInstructionBytes) {
        return false;
    }
    std::uint8_t buf[Int3Site::kMaxInstructionBytes]{};
    if (!read_target_memory(process_handle, site.address, buf, site.length)) {
        return false;
    }
    if (!expect_int3) {
        return std::memcmp(buf, site.original_bytes, site.length) == 0;
    }
    for (std::uint32_t i = 0; i < site.length; ++i) {
        if (buf[i] != kInt3Opcode) {
            return false;
        }
    }
    return true;
}

bool site_belongs_to_overlay(void* process_handle, const Int3Site& site) noexcept {
    if (site.address == 0 || site.length == 0 || site.length > Int3Site::kMaxInstructionBytes) {
        return false;
    }
    std::uint8_t buf[Int3Site::kMaxInstructionBytes]{};
    if (!read_target_memory(process_handle, site.address, buf, site.length)) {
        return false;
    }
    for (std::uint32_t i = 0; i < site.length; ++i) {
        if (buf[i] != kInt3Opcode && buf[i] != site.original_bytes[i]) {
            return false;
        }
    }
    return true;
}

} // namespace

std::uint32_t parity_flag(std::uint8_t value) noexcept {
    std::uint32_t ones = 0;
    for (std::uint32_t i = 0; i < 8; ++i) {
        ones += (value >> i) & 1u;
    }
    return (ones & 1u) == 0u ? 0x4u : 0u;
}

std::uint32_t emulate_add_flags(
    std::uint64_t a,
    std::uint64_t b,
    std::uint8_t width_bytes) noexcept {
    const std::uint64_t mask = width_mask(width_bytes);
    const std::uint64_t sign_bit = width_sign_bit(width_bytes);
    if (mask == 0ULL) {
        return 0u;
    }

    const std::uint64_t lhs = a & mask;
    const std::uint64_t rhs = b & mask;
    const std::uint64_t result = (lhs + rhs) & mask;

    const bool carry = (width_bytes == 8)
                           ? (result < lhs)
                           : ((lhs + rhs) > mask);
    const bool adjust = (((lhs ^ rhs ^ result) & 0x10ULL) != 0ULL);
    const bool zero = (result == 0ULL);
    const bool sign = ((result & sign_bit) != 0ULL);
    const bool overflow = (((~(lhs ^ rhs)) & (lhs ^ result) & sign_bit) != 0ULL);

    return (carry ? 0x1u : 0u) |
           parity_flag(static_cast<std::uint8_t>(result & 0xFFu)) |
           (adjust ? 0x10u : 0u) |
           (zero ? 0x40u : 0u) |
           (sign ? 0x80u : 0u) |
           (overflow ? 0x800u : 0u);
}

std::uint32_t emulate_sub_flags(
    std::uint64_t a,
    std::uint64_t b,
    std::uint8_t width_bytes) noexcept {
    const std::uint64_t mask = width_mask(width_bytes);
    const std::uint64_t sign_bit = width_sign_bit(width_bytes);
    if (mask == 0ULL) {
        return 0u;
    }

    const std::uint64_t lhs = a & mask;
    const std::uint64_t rhs = b & mask;
    const std::uint64_t result = (lhs - rhs) & mask;

    const bool borrow = lhs < rhs;
    const bool adjust = (((lhs ^ rhs ^ result) & 0x10ULL) != 0ULL);
    const bool zero = (result == 0ULL);
    const bool sign = ((result & sign_bit) != 0ULL);
    const bool overflow = ((((lhs ^ rhs) & (lhs ^ result)) & sign_bit) != 0ULL);

    return (borrow ? 0x1u : 0u) |
           parity_flag(static_cast<std::uint8_t>(result & 0xFFu)) |
           (adjust ? 0x10u : 0u) |
           (zero ? 0x40u : 0u) |
           (sign ? 0x80u : 0u) |
           (overflow ? 0x800u : 0u);
}

bool emulate_site_instruction(
    const Int3Site& site,
    std::uint64_t exception_address,
    Int3Context* ctx,
    MemoryReadFn read_fn,
    void* read_user_data) noexcept {
    if (ctx == nullptr || site.address == 0 || site.length == 0) {
        return false;
    }
    // Windows reports ExceptionAddress at the 0xCC byte and RIP at ExceptionAddress + 1.
    if (exception_address != site.address || ctx->rip != exception_address + 1ULL) {
        return false;
    }

    const auto dst_idx = static_cast<std::size_t>(site.dst_reg);
    const auto src_idx = static_cast<std::size_t>(site.src_reg);
    if (dst_idx >= 16 || src_idx >= 16) {
        return false;
    }

    switch (site.op) {
        case Int3EmulationOp::None:
            return false;

        case Int3EmulationOp::Nop:
            break;

        case Int3EmulationOp::AddImm64: {
            const std::uint64_t lhs = ctx->gpr[dst_idx];
            const std::uint64_t rhs = static_cast<std::uint64_t>(site.immediate);
            const std::uint32_t flags = emulate_add_flags(lhs, rhs, 8);
            apply_status_flags(&ctx->eflags, flags);
            ctx->gpr[dst_idx] = lhs + rhs;
            break;
        }

        case Int3EmulationOp::MovReg32:
            ctx->gpr[dst_idx] = static_cast<std::uint64_t>(
                static_cast<std::uint32_t>(ctx->gpr[src_idx]));
            break;

        case Int3EmulationOp::MovReg64:
            ctx->gpr[dst_idx] = ctx->gpr[src_idx];
            break;

        case Int3EmulationOp::LoadReg64FromMem: {
            if (read_fn == nullptr) {
                return false;
            }
            const std::uint64_t effective_addr =
                ctx->gpr[src_idx] + static_cast<std::uint64_t>(site.immediate);
            std::uint64_t loaded = 0;
            if (!read_fn(effective_addr, &loaded, sizeof(loaded), read_user_data)) {
                return false;
            }
            ctx->gpr[dst_idx] = loaded;
            break;
        }

        case Int3EmulationOp::Custom:
            if (site.custom_fn == nullptr) {
                return false;
            }
            if (!site.custom_fn(site, ctx, site.custom_user_data)) {
                return false;
            }
            ctx->rip = site.address + site.length;
            return true;

        default:
            return false;
    }

    ctx->rip = site.address + site.length;
    return true;
}

bool install_full_int3_overlay(
    const Int3Site* sites,
    std::size_t count,
    void* process_handle) noexcept {
    if (sites == nullptr || count == 0) {
        return false;
    }

    for (std::size_t i = 0; i < count; ++i) {
        if (!site_matches_bytes(process_handle, sites[i], false)) {
            return false;
        }
    }

    std::uint8_t traps[Int3Site::kMaxInstructionBytes]{};
    std::memset(traps, kInt3Opcode, sizeof(traps));

    for (std::size_t i = 0; i < count; ++i) {
        if (!write_target_memory(process_handle, sites[i].address, traps, sites[i].length)) {
            return false;
        }
    }
    return true;
}

bool restore_int3_overlay(
    const Int3Site* sites,
    std::size_t count,
    void* process_handle) noexcept {
    if (sites == nullptr || count == 0) {
        return false;
    }

    for (std::size_t i = 0; i < count; ++i) {
        if (!site_belongs_to_overlay(process_handle, sites[i])) {
            return false;
        }
    }

    for (std::size_t i = 0; i < count; ++i) {
        if (!site_matches_bytes(process_handle, sites[i], false)) {
            if (!write_target_memory(
                    process_handle,
                    sites[i].address,
                    sites[i].original_bytes,
                    sites[i].length)) {
                return false;
            }
        }
    }
    return true;
}

OrphanSelfHealGuard::OrphanSelfHealGuard(
    void* controller_process_handle,
    std::vector<Int3Site> sites,
    bool clear_debug_regs) noexcept
    : controller_handle_(controller_process_handle),
      sites_(std::move(sites)),
      clear_debug_regs_(clear_debug_regs) {}

OrphanSelfHealGuard::~OrphanSelfHealGuard() noexcept {
    disarm();
    stop_monitor();
}

void OrphanSelfHealGuard::configure(
    void* controller_process_handle,
    std::vector<Int3Site> sites,
    bool clear_debug_regs) noexcept {
    disarm();
    stop_monitor();
    controller_handle_ = controller_process_handle;
    sites_ = std::move(sites);
    clear_debug_regs_ = clear_debug_regs;
    code_restored_.store(false, std::memory_order_release);
}

bool OrphanSelfHealGuard::arm() noexcept {
    if (sites_.empty()) {
        return false;
    }
    code_restored_.store(false, std::memory_order_release);
    active_.store(true, std::memory_order_release);
    return true;
}

void OrphanSelfHealGuard::disarm() noexcept {
    active_.store(false, std::memory_order_release);
}

bool OrphanSelfHealGuard::start_monitor(std::uint32_t poll_interval_ms) noexcept {
    if (controller_handle_ == nullptr || monitor_thread_.joinable()) {
        return false;
    }
    stop_requested_.store(false, std::memory_order_release);
    const std::uint32_t interval = poll_interval_ms == 0 ? 10u : poll_interval_ms;

    monitor_thread_ = std::thread([this, interval]() {
        while (!stop_requested_.load(std::memory_order_acquire)) {
#ifdef _WIN32
            const DWORD wait_rc = WaitForSingleObject(controller_handle_, interval);
            if (wait_rc == WAIT_OBJECT_0) {
                if (active_.load(std::memory_order_acquire)) {
                    recover_now();
                }
                break;
            }
            if (wait_rc == WAIT_FAILED) {
                break;
            }
#else
            (void)interval;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
#endif
        }
    });
    return true;
}

void OrphanSelfHealGuard::stop_monitor() noexcept {
    stop_requested_.store(true, std::memory_order_release);
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
}

bool OrphanSelfHealGuard::wait_and_heal(std::uint32_t timeout_ms) noexcept {
    if (controller_handle_ == nullptr) {
        return false;
    }
#ifdef _WIN32
    const DWORD wait_rc = WaitForSingleObject(controller_handle_, timeout_ms);
    if (wait_rc != WAIT_OBJECT_0) {
        return false;
    }
    if (!active_.load(std::memory_order_acquire)) {
        return false;
    }
    return recover_now();
#else
    (void)timeout_ms;
    return false;
#endif
}

std::uint64_t OrphanSelfHealGuard::find_rewind_target(
    const std::vector<Int3Site>& sites,
    std::uint64_t rip) noexcept {
    for (const auto& site : sites) {
        if (site.address != 0 && site.length > 0 &&
            rip > site.address && rip <= site.address + site.length) {
            return site.address;
        }
    }
    return 0ULL;
}

bool OrphanSelfHealGuard::recover_now() noexcept {
    if (sites_.empty()) {
        return false;
    }

#ifdef _WIN32
    constexpr std::size_t kMaxThreads = 1024;
    HANDLE stopped_handles[kMaxThreads]{};
    std::size_t stopped_count = 0;

    const DWORD self_tid = GetCurrentThreadId();
    const DWORD self_pid = GetCurrentProcessId();
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID != self_pid ||
                    entry.th32ThreadID == self_tid ||
                    stopped_count >= kMaxThreads) {
                    continue;
                }
                const HANDLE thread = OpenThread(
                    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                        THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                    FALSE,
                    entry.th32ThreadID);
                if (thread == nullptr) {
                    continue;
                }
                if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
                    CloseHandle(thread);
                    continue;
                }
                stopped_handles[stopped_count++] = thread;

                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_CONTROL |
                                   (clear_debug_regs_ ? CONTEXT_DEBUG_REGISTERS : 0u);
                if (GetThreadContext(thread, &ctx)) {
                    bool modified = false;
#if defined(_M_X64) || defined(__x86_64__)
                    const std::uint64_t rewind_addr = find_rewind_target(sites_, ctx.Rip);
                    if (rewind_addr != 0ULL) {
                        ctx.Rip = rewind_addr;
                        rewound_threads_.fetch_add(1u, std::memory_order_acq_rel);
                        modified = true;
                    }
#endif
                    if (clear_debug_regs_) {
                        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 ||
                            ctx.Dr3 != 0 || ctx.Dr6 != 0 || ctx.Dr7 != 0) {
                            ctx.Dr0 = 0;
                            ctx.Dr1 = 0;
                            ctx.Dr2 = 0;
                            ctx.Dr3 = 0;
                            ctx.Dr6 = 0;
                            ctx.Dr7 = 0;
                            cleared_debug_contexts_.fetch_add(1u, std::memory_order_acq_rel);
                            modified = true;
                        }
                    }
                    if (modified) {
                        SetThreadContext(thread, &ctx);
                    }
                }
            } while (Thread32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    const bool restored = restore_int3_overlay(sites_.data(), sites_.size(), nullptr);
    if (restored) {
        code_restores_.fetch_add(1u, std::memory_order_acq_rel);
        code_restored_.store(true, std::memory_order_release);
    }

    for (std::size_t i = 0; i < stopped_count; ++i) {
        ResumeThread(stopped_handles[i]);
        CloseHandle(stopped_handles[i]);
    }
    active_.store(false, std::memory_order_release);
    return restored;
#else
    const bool restored = restore_int3_overlay(sites_.data(), sites_.size(), nullptr);
    if (restored) {
        code_restores_.fetch_add(1u, std::memory_order_acq_rel);
        code_restored_.store(true, std::memory_order_release);
    }
    active_.store(false, std::memory_order_release);
    return restored;
#endif
}

bool OrphanSelfHealGuard::handle_orphan_breakpoint(
    std::uint64_t exception_address,
    Int3Context* ctx) const noexcept {
    if (!active_.load(std::memory_order_acquire) && !code_restored_.load(std::memory_order_acquire)) {
        return false;
    }
    if (ctx == nullptr) {
        return false;
    }

    std::uint64_t site_start = 0;
    for (const auto& site : sites_) {
        if (site.address != 0 && site.length > 0 &&
            exception_address >= site.address &&
            exception_address < site.address + site.length) {
            site_start = site.address;
            break;
        }
    }
    if (site_start == 0) {
        return false;
    }

#ifdef _WIN32
    for (std::uint32_t i = 0; i < 5000 && !code_restored_.load(std::memory_order_acquire); ++i) {
        Sleep(1);
    }
#endif
    if (!code_restored_.load(std::memory_order_acquire)) {
        return false;
    }

    ctx->rip = site_start;
    return true;
}

} // namespace hookkit
