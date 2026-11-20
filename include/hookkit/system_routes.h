#pragma once

#include <cstddef>
#include <cstdint>

namespace hookkit {

enum class RouteId : std::uint32_t {
    NtSuspendThread = 0,
    NtResumeThread = 1,
    NtGetContextThread = 2,
    NtQueryInformationThread = 3,
    NtProtectVirtualMemory = 4,
    NtFlushInstructionCache = 5,
    Count = 6,
};

struct RouteDescriptor {
    RouteId id;
    const char* name;
    std::uint32_t expected_rva;
    std::uint8_t expected_bytes[24];
};

struct RouteVerificationResult {
    bool ok;
    RouteId failed_route;
    std::uint32_t actual_rva;
    std::uint8_t actual_bytes[24];
};

struct BoundThreadEntry {
    std::uint32_t tid;
    void* handle;
    std::uint64_t create_time_100ns;
    bool alive;
};

struct SystemCallLedgerEntry {
    std::uint64_t seq;
    std::uint64_t qpc;
    RouteId route;
    std::uint32_t target_tid;
    std::int32_t ntstatus;
};

class SystemRoutes {
public:
    static constexpr std::size_t kLedgerCapacity = 8192;
    static constexpr std::size_t kMaxBoundThreads = 512;

    SystemRoutes() noexcept;

    RouteVerificationResult verify_and_bind(
        const void* ntdll_base,
        const RouteDescriptor* expected_routes,
        std::size_t route_count) noexcept;

    bool register_thread(std::uint32_t tid, void* handle, std::uint64_t create_time_100ns) noexcept;
    bool verify_thread_identity(std::uint32_t tid, std::uint64_t current_create_time_100ns) const noexcept;
    void mark_thread_dead(std::uint32_t tid) noexcept;

    void record_call(RouteId route, std::uint32_t target_tid, std::int32_t ntstatus, std::uint64_t qpc) noexcept;

    std::uint64_t total_calls() const noexcept { return write_seq_; }
    const SystemCallLedgerEntry* ledger() const noexcept { return ledger_; }
    std::size_t bound_thread_count() const noexcept { return bound_count_; }
    const BoundThreadEntry* bound_threads() const noexcept { return bound_threads_; }

private:
    const void* route_ptrs_[static_cast<std::size_t>(RouteId::Count)];
    BoundThreadEntry bound_threads_[kMaxBoundThreads];
    std::size_t bound_count_;
    SystemCallLedgerEntry ledger_[kLedgerCapacity];
    std::uint64_t write_seq_;
};

} // namespace hookkit
