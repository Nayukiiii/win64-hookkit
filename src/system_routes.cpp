#include "hookkit/system_routes.h"
#include <cstring>

namespace hookkit {

SystemRoutes::SystemRoutes() noexcept
    : route_ptrs_{},
      bound_threads_{},
      bound_count_(0),
      ledger_{},
      write_seq_(0) {}

RouteVerificationResult SystemRoutes::verify_and_bind(
    const void* ntdll_base,
    const RouteDescriptor* expected_routes,
    std::size_t route_count) noexcept {
    RouteVerificationResult result{};
    result.ok = false;
    result.failed_route = RouteId::Count;
    result.actual_rva = 0;

    if (ntdll_base == nullptr || expected_routes == nullptr ||
        route_count != static_cast<std::size_t>(RouteId::Count)) {
        return result;
    }

    const auto* base_bytes = static_cast<const std::uint8_t*>(ntdll_base);
    for (std::size_t i = 0; i < route_count; ++i) {
        const RouteDescriptor& desc = expected_routes[i];
        const auto idx = static_cast<std::size_t>(desc.id);
        if (idx >= static_cast<std::size_t>(RouteId::Count)) {
            result.failed_route = desc.id;
            return result;
        }
        const std::uint8_t* fn_ptr = base_bytes + desc.expected_rva;
        if (std::memcmp(fn_ptr, desc.expected_bytes, sizeof(desc.expected_bytes)) != 0) {
            result.failed_route = desc.id;
            result.actual_rva = desc.expected_rva;
            std::memcpy(result.actual_bytes, fn_ptr, sizeof(result.actual_bytes));
            return result;
        }
        route_ptrs_[idx] = fn_ptr;
    }

    result.ok = true;
    return result;
}

bool SystemRoutes::register_thread(
    std::uint32_t tid,
    void* handle,
    std::uint64_t create_time_100ns) noexcept {
    if (tid == 0 || handle == nullptr) {
        return false;
    }
    for (std::size_t i = 0; i < bound_count_; ++i) {
        if (bound_threads_[i].tid == tid) {
            if (bound_threads_[i].create_time_100ns != create_time_100ns) {
                return false;
            }
            bound_threads_[i].handle = handle;
            bound_threads_[i].alive = true;
            return true;
        }
    }
    if (bound_count_ >= kMaxBoundThreads) {
        return false;
    }
    bound_threads_[bound_count_++] = BoundThreadEntry{
        tid,
        handle,
        create_time_100ns,
        true,
    };
    return true;
}

bool SystemRoutes::verify_thread_identity(
    std::uint32_t tid,
    std::uint64_t current_create_time_100ns) const noexcept {
    for (std::size_t i = 0; i < bound_count_; ++i) {
        if (bound_threads_[i].tid == tid) {
            return bound_threads_[i].create_time_100ns == current_create_time_100ns;
        }
    }
    return false;
}

void SystemRoutes::mark_thread_dead(std::uint32_t tid) noexcept {
    for (std::size_t i = 0; i < bound_count_; ++i) {
        if (bound_threads_[i].tid == tid) {
            bound_threads_[i].alive = false;
            return;
        }
    }
}

void SystemRoutes::record_call(
    RouteId route,
    std::uint32_t target_tid,
    std::int32_t ntstatus,
    std::uint64_t qpc) noexcept {
    const std::uint64_t seq = ++write_seq_;
    const std::size_t slot = static_cast<std::size_t>((seq - 1) % kLedgerCapacity);
    ledger_[slot] = SystemCallLedgerEntry{
        seq,
        qpc,
        route,
        target_tid,
        ntstatus,
    };
}

} // namespace hookkit
