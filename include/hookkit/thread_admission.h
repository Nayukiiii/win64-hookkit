#pragma once

#include "hookkit/system_routes.h"
#include <cstddef>
#include <cstdint>

namespace hookkit {

struct LiveThreadInfo {
    std::uint32_t tid;
    std::uint64_t create_time_100ns;
    void* opened_handle;
};

enum class AdmissionStatus : std::uint32_t {
    Ok = 0,
    IdentityMismatchOnLiveThread = 1,
    IdentityMismatchOnExitedThread = 2,
    RegistryCapacityExceeded = 3,
    TwoPassCensusChanged = 4,
};

struct AdmissionReport {
    AdmissionStatus status;
    std::size_t retained_threads;
    std::size_t newly_admitted_threads;
    std::size_t exited_threads_marked_dead;
    std::uint32_t offending_tid;
};

AdmissionReport admit_live_threads(
    SystemRoutes* routes,
    std::uint32_t self_tid,
    const LiveThreadInfo* live_snapshot,
    std::size_t live_count) noexcept;

// Order-independent equality check across two thread census passes: returns true
// iff both passes contain the exact same multiset of (tid, create_time_100ns) pairs.
bool verify_two_pass_census_equal(
    const LiveThreadInfo* pass_one,
    std::size_t count_one,
    const LiveThreadInfo* pass_two,
    std::size_t count_two) noexcept;

} // namespace hookkit
