#include "hookkit/thread_admission.h"

namespace hookkit {

AdmissionReport admit_live_threads(
    SystemRoutes* routes,
    std::uint32_t self_tid,
    const LiveThreadInfo* live_snapshot,
    std::size_t live_count) noexcept {
    AdmissionReport report{};
    report.status = AdmissionStatus::Ok;
    report.retained_threads = 0;
    report.newly_admitted_threads = 0;
    report.exited_threads_marked_dead = 0;
    report.offending_tid = 0;

    if (routes == nullptr) {
        report.status = AdmissionStatus::RegistryCapacityExceeded;
        return report;
    }

    // Step 1: Check all previously registered threads against the current live snapshot.
    // Worker pool threads that exited cleanly between attach and detach are marked dead
    // instead of triggering a false ThreadChanged abort.
    const std::size_t bound_count = routes->bound_thread_count();
    const BoundThreadEntry* bound = routes->bound_threads();
    for (std::size_t i = 0; i < bound_count; ++i) {
        if (!bound[i].alive || bound[i].tid == self_tid) {
            continue;
        }
        bool still_live = false;
        std::uint64_t observed_create_time = 0;
        for (std::size_t j = 0; j < live_count; ++j) {
            if (live_snapshot[j].tid == bound[i].tid) {
                still_live = true;
                observed_create_time = live_snapshot[j].create_time_100ns;
                break;
            }
        }
        if (still_live) {
            if (observed_create_time != bound[i].create_time_100ns) {
                // TID was recycled by OS for a different thread!
                report.status = AdmissionStatus::IdentityMismatchOnLiveThread;
                report.offending_tid = bound[i].tid;
                return report;
            }
            ++report.retained_threads;
        } else {
            routes->mark_thread_dead(bound[i].tid);
            ++report.exited_threads_marked_dead;
        }
    }

    // Step 2: Admit any newly spawned threads into the bound registry.
    const std::size_t initial_bound_count = routes->bound_thread_count();
    for (std::size_t j = 0; j < live_count; ++j) {
        const LiveThreadInfo& info = live_snapshot[j];
        if (info.tid == self_tid) {
            continue;
        }
        bool already_bound = false;
        const BoundThreadEntry* current_bound = routes->bound_threads();
        const std::size_t current_count = routes->bound_thread_count();
        for (std::size_t i = 0; i < current_count; ++i) {
            if (current_bound[i].tid == info.tid && current_bound[i].alive) {
                already_bound = true;
                break;
            }
        }
        if (!already_bound) {
            if (!routes->register_thread(info.tid, info.opened_handle, info.create_time_100ns)) {
                // Roll back any threads registered earlier in this failed admission pass
                const BoundThreadEntry* after_bound = routes->bound_threads();
                for (std::size_t k = initial_bound_count; k < routes->bound_thread_count(); ++k) {
                    routes->mark_thread_dead(after_bound[k].tid);
                }
                report.newly_admitted_threads = 0;
                report.status = AdmissionStatus::RegistryCapacityExceeded;
                report.offending_tid = info.tid;
                return report;
            }
            ++report.newly_admitted_threads;
        }
    }

    return report;
}

bool verify_two_pass_census_equal(
    const LiveThreadInfo* pass_one,
    std::size_t count_one,
    const LiveThreadInfo* pass_two,
    std::size_t count_two) noexcept {
    if (count_one != count_two) {
        return false;
    }
    if (count_one == 0) {
        return true;
    }
    if (pass_one == nullptr || pass_two == nullptr) {
        return false;
    }
    for (std::size_t i = 0; i < count_one; ++i) {
        std::size_t matches_one = 0;
        std::size_t matches_two = 0;
        for (std::size_t j = 0; j < count_one; ++j) {
            if (pass_one[j].tid == pass_one[i].tid &&
                pass_one[j].create_time_100ns == pass_one[i].create_time_100ns) {
                ++matches_one;
            }
            if (pass_two[j].tid == pass_one[i].tid &&
                pass_two[j].create_time_100ns == pass_one[i].create_time_100ns) {
                ++matches_two;
            }
        }
        if (matches_one != matches_two) {
            return false;
        }
    }
    return true;
}

} // namespace hookkit
