// Included by hook_transaction.cpp or standalone compilation units.
// Extracted transactional patch plan primitives.

#include "hookkit/patch_core.h"
#include <cstring>

namespace hookkit {

bool targets_are_disjoint(const PatchTargetDesc* targets, std::size_t count) noexcept {
    if (targets == nullptr && count > 0) {
        return false;
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto a_start = reinterpret_cast<std::uintptr_t>(targets[i].target);
        const auto a_size = targets[i].expected_patch_bytes ? targets[i].expected_patch_bytes : 14u;
        const auto a_end = a_start + a_size;
        if (a_start == 0 || a_end <= a_start) {
            return false;
        }
        for (std::size_t j = i + 1; j < count; ++j) {
            const auto b_start = reinterpret_cast<std::uintptr_t>(targets[j].target);
            const auto b_size = targets[j].expected_patch_bytes ? targets[j].expected_patch_bytes : 14u;
            const auto b_end = b_start + b_size;
            if (a_start < b_end && b_start < a_end) {
                return false;
            }
        }
    }
    return true;
}

void apply_plan_bytes(const PreparedPatchPlan& plan, std::size_t count) noexcept {
    const std::size_t limit = count <= plan.target_count ? count : plan.target_count;
    for (std::size_t i = 0; i < limit; ++i) {
        const PreparedPatchOp& op = plan.ops[i];
        if (op.write_addr != nullptr && op.write_size > 0 && op.write_size <= sizeof(op.after_bytes)) {
            std::memcpy(op.write_addr, op.after_bytes, op.write_size);
        }
    }
}

void rollback_plan_bytes(const PreparedPatchPlan& plan, std::size_t applied_count) noexcept {
    const std::size_t limit = applied_count <= plan.target_count ? applied_count : plan.target_count;
    for (std::size_t i = limit; i > 0; --i) {
        const PreparedPatchOp& op = plan.ops[i - 1];
        if (op.write_addr != nullptr && op.write_size > 0 && op.write_size <= sizeof(op.before_bytes)) {
            std::memcpy(op.write_addr, op.before_bytes, op.write_size);
        }
    }
}

bool verify_plan_before_bytes(const PreparedPatchPlan& plan, std::size_t* mismatch_index) noexcept {
    for (std::size_t i = 0; i < plan.target_count; ++i) {
        const PreparedPatchOp& op = plan.ops[i];
        if (op.write_addr == nullptr || op.write_size == 0 || op.write_size > sizeof(op.before_bytes)) {
            if (mismatch_index) *mismatch_index = i;
            return false;
        }
        if (std::memcmp(op.write_addr, op.before_bytes, op.write_size) != 0) {
            if (mismatch_index) *mismatch_index = i;
            return false;
        }
    }
    return true;
}

bool verify_plan_after_bytes(const PreparedPatchPlan& plan, std::size_t* mismatch_index) noexcept {
    for (std::size_t i = 0; i < plan.target_count; ++i) {
        const PreparedPatchOp& op = plan.ops[i];
        if (op.write_addr == nullptr || op.write_size == 0 || op.write_size > sizeof(op.after_bytes)) {
            if (mismatch_index) *mismatch_index = i;
            return false;
        }
        if (std::memcmp(op.write_addr, op.after_bytes, op.write_size) != 0) {
            if (mismatch_index) *mismatch_index = i;
            return false;
        }
    }
    return true;
}

void publish_trampolines(const PreparedPatchPlan& plan) noexcept {
    for (std::size_t i = 0; i < plan.target_count; ++i) {
        if (plan.ops[i].original_slot != nullptr) {
            *plan.ops[i].original_slot = plan.ops[i].trampoline;
        }
    }
}

void clear_trampolines(const PreparedPatchPlan& plan) noexcept {
    for (std::size_t i = 0; i < plan.target_count; ++i) {
        if (plan.ops[i].original_slot != nullptr) {
            *plan.ops[i].original_slot = nullptr;
        }
    }
}

void release_prepared_trampolines(PreparedPatchPlan* plan) noexcept {
    if (plan == nullptr) {
        return;
    }
    for (std::size_t i = 0; i < plan->target_count; ++i) {
        plan->ops[i].trampoline = nullptr;
    }
}

} // namespace hookkit
