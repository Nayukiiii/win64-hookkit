#pragma once

#include <cstddef>
#include <cstdint>

namespace hookkit {

struct PatchTargetDesc {
    const char* name;
    void* target;
    void* detour;
    void** original_slot;
    std::size_t expected_patch_bytes;
};

struct PreparedPatchOp {
    const char* name;
    std::uint8_t* write_addr;
    std::size_t write_size;
    std::uint8_t before_bytes[32];
    std::uint8_t after_bytes[32];
    void* trampoline;
    void** original_slot;
};

struct PreparedPatchPlan {
    std::size_t target_count;
    PreparedPatchOp ops[512];
};

enum class PatchPlanFailure : std::uint32_t {
    None = 0,
    InvalidArgument = 1,
    TooManyTargets = 2,
    TargetOverlap = 3,
    DetoursBeginFailed = 4,
    DetoursAttachFailed = 5,
    DetoursPrepareFailed = 6,
    NoPatchGenerated = 7,
    PatchTooLarge = 8,
    UnexpectedWriteAddress = 9,
    TrampolineMissing = 10,
    OriginalMismatch = 11,
};

struct PatchPlanResult {
    PatchPlanFailure failure;
    std::size_t failed_index;
    long detours_error;
};

bool targets_are_disjoint(const PatchTargetDesc* targets, std::size_t count) noexcept;

PatchPlanResult prepare_attach_plan(
    const PatchTargetDesc* targets,
    std::size_t count,
    PreparedPatchPlan* out_plan) noexcept;

PatchPlanResult prepare_detach_plan(
    const PatchTargetDesc* targets,
    std::size_t count,
    const PreparedPatchPlan& attach_plan,
    PreparedPatchPlan* out_plan) noexcept;

void apply_plan_bytes(const PreparedPatchPlan& plan, std::size_t count) noexcept;
void rollback_plan_bytes(const PreparedPatchPlan& plan, std::size_t applied_count) noexcept;
bool verify_plan_before_bytes(const PreparedPatchPlan& plan, std::size_t* mismatch_index) noexcept;
bool verify_plan_after_bytes(const PreparedPatchPlan& plan, std::size_t* mismatch_index) noexcept;

void publish_trampolines(const PreparedPatchPlan& plan) noexcept;
void clear_trampolines(const PreparedPatchPlan& plan) noexcept;
void release_prepared_trampolines(PreparedPatchPlan* plan) noexcept;

} // namespace hookkit
