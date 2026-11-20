#pragma once

#include <cstddef>
#include <cstdint>

namespace hookkit {

inline constexpr std::uint32_t kMaxTrampolineSites = 64;

enum class GprIndex : std::uint32_t {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    Rbp = 4,
    Rsi = 5,
    Rdi = 6,
    R8  = 7,
    R9  = 8,
    R10 = 9,
    R11 = 10,
    R12 = 11,
    R13 = 12,
    R14 = 13,
    R15 = 14,
};

struct CapturedRegisters {
    std::uint64_t xmm[16][2];
    std::uint64_t gpr[15];
    std::uint64_t rflags;
    std::uint64_t rsp;
    std::uint32_t mxcsr;
    std::uint32_t fpu_cw;
};

static_assert(sizeof(CapturedRegisters) == 0x190, "CapturedRegisters layout must be 0x190 bytes");
static_assert(offsetof(CapturedRegisters, xmm) == 0x000, "xmm offset mismatch");
static_assert(offsetof(CapturedRegisters, gpr) == 0x100, "gpr offset mismatch");
static_assert(offsetof(CapturedRegisters, rflags) == 0x178, "rflags offset mismatch");
static_assert(offsetof(CapturedRegisters, rsp) == 0x180, "rsp offset mismatch");
static_assert(offsetof(CapturedRegisters, mxcsr) == 0x188, "mxcsr offset mismatch");
static_assert(offsetof(CapturedRegisters, fpu_cw) == 0x18C, "fpu_cw offset mismatch");

using PairObserveFn = void (*)(std::uint32_t site_id, std::uint32_t is_exit, CapturedRegisters* regs);
using EntryObserveFn = void (*)(std::uint32_t site_id, CapturedRegisters* regs);

} // namespace hookkit

extern "C" {

extern void* hookkit_site_originals[hookkit::kMaxTrampolineSites];
extern hookkit::PairObserveFn hookkit_observe_pair;
extern hookkit::EntryObserveFn hookkit_observe_entry;

void HookkitPairSite0();
void HookkitPairSite1();
void HookkitPairSite2();
void HookkitPairSite3();
void HookkitPairSite4();
void HookkitPairSite5();
void HookkitPairSite6();
void HookkitPairSite7();

void HookkitEntrySite0();
void HookkitEntrySite1();
void HookkitEntrySite2();
void HookkitEntrySite3();
void HookkitEntrySite4();
void HookkitEntrySite5();
void HookkitEntrySite6();
void HookkitEntrySite7();

} // extern "C"

namespace hookkit {

inline bool register_site_original(std::uint32_t site_id, void* original_fn) noexcept {
    if (site_id >= kMaxTrampolineSites) {
        return false;
    }
    hookkit_site_originals[site_id] = original_fn;
    return true;
}

inline void* get_site_original(std::uint32_t site_id) noexcept {
    if (site_id >= kMaxTrampolineSites) {
        return nullptr;
    }
    return hookkit_site_originals[site_id];
}

inline void clear_site_originals() noexcept {
    for (std::uint32_t i = 0; i < kMaxTrampolineSites; ++i) {
        hookkit_site_originals[i] = nullptr;
    }
}

inline void set_pair_observer(PairObserveFn fn) noexcept {
    hookkit_observe_pair = fn;
}

inline void set_entry_observer(EntryObserveFn fn) noexcept {
    hookkit_observe_entry = fn;
}

inline void* pair_trampoline_address(std::uint32_t site_id) noexcept {
    switch (site_id) {
        case 0: return reinterpret_cast<void*>(&HookkitPairSite0);
        case 1: return reinterpret_cast<void*>(&HookkitPairSite1);
        case 2: return reinterpret_cast<void*>(&HookkitPairSite2);
        case 3: return reinterpret_cast<void*>(&HookkitPairSite3);
        case 4: return reinterpret_cast<void*>(&HookkitPairSite4);
        case 5: return reinterpret_cast<void*>(&HookkitPairSite5);
        case 6: return reinterpret_cast<void*>(&HookkitPairSite6);
        case 7: return reinterpret_cast<void*>(&HookkitPairSite7);
        default: return nullptr;
    }
}

inline void* entry_trampoline_address(std::uint32_t site_id) noexcept {
    switch (site_id) {
        case 0: return reinterpret_cast<void*>(&HookkitEntrySite0);
        case 1: return reinterpret_cast<void*>(&HookkitEntrySite1);
        case 2: return reinterpret_cast<void*>(&HookkitEntrySite2);
        case 3: return reinterpret_cast<void*>(&HookkitEntrySite3);
        case 4: return reinterpret_cast<void*>(&HookkitEntrySite4);
        case 5: return reinterpret_cast<void*>(&HookkitEntrySite5);
        case 6: return reinterpret_cast<void*>(&HookkitEntrySite6);
        case 7: return reinterpret_cast<void*>(&HookkitEntrySite7);
        default: return nullptr;
    }
}

} // namespace hookkit
