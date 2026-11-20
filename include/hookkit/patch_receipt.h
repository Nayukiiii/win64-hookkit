#pragma once

#include "hookkit/hook_transaction.h"
#include "hookkit/patch_core.h"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace hookkit {

inline constexpr std::uint64_t kPatchReceiptMagic = 0x3130525F54494B48ULL; // "HKIT_R01"

enum class ReceiptPhase : std::uint32_t {
    PreInstall = 0,
    PostInstall = 1,
    PreRemove = 2,
    PostRemove = 3,
};

struct TargetPatchRecord {
    char name[64]{};
    std::uint64_t target_address{};
    std::uint64_t trampoline_address{};
    std::uint64_t original_slot_address{};
    std::uint64_t slot_value_actual{};
    std::uint32_t write_size{};
    std::uint32_t trampoline_size{};
    std::uint32_t actual_protect{};
    std::uint8_t before_bytes[32]{};
    std::uint8_t after_bytes[32]{};
    std::uint8_t actual_bytes[32]{};
    std::uint8_t trampoline_bytes[96]{};
    std::uint8_t target_readable{};
    std::uint8_t slot_readable{};
    std::uint8_t trampoline_readable{};
    std::uint8_t reserved{};
    std::uint32_t crc32_actual{};
};

struct PatchReceipt {
    std::uint64_t magic{kPatchReceiptMagic};
    ReceiptPhase phase{ReceiptPhase::PreInstall};
    std::uint32_t target_count{};
    std::uint64_t timestamp_qpc{};
    std::uint64_t timestamp_unix_ms{};
    std::uint32_t transaction_reason{};
    std::uint8_t rolled_back{};
    std::uint8_t cleanly_resumed{};
    std::uint16_t reserved{};
    std::uint32_t receipt_crc32{};
    std::vector<TargetPatchRecord> targets{};
};

class PatchWitness {
public:
    static std::uint32_t crc32(const void* data, std::size_t size) noexcept;

    static bool capture_from_plan(
        ReceiptPhase phase,
        const PreparedPatchPlan& plan,
        const TransactionReport* report,
        PatchReceipt* out_receipt,
        bool read_live_memory = true,
        std::size_t trampoline_capture_size = 96) noexcept;

    static bool capture_manual(
        ReceiptPhase phase,
        const TargetPatchRecord* records,
        std::size_t count,
        PatchReceipt* out_receipt) noexcept;

    static void finalize_crc(PatchReceipt* receipt) noexcept;
    static bool verify_receipt_integrity(const PatchReceipt& receipt) noexcept;

    static bool serialize_hex_json(std::FILE* file, const PatchReceipt& receipt) noexcept;
    static bool serialize_pair_json(
        std::FILE* file,
        const PatchReceipt& install_receipt,
        const PatchReceipt& remove_receipt) noexcept;

    static bool serialize_binary(std::FILE* file, const PatchReceipt& receipt) noexcept;
    static bool deserialize_binary(std::FILE* file, PatchReceipt* out_receipt) noexcept;

    static bool write_json_to_path(const char* path, const PatchReceipt& receipt) noexcept;
    static bool write_binary_to_path(const char* path, const PatchReceipt& receipt) noexcept;
};

} // namespace hookkit
