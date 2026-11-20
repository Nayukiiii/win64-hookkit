#include "hookkit/patch_receipt.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#else
#include <chrono>
#endif

#include <cstring>

namespace hookkit {
namespace {

bool safe_read_bytes(void* dst, const void* src, std::size_t bytes) noexcept {
    if (dst == nullptr || src == nullptr || bytes == 0) {
        return false;
    }
#if defined(_MSC_VER) && defined(_WIN32)
    __try {
        const auto* s = static_cast<const volatile std::uint8_t*>(src);
        auto* d = static_cast<std::uint8_t*>(dst);
        for (std::size_t i = 0; i < bytes; ++i) {
            d[i] = s[i];
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    std::memcpy(dst, src, bytes);
    return true;
#endif
}

std::uint32_t query_protect(const void* addr) noexcept {
#ifdef _WIN32
    if (addr == nullptr) {
        return 0;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        return static_cast<std::uint32_t>(mbi.Protect);
    }
#else
    (void)addr;
#endif
    return 0;
}

std::uint64_t query_qpc_now() noexcept {
#ifdef _WIN32
    LARGE_INTEGER value{};
    QueryPerformanceCounter(&value);
    return static_cast<std::uint64_t>(value.QuadPart);
#else
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
#endif
}

std::uint64_t query_unix_ms_now() noexcept {
#ifdef _WIN32
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli{};
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Windows epoch (1601-01-01) to Unix epoch (1970-01-01) in 100ns ticks.
    constexpr std::uint64_t kEpochDiff100ns = 116444736000000000ULL;
    if (uli.QuadPart < kEpochDiff100ns) {
        return 0;
    }
    return (uli.QuadPart - kEpochDiff100ns) / 10000ULL;
#else
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
#endif
}

const char* phase_name(ReceiptPhase phase) noexcept {
    switch (phase) {
        case ReceiptPhase::PreInstall: return "pre_install";
        case ReceiptPhase::PostInstall: return "post_install";
        case ReceiptPhase::PreRemove: return "pre_remove";
        case ReceiptPhase::PostRemove: return "post_remove";
        default: return "unknown";
    }
}

void write_hex(std::FILE* f, const std::uint8_t* data, std::size_t size) noexcept {
    for (std::size_t i = 0; i < size; ++i) {
        std::fprintf(f, "%02X", static_cast<unsigned>(data[i]));
    }
}

void write_json_escaped(std::FILE* f, const char* s) noexcept {
    std::fputc('"', f);
    if (s != nullptr) {
        for (const char* p = s; *p != '\0'; ++p) {
            const unsigned char c = static_cast<unsigned char>(*p);
            if (c == '"' || c == '\\') {
                std::fputc('\\', f);
                std::fputc(c, f);
            } else if (c >= 0x20 && c < 0x7F) {
                std::fputc(c, f);
            }
        }
    }
    std::fputc('"', f);
}

std::uint32_t crc32_update(std::uint32_t crc, const void* data, std::size_t size) noexcept {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = (crc & 1u) ? 0xEDB88320u : 0u;
            crc = (crc >> 1) ^ mask;
        }
    }
    return crc;
}

std::uint32_t compute_receipt_crc(const PatchReceipt& r) noexcept {
    std::uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update(crc, &r.magic, sizeof(r.magic));
    const auto phase_val = static_cast<std::uint32_t>(r.phase);
    crc = crc32_update(crc, &phase_val, sizeof(phase_val));
    crc = crc32_update(crc, &r.target_count, sizeof(r.target_count));
    crc = crc32_update(crc, &r.timestamp_qpc, sizeof(r.timestamp_qpc));
    crc = crc32_update(crc, &r.timestamp_unix_ms, sizeof(r.timestamp_unix_ms));
    crc = crc32_update(crc, &r.transaction_reason, sizeof(r.transaction_reason));
    crc = crc32_update(crc, &r.rolled_back, sizeof(r.rolled_back));
    crc = crc32_update(crc, &r.cleanly_resumed, sizeof(r.cleanly_resumed));
    crc = crc32_update(crc, &r.reserved, sizeof(r.reserved));
    for (const auto& t : r.targets) {
        crc = crc32_update(crc, &t, sizeof(t));
    }
    return ~crc;
}

template <typename T>
bool write_pod(std::FILE* f, const T& v) noexcept {
    return std::fwrite(&v, sizeof(v), 1, f) == 1;
}

template <typename T>
bool read_pod(std::FILE* f, T* v) noexcept {
    return std::fread(v, sizeof(*v), 1, f) == 1;
}

} // namespace

std::uint32_t PatchWitness::crc32(const void* data, std::size_t size) noexcept {
    if (data == nullptr || size == 0) {
        return 0;
    }
    return ~crc32_update(0xFFFFFFFFu, data, size);
}

bool PatchWitness::capture_from_plan(
    ReceiptPhase phase,
    const PreparedPatchPlan& plan,
    const TransactionReport* report,
    PatchReceipt* out_receipt,
    bool read_live_memory,
    std::size_t trampoline_capture_size) noexcept {
    if (out_receipt == nullptr || plan.target_count > 512) {
        return false;
    }

    PatchReceipt receipt{};
    receipt.magic = kPatchReceiptMagic;
    receipt.phase = phase;
    receipt.target_count = static_cast<std::uint32_t>(plan.target_count);
    receipt.timestamp_qpc = query_qpc_now();
    receipt.timestamp_unix_ms = query_unix_ms_now();
    if (report != nullptr) {
        receipt.transaction_reason = static_cast<std::uint32_t>(report->reason);
        receipt.rolled_back = report->rolled_back ? 1u : 0u;
        receipt.cleanly_resumed = report->cleanly_resumed ? 1u : 0u;
    }

    const std::size_t clamped_tramp_size =
        trampoline_capture_size <= 96 ? trampoline_capture_size : 96;

    receipt.targets.resize(plan.target_count);
    for (std::size_t i = 0; i < plan.target_count; ++i) {
        const PreparedPatchOp& op = plan.ops[i];
        TargetPatchRecord& rec = receipt.targets[i];

        if (op.name != nullptr) {
            const std::size_t len = std::strlen(op.name);
            const std::size_t copy_len = len < sizeof(rec.name) - 1 ? len : sizeof(rec.name) - 1;
            std::memcpy(rec.name, op.name, copy_len);
            rec.name[copy_len] = '\0';
        }
        rec.target_address = reinterpret_cast<std::uint64_t>(op.write_addr);
        rec.trampoline_address = reinterpret_cast<std::uint64_t>(op.trampoline);
        rec.original_slot_address = reinterpret_cast<std::uint64_t>(op.original_slot);

        const std::size_t wsize = op.write_size <= 32 ? op.write_size : 32;
        rec.write_size = static_cast<std::uint32_t>(wsize);
        std::memcpy(rec.before_bytes, op.before_bytes, wsize);
        std::memcpy(rec.after_bytes, op.after_bytes, wsize);

        if (read_live_memory) {
            if (op.write_addr != nullptr && wsize > 0) {
                rec.target_readable = safe_read_bytes(rec.actual_bytes, op.write_addr, wsize) ? 1u : 0u;
                rec.actual_protect = query_protect(op.write_addr);
                if (rec.target_readable != 0u) {
                    rec.crc32_actual = crc32(rec.actual_bytes, wsize);
                }
            }
            if (op.original_slot != nullptr) {
                rec.slot_readable = safe_read_bytes(
                    &rec.slot_value_actual,
                    op.original_slot,
                    sizeof(rec.slot_value_actual)) ? 1u : 0u;
            }
            if (op.trampoline != nullptr && clamped_tramp_size > 0) {
                rec.trampoline_size = static_cast<std::uint32_t>(clamped_tramp_size);
                rec.trampoline_readable = safe_read_bytes(
                    rec.trampoline_bytes,
                    op.trampoline,
                    clamped_tramp_size) ? 1u : 0u;
            }
        }
    }

    finalize_crc(&receipt);
    *out_receipt = std::move(receipt);
    return true;
}

bool PatchWitness::capture_manual(
    ReceiptPhase phase,
    const TargetPatchRecord* records,
    std::size_t count,
    PatchReceipt* out_receipt) noexcept {
    if (out_receipt == nullptr || (count > 0 && records == nullptr) || count > 512) {
        return false;
    }

    PatchReceipt receipt{};
    receipt.magic = kPatchReceiptMagic;
    receipt.phase = phase;
    receipt.target_count = static_cast<std::uint32_t>(count);
    receipt.timestamp_qpc = query_qpc_now();
    receipt.timestamp_unix_ms = query_unix_ms_now();
    receipt.targets.assign(records, records + count);
    for (auto& t : receipt.targets) {
        if (t.write_size > 32) {
            t.write_size = 32;
        }
        if (t.trampoline_size > 96) {
            t.trampoline_size = 96;
        }
        if (t.target_readable != 0u && t.write_size > 0 && t.crc32_actual == 0) {
            t.crc32_actual = crc32(t.actual_bytes, t.write_size);
        }
    }
    finalize_crc(&receipt);
    *out_receipt = std::move(receipt);
    return true;
}

void PatchWitness::finalize_crc(PatchReceipt* receipt) noexcept {
    if (receipt == nullptr) {
        return;
    }
    receipt->magic = kPatchReceiptMagic;
    receipt->target_count = static_cast<std::uint32_t>(receipt->targets.size());
    receipt->receipt_crc32 = compute_receipt_crc(*receipt);
}

bool PatchWitness::verify_receipt_integrity(const PatchReceipt& receipt) noexcept {
    if (receipt.magic != kPatchReceiptMagic) {
        return false;
    }
    if (receipt.target_count != receipt.targets.size()) {
        return false;
    }
    return receipt.receipt_crc32 == compute_receipt_crc(receipt);
}

bool PatchWitness::serialize_hex_json(std::FILE* file, const PatchReceipt& receipt) noexcept {
    if (file == nullptr) {
        return false;
    }
    std::fprintf(
        file,
        "{\"magic\":\"0x%016llX\",\"phase\":\"%s\",\"target_count\":%u,"
        "\"timestamp_qpc\":%llu,\"timestamp_unix_ms\":%llu,"
        "\"transaction_reason\":%u,\"rolled_back\":%s,\"cleanly_resumed\":%s,"
        "\"receipt_crc32\":\"0x%08X\",\"targets\":[",
        static_cast<unsigned long long>(receipt.magic),
        phase_name(receipt.phase),
        receipt.target_count,
        static_cast<unsigned long long>(receipt.timestamp_qpc),
        static_cast<unsigned long long>(receipt.timestamp_unix_ms),
        receipt.transaction_reason,
        receipt.rolled_back ? "true" : "false",
        receipt.cleanly_resumed ? "true" : "false",
        receipt.receipt_crc32);

    for (std::size_t i = 0; i < receipt.targets.size(); ++i) {
        if (i > 0) {
            std::fputc(',', file);
        }
        const TargetPatchRecord& t = receipt.targets[i];
        const std::size_t wsize = t.write_size <= 32 ? t.write_size : 32;
        const std::size_t tsize = t.trampoline_size <= 96 ? t.trampoline_size : 96;

        std::fprintf(file, "{\"name\":");
        write_json_escaped(file, t.name);
        std::fprintf(
            file,
            ",\"target_address\":\"0x%016llX\",\"trampoline_address\":\"0x%016llX\","
            "\"original_slot_address\":\"0x%016llX\",\"slot_value_actual\":\"0x%016llX\","
            "\"write_size\":%u,\"trampoline_size\":%u,\"actual_protect\":%u,"
            "\"target_readable\":%s,\"slot_readable\":%s,\"trampoline_readable\":%s,"
            "\"crc32_actual\":\"0x%08X\",\"before\":\"",
            static_cast<unsigned long long>(t.target_address),
            static_cast<unsigned long long>(t.trampoline_address),
            static_cast<unsigned long long>(t.original_slot_address),
            static_cast<unsigned long long>(t.slot_value_actual),
            t.write_size,
            t.trampoline_size,
            t.actual_protect,
            t.target_readable ? "true" : "false",
            t.slot_readable ? "true" : "false",
            t.trampoline_readable ? "true" : "false",
            t.crc32_actual);
        write_hex(file, t.before_bytes, wsize);
        std::fprintf(file, "\",\"after\":\"");
        write_hex(file, t.after_bytes, wsize);
        std::fprintf(file, "\",\"actual\":\"");
        if (t.target_readable) {
            write_hex(file, t.actual_bytes, wsize);
        }
        std::fprintf(file, "\",\"trampoline_hex\":\"");
        if (t.trampoline_readable && tsize > 0) {
            write_hex(file, t.trampoline_bytes, tsize);
        }
        std::fprintf(file, "\"}");
    }

    return std::fprintf(file, "]}") > 0;
}

bool PatchWitness::serialize_pair_json(
    std::FILE* file,
    const PatchReceipt& install_receipt,
    const PatchReceipt& remove_receipt) noexcept {
    if (file == nullptr) {
        return false;
    }
    if (std::fprintf(file, "{\"install\":") <= 0) {
        return false;
    }
    if (!serialize_hex_json(file, install_receipt)) {
        return false;
    }
    if (std::fprintf(file, ",\"remove\":") <= 0) {
        return false;
    }
    if (!serialize_hex_json(file, remove_receipt)) {
        return false;
    }
    return std::fprintf(file, "}\n") > 0;
}

bool PatchWitness::serialize_binary(std::FILE* file, const PatchReceipt& receipt) noexcept {
    if (file == nullptr) {
        return false;
    }
    const std::uint32_t count = static_cast<std::uint32_t>(receipt.targets.size());
    const std::uint32_t phase_val = static_cast<std::uint32_t>(receipt.phase);
    const std::uint32_t crc = compute_receipt_crc(receipt);

    if (!write_pod(file, receipt.magic) ||
        !write_pod(file, phase_val) ||
        !write_pod(file, count) ||
        !write_pod(file, receipt.timestamp_qpc) ||
        !write_pod(file, receipt.timestamp_unix_ms) ||
        !write_pod(file, receipt.transaction_reason) ||
        !write_pod(file, receipt.rolled_back) ||
        !write_pod(file, receipt.cleanly_resumed) ||
        !write_pod(file, receipt.reserved) ||
        !write_pod(file, crc)) {
        return false;
    }

    for (const auto& t : receipt.targets) {
        if (!write_pod(file, t)) {
            return false;
        }
    }
    return true;
}

bool PatchWitness::deserialize_binary(std::FILE* file, PatchReceipt* out_receipt) noexcept {
    if (file == nullptr || out_receipt == nullptr) {
        return false;
    }

    PatchReceipt r{};
    std::uint32_t phase_val = 0;
    if (!read_pod(file, &r.magic) ||
        !read_pod(file, &phase_val) ||
        !read_pod(file, &r.target_count) ||
        !read_pod(file, &r.timestamp_qpc) ||
        !read_pod(file, &r.timestamp_unix_ms) ||
        !read_pod(file, &r.transaction_reason) ||
        !read_pod(file, &r.rolled_back) ||
        !read_pod(file, &r.cleanly_resumed) ||
        !read_pod(file, &r.reserved) ||
        !read_pod(file, &r.receipt_crc32)) {
        return false;
    }

    if (r.magic != kPatchReceiptMagic || r.target_count > 512) {
        return false;
    }
    r.phase = static_cast<ReceiptPhase>(phase_val);
    r.targets.resize(r.target_count);
    for (std::uint32_t i = 0; i < r.target_count; ++i) {
        if (!read_pod(file, &r.targets[i])) {
            return false;
        }
    }
    if (!verify_receipt_integrity(r)) {
        return false;
    }

    *out_receipt = std::move(r);
    return true;
}

namespace {

std::FILE* open_write_binary(const char* path) noexcept {
    if (path == nullptr) {
        return nullptr;
    }
#ifdef _MSC_VER
    std::FILE* f = nullptr;
    if (fopen_s(&f, path, "wb") != 0) {
        return nullptr;
    }
    return f;
#else
    return std::fopen(path, "wb");
#endif
}

} // namespace

bool PatchWitness::write_json_to_path(const char* path, const PatchReceipt& receipt) noexcept {
    std::FILE* f = open_write_binary(path);
    if (f == nullptr) {
        return false;
    }
    const bool ok = serialize_hex_json(f, receipt);
    std::fclose(f);
    return ok;
}

bool PatchWitness::write_binary_to_path(const char* path, const PatchReceipt& receipt) noexcept {
    std::FILE* f = open_write_binary(path);
    if (f == nullptr) {
        return false;
    }
    const bool ok = serialize_binary(f, receipt);
    std::fclose(f);
    return ok;
}

} // namespace hookkit
