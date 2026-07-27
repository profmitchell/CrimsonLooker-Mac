#include "axiom_force_service.h"
#include "axiom_force_runtime.h"
#include "axiom_patch.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace {

using cdumm::axiom_force::Config;
using cdumm::axiom_force::MaskedFingerprint;
using cdumm::axiom_force::Signature;

constexpr int kStartupDelaySeconds = 15;
constexpr int kResolveAttempts = 30;
constexpr int kResolveRetrySeconds = 2;
constexpr float kFloatTolerance = 0.001f;

// Statically resolved RemoteCatch (Axiom Force) pull-range gate.
//
// pa::ClientRemoteCatchActorComponent's pull check reduces the player-to-target
// delta to its largest component and compares it against this global:
//
//   1003c0224  bl   0x100b5c108          ; fetch target + self position
//   1003c0248  mov  s2, v0[1]            ; reduce delta to max component
//   1003c025c  adrp x8, 0x108819000
//   1003c0260  ldr  s1, [x8, #0x62c]     ; <- kKnownRangeUnslid
//   1003c0264  fcmp s0, s1
//   1003c0268  b.gt 0x1003c0298          ; out of range -> cannot pull
//
// It lives in __DATA,__common, so there is nothing to scan for: the runtime
// address is just the unslid address plus the image slide. #0x62c is loaded
// from this page at exactly one site in the binary, so there is no ambiguity.
// Gated on the build UUID because the offset is build-specific.
constexpr const char *kKnownBuildUuid = "6f86f0e5-6cc6-3bed-b434-d1ef27f9a72e";
// Confirmed by scanning __DATA for the 20.0/40.0 pair the Windows ASI validates
// against, then checking the write preimage read back as exactly 20.0. See
// docs/PORTING.md. An earlier revision pointed range at 0x10881962c, which is a
// tolerance in one catch-type branch and produced no gameplay change.
constexpr uint64_t kKnownRangeUnslid = 0x10881926cull;
constexpr uint64_t kKnownPullUnslid = 0x108819decull;

// Every global read by code in the RemoteCatch cluster (0x1003b0000-0x1003c1000),
// recovered by pairing adrp with its dependent ldr in a full disassembly. These
// all live in BSS, so their values only exist at runtime; dumping them once after
// resolve is how we tell a reach/distance from a tolerance or a lerp weight.
constexpr uint64_t kRemoteCatchGlobals[] = {
    0x10861e1f8ull, 0x108805008ull, 0x108805034ull, 0x108819088ull, 0x108819094ull,
    0x1088193fcull, 0x10881962cull, 0x10881967cull, 0x108819b6cull, 0x108819cacull,
    0x108819d9cull, 0x108819decull, 0x108819f24ull, 0x108819fc4ull, 0x10881a000ull,
    0x10881a008ull, 0x10881a014ull, 0x10881a064ull, 0x10881a154ull, 0x10881a17cull,
    0x10881a4f4ull, 0x10881a684ull, 0x10881a77cull, 0x10881a7ccull, 0x10881a86cull,
    0x10881a8bcull, 0x10881a90cull, 0x10881a95cull, 0x10881acccull, 0x10881b000ull,
    0x10881b008ull, 0x10881b020ull, 0x10881b070ull, 0x10881b2fcull, 0x10881b34cull,
    0x10881b39cull, 0x10881b3ecull, 0x10881b48cull, 0x10881b52cull, 0x10881b7acull,
    0x10881b7fcull, 0x10881bae4ull, 0x10881bb34ull, 0x10881bb84ull, 0x10881bd0cull,
    0x10881bd5cull, 0x10881bdacull, 0x10881bdfcull, 0x108849000ull, 0x10888d000ull,
    0x10888d004ull, 0x10888d008ull, 0x10888d00cull, 0x10888da68ull,
};

struct Range {
    uint64_t start = 0;
    uint64_t end = 0;
    uint64_t unslid_start = 0;
    uint64_t file_offset = 0;
    uint64_t file_size = 0;
    std::string segment;
    std::string section;
};

struct GameImage {
    const mach_header_64 *header = nullptr;
    intptr_t slide = 0;
    std::string path;
    std::string uuid;
    uint64_t file_size = 0;
    std::vector<Range> text;
    std::vector<Range> data;
};

struct Addresses {
    uint64_t limit = 0;
    uint64_t range = 0;
    uint64_t pull = 0;
    std::string source;
    size_t limit_xrefs = 0;
    size_t range_xrefs = 0;
    size_t pull_xrefs = 0;
    // Set when only the pull-range gate is known. The limit and pull-speed
    // globals have no confirmed address yet, so they are left untouched
    // rather than guessed at.
    bool range_only = false;
    // Range and pull are confirmed; the third "limit" value never was, so the
    // known-address path writes the pair and leaves it alone.
    bool known_pair = false;
};

struct Originals {
    bool captured = false;
    float limit = 0.0f;
    float range = 0.0f;
    float pull = 0.0f;
};

struct RegionProtection {
    vm_prot_t protection = VM_PROT_NONE;
    mach_vm_address_t region_start = 0;
    mach_vm_size_t region_size = 0;
};

void service_log(const char *fmt, ...) {
    const char *configured = getenv("CRIMSONLOOKER_LOG_PATH");
    const char *path = configured != nullptr && configured[0] == '/'
        ? configured : "/tmp/CrimsonLooker.log";
    char message[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(message, sizeof(message), fmt, ap);
    va_end(ap);
    if (FILE *file = fopen(path, "a")) {
        fprintf(file, "axiom: [AxiomForce] %s\n", message);
        fclose(file);
    }
}

std::string canonical_path(const char *path) {
    if (path == nullptr || path[0] == '\0') return {};
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != nullptr) return resolved;
    return path;
}

std::string executable_path() {
    uint32_t size = PATH_MAX;
    char buffer[PATH_MAX];
    if (_NSGetExecutablePath(buffer, &size) != 0) return {};
    return canonical_path(buffer);
}

std::string uuid_string(const uuid_command *uuid) {
    char value[37];
    snprintf(value, sizeof(value),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid->uuid[0], uuid->uuid[1], uuid->uuid[2], uuid->uuid[3],
        uuid->uuid[4], uuid->uuid[5], uuid->uuid[6], uuid->uuid[7],
        uuid->uuid[8], uuid->uuid[9], uuid->uuid[10], uuid->uuid[11],
        uuid->uuid[12], uuid->uuid[13], uuid->uuid[14], uuid->uuid[15]);
    return value;
}

std::string fixed_name(const char *value, size_t size) {
    return std::string(value, strnlen(value, size));
}

bool find_game_image(GameImage *out) {
    if (out == nullptr) return false;
    const std::string main_path = executable_path();
    if (main_path.empty()) return false;
    GameImage image;
    for (uint32_t index = 0; index < _dyld_image_count(); ++index) {
        const char *name = _dyld_get_image_name(index);
        const mach_header *header = _dyld_get_image_header(index);
        if (name == nullptr || header == nullptr || canonical_path(name) != main_path) continue;
        if (header->magic != MH_MAGIC_64) return false;
        image.header = reinterpret_cast<const mach_header_64 *>(header);
        image.slide = _dyld_get_image_vmaddr_slide(index);
        image.path = main_path;
        break;
    }
    if (image.header == nullptr) return false;

    struct stat st{};
    if (stat(image.path.c_str(), &st) != 0 || st.st_size <= 0) return false;
    image.file_size = static_cast<uint64_t>(st.st_size);

    const uint8_t *commands = reinterpret_cast<const uint8_t *>(image.header) + sizeof(mach_header_64);
    const uint8_t *cursor = commands;
    const uint8_t *commands_end = commands + image.header->sizeofcmds;
    for (uint32_t index = 0; index < image.header->ncmds; ++index) {
        if (cursor + sizeof(load_command) > commands_end) return false;
        const auto *command = reinterpret_cast<const load_command *>(cursor);
        if (command->cmdsize < sizeof(load_command) || cursor + command->cmdsize > commands_end) return false;
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(uuid_command)) {
            image.uuid = uuid_string(reinterpret_cast<const uuid_command *>(command));
        } else if (command->cmd == LC_SEGMENT_64 && command->cmdsize >= sizeof(segment_command_64)) {
            const auto *segment = reinterpret_cast<const segment_command_64 *>(command);
            const std::string segment_name = fixed_name(segment->segname, sizeof(segment->segname));
            const auto *sections = reinterpret_cast<const section_64 *>(segment + 1);
            const uint64_t section_bytes = static_cast<uint64_t>(segment->nsects) * sizeof(section_64);
            if (reinterpret_cast<const uint8_t *>(sections) + section_bytes > cursor + command->cmdsize) return false;
            for (uint32_t section_index = 0; section_index < segment->nsects; ++section_index) {
                const section_64 &section = sections[section_index];
                Range range;
                range.start = section.addr + image.slide;
                range.end = range.start + section.size;
                range.unslid_start = section.addr;
                range.file_offset = section.offset;
                range.file_size = (section.offset < segment->fileoff + segment->filesize)
                    ? std::min<uint64_t>(section.size, segment->fileoff + segment->filesize - section.offset)
                    : 0;
                range.segment = fixed_name(section.segname, sizeof(section.segname));
                range.section = fixed_name(section.sectname, sizeof(section.sectname));
                if (segment_name == "__TEXT" && range.section == "__text") image.text.push_back(range);
                if (segment_name == "__DATA" || segment_name == "__DATA_CONST") image.data.push_back(range);
            }
        }
        cursor += command->cmdsize;
    }
    if (image.uuid.empty() || image.text.empty() || image.data.empty()) return false;
    *out = std::move(image);
    return true;
}

bool contains(const Range &range, uint64_t address, size_t size = 1) {
    if (address < range.start || size > range.end - range.start) return false;
    return address <= range.end - size;
}

bool in_ranges(const std::vector<Range> &ranges, uint64_t address, size_t size = 1) {
    for (const Range &range : ranges) {
        if (contains(range, address, size)) return true;
    }
    return false;
}

bool read_float(uint64_t address, const std::vector<Range> &ranges, float *out) {
    if (out == nullptr || !in_ranges(ranges, address, sizeof(float))) return false;
    memcpy(out, reinterpret_cast<const void *>(address), sizeof(float));
    return std::isfinite(*out);
}

bool near(float lhs, float rhs) {
    return std::isfinite(lhs) && std::isfinite(rhs) && fabsf(lhs - rhs) <= kFloatTolerance;
}

int64_t sign_extend(uint64_t value, unsigned bits) {
    const uint64_t sign = uint64_t{1} << (bits - 1);
    return static_cast<int64_t>((value ^ sign) - sign);
}

bool decode_add_immediate(uint32_t instruction, int *rd, int *rn, uint64_t *immediate) {
    if ((instruction & 0x7f000000u) != 0x11000000u) return false;
    if (rd) *rd = static_cast<int>(instruction & 31u);
    if (rn) *rn = static_cast<int>((instruction >> 5) & 31u);
    const uint64_t value = (instruction >> 10) & 0xfffu;
    if (immediate) *immediate = value << (((instruction >> 22) & 1u) ? 12 : 0);
    return true;
}

bool decode_unsigned_load(uint32_t instruction, int *rn, uint64_t *immediate) {
    struct Pattern { uint32_t mask; uint32_t value; uint32_t scale; };
    static constexpr Pattern patterns[] = {
        {0xffc00000u, 0xbd400000u, 4},
        {0xffc00000u, 0xfd400000u, 8},
        {0xffc00000u, 0x3dc00000u, 16},
        {0xffc00000u, 0xb9400000u, 4},
        {0xffc00000u, 0xf9400000u, 8},
    };
    for (const Pattern &pattern : patterns) {
        if ((instruction & pattern.mask) != pattern.value) continue;
        if (rn) *rn = static_cast<int>((instruction >> 5) & 31u);
        if (immediate) *immediate = ((instruction >> 10) & 0xfffu) * pattern.scale;
        return true;
    }
    return false;
}

std::set<uint64_t> find_xrefs(const GameImage &image, uint64_t target) {
    std::set<uint64_t> references;
    for (const Range &range : image.text) {
        const uint64_t aligned_start = (range.start + 3u) & ~uint64_t{3};
        for (uint64_t pc = aligned_start; pc + sizeof(uint32_t) <= range.end; pc += 4) {
            uint32_t instruction = 0;
            memcpy(&instruction, reinterpret_cast<const void *>(pc), sizeof(instruction));

            if ((instruction & 0xff000000u) == 0x1c000000u ||
                (instruction & 0xff000000u) == 0x18000000u) {
                const int64_t offset = sign_extend((instruction >> 5) & 0x7ffffu, 19) << 2;
                if (static_cast<uint64_t>(static_cast<int64_t>(pc) + offset) == target) references.insert(pc);
            }

            if ((instruction & 0x9f000000u) != 0x90000000u) continue;
            const int rd = static_cast<int>(instruction & 31u);
            const uint64_t raw = (((instruction >> 5) & 0x7ffffu) << 2) | ((instruction >> 29) & 3u);
            const int64_t pages = sign_extend(raw, 21);
            std::array<bool, 32> known{};
            std::array<uint64_t, 32> values{};
            known[rd] = true;
            values[rd] = static_cast<uint64_t>(static_cast<int64_t>(pc & ~uint64_t{0xfff}) + (pages << 12));
            for (unsigned lookahead = 1; lookahead <= 8 && pc + lookahead * 4 + 4 <= range.end; ++lookahead) {
                uint32_t next = 0;
                memcpy(&next, reinterpret_cast<const void *>(pc + lookahead * 4), sizeof(next));
                int next_rd = static_cast<int>(next & 31u);
                int rn = 0;
                uint64_t immediate = 0;
                if (decode_add_immediate(next, &next_rd, &rn, &immediate) && known[rn]) {
                    values[next_rd] = values[rn] + immediate;
                    known[next_rd] = true;
                    if (values[next_rd] == target) references.insert(pc + lookahead * 4);
                    continue;
                }
                if (decode_unsigned_load(next, &rn, &immediate) && known[rn]) {
                    if (values[rn] + immediate == target) references.insert(pc + lookahead * 4);
                }
                if (next_rd != 31 && next_rd != rd) known[next_rd] = false;
            }
        }
    }
    return references;
}

bool file_offset_for(const GameImage &image, uint64_t runtime_address, uint64_t *out) {
    for (const Range &range : image.data) {
        if (!contains(range, runtime_address, sizeof(float))) continue;
        const uint64_t delta = runtime_address - range.start;
        if (delta + sizeof(float) > range.file_size) return false;
        if (out) *out = range.file_offset + delta;
        return true;
    }
    return false;
}

bool blacklisted(const GameImage &image, uint64_t runtime_address) {
    static constexpr uint64_t offsets[] = {0x4baff80, 0x4baff88, 0x4d14870, 0x4d1488c};
    uint64_t file_offset = 0;
    if (!file_offset_for(image, runtime_address, &file_offset)) return false;
    return std::find(std::begin(offsets), std::end(offsets), file_offset) != std::end(offsets);
}

std::vector<uint8_t> decode_hex(const std::string &hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t index = 0; index + 1 < hex.size(); index += 2) {
        char encoded[3] = {hex[index], hex[index + 1], '\0'};
        char *end = nullptr;
        const unsigned long value = strtoul(encoded, &end, 16);
        if (end != encoded + 2) return {};
        bytes.push_back(static_cast<uint8_t>(value));
    }
    return bytes;
}

bool fingerprint_matches(uint64_t field, const MaskedFingerprint &fingerprint,
                         const std::vector<Range> &ranges) {
    const std::vector<uint8_t> expected = decode_hex(fingerprint.bytes_hex);
    const std::vector<uint8_t> mask = decode_hex(fingerprint.mask_hex);
    if (expected.empty() || expected.size() != mask.size()) return false;
    const int64_t signed_start = static_cast<int64_t>(field) + fingerprint.start_delta;
    if (signed_start <= 0) return false;
    const uint64_t start = static_cast<uint64_t>(signed_start);
    if (!in_ranges(ranges, start, expected.size())) return false;
    const auto *current = reinterpret_cast<const uint8_t *>(start);
    for (size_t index = 0; index < expected.size(); ++index) {
        if ((current[index] & mask[index]) != (expected[index] & mask[index])) return false;
    }
    return true;
}

std::string directory_of(const std::string &path) {
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? std::string{} : path.substr(0, slash);
}

std::string config_path() {
    const char *explicit_path = getenv("CRIMSONLOOKER_AXIOM_CONFIG_PATH");
    if (explicit_path != nullptr && explicit_path[0] != '\0') return explicit_path;
    const char *log_path = getenv("CRIMSONLOOKER_LOG_PATH");
    if (log_path != nullptr && log_path[0] == '/') {
        return directory_of(log_path) + "/CrimsonLooker.AxiomForce.json";
    }
    const char *user_home = getenv("HOME");
    if (user_home != nullptr && user_home[0] != '\0') {
        return std::string(user_home) + "/Library/Application Support/CDUMM/CrimsonLooker.AxiomForce.json";
    }
    return "/tmp/CrimsonLooker.AxiomForce.json";
}

std::string signature_path(const std::string &config) {
    const char *explicit_path = getenv("CRIMSONLOOKER_AXIOM_SIGNATURE_PATH");
    if (explicit_path != nullptr && explicit_path[0] != '\0') return explicit_path;
    return directory_of(config) + "/CrimsonLooker.AxiomForce.signature.json";
}

bool resolve_signature(const GameImage &image, const Config &config, const Signature &signature,
                       Addresses *out, std::string *failure) {
    std::string current_uuid = image.uuid;
    std::string signature_uuid = signature.build_uuid;
    std::transform(current_uuid.begin(), current_uuid.end(), current_uuid.begin(), ::tolower);
    std::transform(signature_uuid.begin(), signature_uuid.end(), signature_uuid.begin(), ::tolower);
    if (!signature.valid || signature_uuid != current_uuid || signature.mach_o_size != image.file_size) {
        if (failure) *failure = "build fingerprint mismatch";
        return false;
    }
    Addresses addresses;
    addresses.range = signature.range_unslid_vmaddr + image.slide;
    addresses.limit = signature.limit_unslid_vmaddr + image.slide;
    addresses.pull = signature.pull_unslid_vmaddr + image.slide;
    addresses.source = "known-signature";
    if (!in_ranges(image.data, addresses.range, sizeof(float)) ||
        !in_ranges(image.data, addresses.limit, sizeof(float)) ||
        !in_ranges(image.data, addresses.pull, sizeof(float)) ||
        blacklisted(image, addresses.range) || blacklisted(image, addresses.limit) || blacklisted(image, addresses.pull)) {
        if (failure) *failure = "signature address outside mapped game data or blacklisted";
        return false;
    }
    float current_range = 0.0f;
    float current_limit = 0.0f;
    float current_pull = 0.0f;
    if (!read_float(addresses.range, image.data, &current_range) ||
        !read_float(addresses.limit, image.data, &current_limit) ||
        !read_float(addresses.pull, image.data, &current_pull) ||
        (!near(current_range, signature.original_range) && !near(current_range, config.range)) ||
        (!near(current_limit, signature.original_limit) && !near(current_limit, config.range)) ||
        (!near(current_pull, signature.original_pull) && !near(current_pull, config.pull_speed)) ||
        !fingerprint_matches(addresses.range, signature.range_fingerprint, image.data) ||
        !fingerprint_matches(addresses.limit, signature.limit_fingerprint, image.data) ||
        !fingerprint_matches(addresses.pull, signature.pull_fingerprint, image.data)) {
        if (failure) *failure = "signature preimage or masked fingerprint mismatch";
        return false;
    }
    addresses.range_xrefs = find_xrefs(image, addresses.range).size();
    addresses.limit_xrefs = find_xrefs(image, addresses.limit).size();
    addresses.pull_xrefs = find_xrefs(image, addresses.pull).size();
    if (addresses.range_xrefs == 0 || addresses.limit_xrefs == 0 || addresses.pull_xrefs == 0) {
        if (failure) *failure = "signature ARM64 xref verification failed";
        return false;
    }
    *out = addresses;
    return true;
}

// Live probe file: one "0xUNSLID = VALUE" per line, '#' comments allowed.
// Re-read on the same cadence as the main config so a value can be tried,
// judged in game, and changed again without relaunching. This exists because
// the reach-limiting global has to be found by experiment: every candidate is
// BSS, so none of them can be told apart by reading the binary alone.
bool write_float(uint64_t address, float value);  // defined below, next to the protection helpers

struct Override { uint64_t unslid = 0; float value = 0.0f; };

std::string overrides_path(const std::string &config_file) {
    const size_t slash = config_file.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? std::string(".") : config_file.substr(0, slash);
    return dir + "/CrimsonLooker.AxiomOverrides.txt";
}

std::vector<Override> load_overrides(const std::string &path) {
    std::vector<Override> result;
    std::ifstream stream(path);
    if (!stream.is_open()) return result;
    std::string line;
    while (std::getline(stream, line)) {
        const size_t comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        const size_t equals = line.find('=');
        if (equals == std::string::npos) continue;
        Override entry;
        entry.unslid = strtoull(line.substr(0, equals).c_str(), nullptr, 0);
        entry.value = strtof(line.substr(equals + 1).c_str(), nullptr);
        if (entry.unslid == 0 || !std::isfinite(entry.value)) continue;
        result.push_back(entry);
    }
    return result;
}

void apply_overrides(const GameImage &image, const std::vector<Override> &overrides, bool log_each) {
    // Offsets are build-specific. On any other build the same address is an
    // unrelated float, so go inert rather than write somewhere meaningless.
    // Values themselves are intentionally unbounded.
    if (image.uuid != kKnownBuildUuid) return;
    for (const Override &entry : overrides) {
        const uint64_t address = entry.unslid + static_cast<uint64_t>(image.slide);
        float before = 0.0f;
        if (!read_float(address, image.data, &before)) {
            if (log_each) service_log("override 0x%llx unreadable",
                static_cast<unsigned long long>(entry.unslid));
            continue;
        }
        if (near(before, entry.value)) continue;
        if (write_float(address, entry.value)) {
            service_log("override 0x%llx %.4g -> %.4g",
                static_cast<unsigned long long>(entry.unslid), before, entry.value);
        } else {
            service_log("override 0x%llx write refused",
                static_cast<unsigned long long>(entry.unslid));
        }
    }
}

void log_remote_catch_globals(const GameImage &image, const char *label) {
    if (image.uuid != kKnownBuildUuid) return;
    std::string line;
    size_t shown = 0;
    for (uint64_t unslid : kRemoteCatchGlobals) {
        const uint64_t address = unslid + static_cast<uint64_t>(image.slide);
        float value = 0.0f;
        if (!read_float(address, image.data, &value)) continue;
        if (!std::isfinite(value)) continue;
        char entry[64];
        snprintf(entry, sizeof(entry), "%llx=%.4g ",
            static_cast<unsigned long long>(unslid & 0xfffff), value);
        line += entry;
        if (++shown % 8 == 0) {
            service_log("globals[%s] %s", label, line.c_str());
            line.clear();
        }
    }
    if (!line.empty()) service_log("globals[%s] %s", label, line.c_str());
    service_log("globals[%s] dumped %zu of %zu", label, shown,
        sizeof(kRemoteCatchGlobals) / sizeof(kRemoteCatchGlobals[0]));
}

// The Windows SuperAxiomForce.asi binds by locating a range float of 20.0 and a
// pull-speed float of 40.0 and refuses to patch unless both match. Sweep __DATA
// for that pair so the Mach-O equivalents can be identified instead of guessed.
void scan_value_pair(const GameImage &image, float wanted_range, float wanted_pull) {
    std::vector<uint64_t> range_hits;
    std::vector<uint64_t> pull_hits;
    for (const Range &range : image.data) {
        if (range.end <= range.start) continue;
        for (uint64_t address = range.start; address + sizeof(float) <= range.end; address += sizeof(float)) {
            float value = 0.0f;
            memcpy(&value, reinterpret_cast<const void *>(address), sizeof(float));
            if (!std::isfinite(value)) continue;
            const uint64_t unslid = address - static_cast<uint64_t>(image.slide);
            if (near(value, wanted_range) && range_hits.size() < 512) range_hits.push_back(unslid);
            if (near(value, wanted_pull) && pull_hits.size() < 512) pull_hits.push_back(unslid);
        }
    }

    service_log("scan: %.4g hits=%zu, %.4g hits=%zu",
        wanted_range, range_hits.size(), wanted_pull, pull_hits.size());

    // Only the pairs matter: a range float with a pull float a short distance away.
    size_t pairs = 0;
    for (uint64_t range_unslid : range_hits) {
        for (uint64_t pull_unslid : pull_hits) {
            const int64_t delta = static_cast<int64_t>(pull_unslid) - static_cast<int64_t>(range_unslid);
            if (delta <= 0 || delta > 0x4000) continue;
            service_log("scan: pair range=0x%llx pull=0x%llx delta=0x%llx",
                static_cast<unsigned long long>(range_unslid),
                static_cast<unsigned long long>(pull_unslid),
                static_cast<unsigned long long>(delta));
            if (++pairs >= 64) return;
        }
    }
    service_log("scan: %zu pair%s within 0x4000", pairs, pairs == 1 ? "" : "s");
}

bool resolve_known(const GameImage &image, Addresses *out, std::string *reason) {
    if (out == nullptr) return false;
    if (image.uuid != kKnownBuildUuid) {
        if (reason) *reason = "build uuid " + image.uuid + " is not the mapped build";
        return false;
    }
    const uint64_t range_address = kKnownRangeUnslid + static_cast<uint64_t>(image.slide);
    const uint64_t pull_address = kKnownPullUnslid + static_cast<uint64_t>(image.slide);
    if (!in_ranges(image.data, range_address, sizeof(float)) ||
        !in_ranges(image.data, pull_address, sizeof(float))) {
        if (reason) *reason = "mapped range/pull address is outside __DATA";
        return false;
    }

    // Refuse the mapping unless both slots still hold their vanilla values. This
    // is the same check the Windows ASI makes, and it catches a build that kept
    // the UUID but moved the data.
    float range_value = 0.0f;
    float pull_value = 0.0f;
    if (!read_float(range_address, image.data, &range_value) ||
        !read_float(pull_address, image.data, &pull_value)) {
        if (reason) *reason = "mapped range/pull address is unreadable";
        return false;
    }
    if (!near(range_value, 20.0f) || !near(pull_value, 40.0f)) {
        if (reason) {
            char detail[128];
            snprintf(detail, sizeof(detail),
                "mapped slots hold %.4g/%.4g, expected vanilla 20/40", range_value, pull_value);
            *reason = detail;
        }
        return false;
    }

    Addresses candidate;
    candidate.range = range_address;
    candidate.pull = pull_address;
    candidate.known_pair = true;
    candidate.source = "known-offset";
    *out = candidate;
    return true;
}

bool resolve_exact(const GameImage &image, Addresses *out, size_t *raw_count, size_t *xref_rejected) {
    std::vector<Addresses> candidates;
    size_t raw = 0;
    size_t rejected = 0;
    for (const Range &data_range : image.data) {
        const uint64_t start = (data_range.start + 3u) & ~uint64_t{3};
        for (uint64_t range_address = start; range_address + sizeof(float) <= data_range.end; range_address += 4) {
            float range_value = 0.0f;
            if (!read_float(range_address, image.data, &range_value) || !near(range_value, 20.0f) ||
                range_address < 0x50 || range_address > UINT64_MAX - 0xb40) continue;
            const uint64_t limit_address = range_address - 0x50;
            const uint64_t pull_address = range_address + 0xb40;
            float limit_value = 0.0f;
            float pull_value = 0.0f;
            if (!read_float(limit_address, image.data, &limit_value) ||
                !read_float(pull_address, image.data, &pull_value) ||
                !near(limit_value, 20.0f) || !near(pull_value, 40.0f)) continue;
            ++raw;
            if (blacklisted(image, range_address) || blacklisted(image, limit_address) || blacklisted(image, pull_address)) {
                ++rejected;
                continue;
            }
            Addresses candidate;
            candidate.limit = limit_address;
            candidate.range = range_address;
            candidate.pull = pull_address;
            candidate.source = "runtime-exact";
            candidate.limit_xrefs = find_xrefs(image, limit_address).size();
            candidate.range_xrefs = find_xrefs(image, range_address).size();
            candidate.pull_xrefs = find_xrefs(image, pull_address).size();
            if (candidate.limit_xrefs == 0 || candidate.range_xrefs == 0 || candidate.pull_xrefs == 0) {
                ++rejected;
                continue;
            }
            candidates.push_back(candidate);
        }
    }
    if (raw_count) *raw_count = raw;
    if (xref_rejected) *xref_rejected = rejected;
    if (candidates.size() != 1) return false;
    *out = candidates.front();
    return true;
}

bool query_protection(uint64_t address, RegionProtection *out) {
    if (out == nullptr) return false;
    mach_vm_address_t region = address;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info{};
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    const kern_return_t result = mach_vm_region_recurse(
        mach_task_self(), &region, &size, &depth,
        reinterpret_cast<vm_region_recurse_info_t>(&info), &count);
    if (result != KERN_SUCCESS || address < region || address + sizeof(float) > region + size ||
        (info.protection & VM_PROT_READ) == 0 || (info.protection & VM_PROT_EXECUTE) != 0) {
        return false;
    }
    out->protection = info.protection;
    out->region_start = region;
    out->region_size = size;
    return true;
}

mach_vm_address_t page_start(uint64_t address) {
    return address & ~static_cast<mach_vm_address_t>(vm_page_size - 1);
}

bool probe_writable(uint64_t address) {
    RegionProtection region;
    if (!query_protection(address, &region)) return false;
    if ((region.protection & VM_PROT_WRITE) != 0) return true;
    const mach_vm_address_t page = page_start(address);
    if (mach_vm_protect(mach_task_self(), page, vm_page_size, FALSE,
            region.protection | VM_PROT_WRITE) != KERN_SUCCESS) return false;
    return mach_vm_protect(mach_task_self(), page, vm_page_size, FALSE, region.protection) == KERN_SUCCESS;
}

bool write_float(uint64_t address, float value) {
    RegionProtection region;
    if (!query_protection(address, &region)) return false;
    const bool needs_protection = (region.protection & VM_PROT_WRITE) == 0;
    const mach_vm_address_t page = page_start(address);
    if (needs_protection && mach_vm_protect(mach_task_self(), page, vm_page_size, FALSE,
            region.protection | VM_PROT_WRITE) != KERN_SUCCESS) return false;
    memcpy(reinterpret_cast<void *>(address), &value, sizeof(value));
    std::atomic_thread_fence(std::memory_order_seq_cst);
    if (needs_protection && mach_vm_protect(mach_task_self(), page, vm_page_size, FALSE,
            region.protection) != KERN_SUCCESS) return false;
    return true;
}

bool preflight_addresses(const Addresses &addresses, bool include_limit) {
    if (!probe_writable(addresses.range)) return false;
    if (addresses.range_only) return true;
    if (addresses.known_pair) return probe_writable(addresses.pull);
    return (!include_limit || probe_writable(addresses.limit)) && probe_writable(addresses.pull);
}

bool set_values(const Addresses &addresses, float limit, float range, float pull, bool include_limit) {
    if (!preflight_addresses(addresses, include_limit)) return false;
    struct Write { uint64_t address; float value; };
    std::vector<Write> writes;
    if (!addresses.range_only && !addresses.known_pair && include_limit) {
        writes.push_back({addresses.limit, limit});
    }
    writes.push_back({addresses.range, range});
    if (!addresses.range_only) writes.push_back({addresses.pull, pull});

    std::vector<Write> completed;
    for (const Write &write : writes) {
        float before = 0.0f;
        memcpy(&before, reinterpret_cast<const void *>(write.address), sizeof(before));
        if (near(before, write.value)) continue;
        if (!write_float(write.address, write.value)) {
            for (auto it = completed.rbegin(); it != completed.rend(); ++it) {
                (void)write_float(it->address, it->value);
            }
            return false;
        }
        completed.push_back({write.address, before});
    }
    return true;
}

uint64_t file_version(const std::string &path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) return 0;
    return (static_cast<uint64_t>(st.st_mtimespec.tv_sec) << 32) ^
        static_cast<uint32_t>(st.st_mtimespec.tv_nsec) ^ static_cast<uint64_t>(st.st_size);
}

bool load_initial_config(const std::string &path, Config *config) {
    if (!cdumm::axiom_force::load_config_file(path, config)) {
        service_log("disabled: config unreadable at %s", path.c_str());
        return false;
    }
    if (!config->valid) {
        service_log("disabled: malformed config or value outside safe bounds at %s", path.c_str());
        return false;
    }
    return true;
}

}  // namespace

extern "C" bool axiom_force_json_mode_requested(void) {
    struct stat st{};
    const std::string path = config_path();
    return !path.empty() && stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

extern "C" void axiom_force_run_json_service(void) {
    const std::string config_file = config_path();
    Config config;
    if (!load_initial_config(config_file, &config)) return;
    uint64_t config_version = file_version(config_file);
    service_log("automatic mode scheduled config=%s range=%.1f pull=%.1f",
        config_file.c_str(), config.range, config.pull_speed);

    sleep(kStartupDelaySeconds);
    GameImage image;
    if (!find_game_image(&image)) {
        service_log("resolver failed closed: canonical main image unavailable");
        return;
    }

    Addresses addresses;
    bool resolved = false;
    {
        std::string reason;
        if (resolve_known(image, &addresses, &reason)) {
            resolved = true;
            service_log("resolved via known offset: range=0x%llx",
                static_cast<unsigned long long>(kKnownRangeUnslid));
        } else {
            service_log("known offset unavailable: %s", reason.c_str());
        }
    }
    const std::string signature_file = signature_path(config_file);
    Signature signature;
    if (!resolved && cdumm::axiom_force::load_signature_file(signature_file, &signature)) {
        std::string reason;
        if (resolve_signature(image, config, signature, &addresses, &reason)) {
            resolved = true;
        } else {
            service_log("known signature rejected: %s", reason.c_str());
        }
    }

    size_t last_raw = 0;
    size_t last_rejected = 0;
    for (int attempt = 1; !resolved && attempt <= kResolveAttempts; ++attempt) {
        if (resolve_exact(image, &addresses, &last_raw, &last_rejected)) {
            resolved = true;
            break;
        }
        if (attempt < kResolveAttempts) sleep(kResolveRetrySeconds);
    }
    if (!resolved) {
        service_log("resolver failed closed: exact=%zu xref_rejected=%zu unique=0", last_raw, last_rejected);
        service_log("starting read-only RemoteCatch component fallback probe");
        for (int attempt = 1; attempt <= 12; ++attempt) {
            if (axiom_probe_remote_catch_component()) break;
            if (attempt < 12) sleep(5);
        }
        return;
    }

    Originals originals;
    if (!read_float(addresses.range, image.data, &originals.range) ||
        (addresses.known_pair && !read_float(addresses.pull, image.data, &originals.pull)) ||
        (!addresses.range_only && !addresses.known_pair &&
            (!read_float(addresses.limit, image.data, &originals.limit) ||
             !read_float(addresses.pull, image.data, &originals.pull)))) {
        service_log("resolver failed closed: resolved preimage unreadable");
        return;
    }
    originals.captured = true;
    if (addresses.range_only) {
        service_log("resolved source=%s range=0x%llx vanilla=%.3f (limit/pull untouched)",
            addresses.source.c_str(),
            static_cast<unsigned long long>(addresses.range - image.slide),
            originals.range);
    } else if (addresses.known_pair) {
        service_log("resolved source=%s range=0x%llx pull=0x%llx vanilla=%.3f/%.3f (limit untouched)",
            addresses.source.c_str(),
            static_cast<unsigned long long>(addresses.range - image.slide),
            static_cast<unsigned long long>(addresses.pull - image.slide),
            originals.range, originals.pull);
    } else {
        service_log("resolved source=%s limit=0x%llx range=0x%llx pull=0x%llx xrefs=%zu/%zu/%zu",
            addresses.source.c_str(),
            static_cast<unsigned long long>(addresses.limit - image.slide),
            static_cast<unsigned long long>(addresses.range - image.slide),
            static_cast<unsigned long long>(addresses.pull - image.slide),
            addresses.limit_xrefs, addresses.range_xrefs, addresses.pull_xrefs);
    }

    log_remote_catch_globals(image, "startup");

    const std::string overrides_file = overrides_path(config_file);
    uint64_t overrides_version = 0;
    service_log("override probe file: %s", overrides_file.c_str());

    bool applied = false;
    int iterations = 0;
    bool late_dumped = false;
    while (true) {
        {
            const uint64_t version = file_version(overrides_file);
            if (version != overrides_version) {
                overrides_version = version;
                const std::vector<Override> overrides = load_overrides(overrides_file);
                service_log("override file reloaded: %zu entries", overrides.size());
                apply_overrides(image, overrides, true);
            } else if (overrides_version != 0) {
                apply_overrides(image, load_overrides(overrides_file), false);
            }
        }
        // Many of these globals are populated well after the 15s startup delay,
        // so take a second reading once gameplay is actually running.
        if (!late_dumped && ++iterations >= 45) {
            log_remote_catch_globals(image, "late");
            scan_value_pair(image, 20.0f, 40.0f);
            late_dumped = true;
        }
        const uint64_t version = file_version(config_file);
        if (version != 0 && version != config_version) {
            Config reloaded;
            if (cdumm::axiom_force::load_config_file(config_file, &reloaded) && reloaded.valid) {
                config = std::move(reloaded);
                config_version = version;
                service_log("config reloaded enabled=%s range=%.1f pull=%.1f",
                    config.enabled ? "true" : "false", config.range, config.pull_speed);
            } else {
                service_log("config reload ignored: keeping last valid values");
            }
        }

        bool success = false;
        if (config.enabled) {
            success = set_values(addresses, config.range, config.range, config.pull_speed,
                config.patch_axiom_limit_range);
            if (success && !applied) {
                if (addresses.range_only) {
                    service_log("applied Range=%.1f (was %.3f)", config.range, originals.range);
                } else if (addresses.known_pair) {
                    service_log("applied Range=%.1f (was %.3f) PullSpeed=%.1f (was %.3f)",
                        config.range, originals.range, config.pull_speed, originals.pull);
                } else {
                    service_log("applied LimitRange/Range=%.1f PullSpeed=%.1f", config.range, config.pull_speed);
                }
            }
            applied = success;
        } else if (originals.captured) {
            success = set_values(addresses, originals.limit, originals.range, originals.pull, true);
            if (success && applied) service_log("disabled: original values restored");
            if (success) applied = false;
        }
        if (!success) {
            service_log("write failed closed: no partial patch retained");
            return;
        }
        const useconds_t delay = static_cast<useconds_t>(config.hot_reload_seconds * 1000000.0f);
        usleep(std::max<useconds_t>(250000, delay));
    }
}
