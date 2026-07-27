// In-process, calibration-gated Axiom Force range patcher for CrimsonLooker.
//
// This deliberately does not patch executable bytes or scan generic float
// pairs. A candidate is tied to ClientRemoteCatchActorComponent's vtable,
// fingerprinted to the current game image, test-applied once, and only then
// allowed to receive the configured Range value in live writable memory.

#include "axiom_patch.h"
#include "axiom_runtime.h"
#include "axiom_force_service.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using cdumm::axiom::Config;
using cdumm::axiom::Fingerprint;
using cdumm::axiom::Profile;

constexpr char kRemoteCatchTypeName[] = "N2pa31ClientRemoteCatchActorComponentE";
constexpr size_t kMaxObjectCount = 24;
constexpr size_t kObjectProbeBytes = 0x300;
constexpr mach_vm_size_t kMaxRegionSize = 32 * 1024 * 1024;
constexpr int kActivePatchAttempts = 18;
constexpr int kActivePatchIntervalSec = 5;

struct Range {
    uint64_t start = 0;
    uint64_t end = 0;
};

struct GameImage {
    const mach_header_64 *header = nullptr;
    intptr_t slide = 0;
    std::string path;
    std::vector<Range> text_ranges;
    std::vector<Range> data_ranges;
    std::vector<Range> cstring_ranges;
};

struct FieldKey {
    uint64_t object_vmaddr = 0;
    uint32_t offset = 0;

    bool operator<(const FieldKey &other) const {
        return object_vmaddr != other.object_vmaddr
            ? object_vmaddr < other.object_vmaddr
            : offset < other.offset;
    }
};

struct FieldSample {
    FieldKey key;
    float value = 0.0f;
};

struct CalibrationSnapshot {
    std::string phase;
    uint64_t vtable_runtime = 0;
    uint64_t vtable_vmaddr = 0;
    std::vector<FieldSample> fields;
};

struct CandidateStats {
    int idle = 0;
    int charging = 0;
    int release = 0;
    float min_value = INFINITY;
    float max_value = -INFINITY;
    float first_value = 0.0f;
    bool has_value = false;
};

std::mutex g_mutex;
std::mutex g_log_mutex;
Config g_config;
std::string g_profile_path;
std::string g_capture_session_dir;
std::vector<CalibrationSnapshot> g_snapshots;
bool g_validation_applied = false;
bool g_patch_success = false;

void axiom_log(const char *fmt, ...) {
    const char *env_path = getenv("CRIMSONLOOKER_LOG_PATH");
    const char *log_path = (env_path != nullptr && env_path[0] == '/')
        ? env_path : "/tmp/CrimsonLooker.log";
    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (FILE *file = fopen(log_path, "a")) {
        fprintf(file, "axiom: %s\n", line);
        fclose(file);
    }
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parse_enabled(const char *value, bool *out) {
    if (value == nullptr || value[0] == '\0' || out == nullptr) return false;
    std::string normalized(value);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    normalized = trim(normalized);
    if (normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on") {
        *out = true;
        return true;
    }
    if (normalized == "0" || normalized == "false" || normalized == "no" || normalized == "off") {
        *out = false;
        return true;
    }
    return false;
}

bool parse_range_env(const char *value, float *out) {
    if (value == nullptr || value[0] == '\0' || out == nullptr) return false;
    char *end = nullptr;
    const float parsed = strtof(value, &end);
    if (end == value || *end != '\0' || !cdumm::axiom::is_valid_range(parsed)) return false;
    *out = parsed;
    return true;
}

std::string default_profile_path() {
    const char *home = getenv("HOME");
    if (home != nullptr && home[0] != '\0') {
        return std::string(home) + "/Library/Application Support/cdumm/AxiomForceProfile.json";
    }
    return "/tmp/AxiomForceProfile.json";
}

bool read_file(const std::string &path, std::string *out) {
    if (out == nullptr || path.empty()) return false;
    std::ifstream input(path);
    if (!input) return false;
    std::ostringstream contents;
    contents << input.rdbuf();
    *out = contents.str();
    return true;
}

bool write_file_atomic(const std::string &path, const std::string &contents) {
    if (path.empty()) return false;
    std::error_code error;
    const std::filesystem::path destination(path);
    std::filesystem::create_directories(destination.parent_path(), error);
    if (error) return false;
    const std::filesystem::path temporary = destination.string() + ".tmp";
    {
        std::ofstream output(temporary, std::ios::trunc);
        if (!output) return false;
        output << contents;
    }
    std::filesystem::rename(temporary, destination, error);
    if (!error) return true;
    std::filesystem::remove(destination, error);
    error.clear();
    std::filesystem::rename(temporary, destination, error);
    return !error;
}

bool find_game_image(GameImage *out) {
    if (out == nullptr) return false;
    GameImage image;
    for (uint32_t index = 0; index < _dyld_image_count(); ++index) {
        const char *name = _dyld_get_image_name(index);
        const mach_header *header = _dyld_get_image_header(index);
        if (name == nullptr || header == nullptr ||
            strstr(name, "CrimsonDesert.app/Contents/MacOS/CrimsonDesert") == nullptr) {
            continue;
        }
        if (header->magic != MH_MAGIC_64 && header->magic != MH_CIGAM_64) continue;
        image.header = reinterpret_cast<const mach_header_64 *>(header);
        image.slide = _dyld_get_image_vmaddr_slide(index);
        image.path = name;
        break;
    }
    if (image.header == nullptr) return false;

    const uint8_t *cursor = reinterpret_cast<const uint8_t *>(image.header) + sizeof(mach_header_64);
    for (uint32_t i = 0; i < image.header->ncmds; ++i) {
        const auto *command = reinterpret_cast<const load_command *>(cursor);
        if (command->cmdsize < sizeof(load_command)) return false;
        if (command->cmd == LC_SEGMENT_64) {
            const auto *segment = reinterpret_cast<const segment_command_64 *>(command);
            const uint64_t start = segment->vmaddr + image.slide;
            const uint64_t end = start + segment->vmsize;
            const std::string segment_name(segment->segname, strnlen(segment->segname, sizeof(segment->segname)));
            if (segment_name == "__TEXT") image.text_ranges.push_back({start, end});
            if (segment_name == "__DATA" || segment_name == "__DATA_CONST") image.data_ranges.push_back({start, end});
            const auto *section = reinterpret_cast<const section_64 *>(segment + 1);
            for (uint32_t section_index = 0; section_index < segment->nsects; ++section_index) {
                const std::string section_name(section[section_index].sectname,
                    strnlen(section[section_index].sectname, sizeof(section[section_index].sectname)));
                // This build stores C++ RTTI names in __TEXT,__const rather
                // than __cstring. Search both exact read-only string pools;
                // restricting the lookup to __cstring made every live
                // RemoteCatch snapshot fail before object discovery.
                if (section_name == "__cstring" || section_name == "__const") {
                    const uint64_t section_start = section[section_index].addr + image.slide;
                    image.cstring_ranges.push_back({section_start, section_start + section[section_index].size});
                }
            }
        }
        cursor += command->cmdsize;
    }
    *out = std::move(image);
    return true;
}

bool address_in_ranges(uint64_t address, const std::vector<Range> &ranges) {
    for (const Range &range : ranges) {
        if (address >= range.start && address < range.end) return true;
    }
    return false;
}

std::string current_mach_uuid(const GameImage &image) {
    const uint8_t *cursor = reinterpret_cast<const uint8_t *>(image.header) + sizeof(mach_header_64);
    for (uint32_t i = 0; i < image.header->ncmds; ++i) {
        const auto *command = reinterpret_cast<const load_command *>(cursor);
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(uuid_command)) {
            const auto *uuid = reinterpret_cast<const uuid_command *>(command);
            char value[37];
            snprintf(value, sizeof(value),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                uuid->uuid[0], uuid->uuid[1], uuid->uuid[2], uuid->uuid[3],
                uuid->uuid[4], uuid->uuid[5], uuid->uuid[6], uuid->uuid[7],
                uuid->uuid[8], uuid->uuid[9], uuid->uuid[10], uuid->uuid[11],
                uuid->uuid[12], uuid->uuid[13], uuid->uuid[14], uuid->uuid[15]);
            return value;
        }
        cursor += command->cmdsize;
    }
    return {};
}

std::string current_bundle_version(const GameImage &image) {
    const auto marker = image.path.find("/Contents/MacOS/");
    if (marker == std::string::npos) return {};
    std::string plist;
    if (!read_file(image.path.substr(0, marker) + "/Contents/Info.plist", &plist)) return {};
    const auto key = plist.find("<key>CFBundleShortVersionString</key>");
    if (key == std::string::npos) return {};
    const auto start = plist.find("<string>", key);
    const auto end = start == std::string::npos ? std::string::npos : plist.find("</string>", start + 8);
    if (start == std::string::npos || end == std::string::npos) return {};
    return plist.substr(start + 8, end - (start + 8));
}

bool current_fingerprint(GameImage *image, Fingerprint *fingerprint) {
    GameImage found;
    if (!find_game_image(&found)) return false;
    Fingerprint result{current_bundle_version(found), current_mach_uuid(found)};
    if (result.bundle_version.empty() || result.mach_uuid.empty()) return false;
    if (image) *image = std::move(found);
    if (fingerprint) *fingerprint = std::move(result);
    return true;
}

bool find_remote_catch_vtable(const GameImage &image, uint64_t *out_runtime_vtable) {
    if (out_runtime_vtable == nullptr) return false;
    const size_t name_length = strlen(kRemoteCatchTypeName);
    std::vector<uint64_t> type_names;
    for (const Range &range : image.cstring_ranges) {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(range.start);
        for (uint64_t address = range.start; address + name_length < range.end; ++address) {
            const uint8_t *candidate = bytes + (address - range.start);
            if (memcmp(candidate, kRemoteCatchTypeName, name_length) == 0 && candidate[name_length] == '\0') {
                type_names.push_back(address);
            }
        }
    }
    if (type_names.empty()) {
        axiom_log("RemoteCatch RTTI lookup failed: type name absent from %zu read-only ranges",
            image.cstring_ranges.size());
        return false;
    }

    std::vector<uint64_t> type_infos;
    for (const Range &range : image.data_ranges) {
        for (uint64_t address = range.start; address + sizeof(uint64_t) <= range.end; address += sizeof(uint64_t)) {
            uint64_t value = 0;
            memcpy(&value, reinterpret_cast<const void *>(address), sizeof(value));
            if (std::find(type_names.begin(), type_names.end(), value) != type_names.end() && address >= sizeof(uint64_t)) {
                type_infos.push_back(address - sizeof(uint64_t));
            }
        }
    }
    if (type_infos.empty()) {
        axiom_log("RemoteCatch RTTI lookup failed: type_names=%zu type_infos=0",
            type_names.size());
        return false;
    }
    for (const Range &range : image.data_ranges) {
        for (uint64_t address = range.start; address + 4 * sizeof(uint64_t) <= range.end; address += sizeof(uint64_t)) {
            uint64_t value = 0;
            memcpy(&value, reinterpret_cast<const void *>(address), sizeof(value));
            if (std::find(type_infos.begin(), type_infos.end(), value) == type_infos.end()) continue;
            const uint64_t vtable = address + sizeof(uint64_t);
            uint64_t entry0 = 0;
            uint64_t entry1 = 0;
            memcpy(&entry0, reinterpret_cast<const void *>(vtable), sizeof(entry0));
            memcpy(&entry1, reinterpret_cast<const void *>(vtable + sizeof(uint64_t)), sizeof(entry1));
            if (address_in_ranges(entry0, image.text_ranges) && address_in_ranges(entry1, image.text_ranges)) {
                *out_runtime_vtable = vtable;
                return true;
            }
        }
    }
    axiom_log("RemoteCatch RTTI lookup failed: type_names=%zu type_infos=%zu vtables=0",
        type_names.size(), type_infos.size());
    return false;
}

bool object_address_is_writable(uint64_t address) {
    mach_vm_address_t region = address;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info{};
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    const kern_return_t result = mach_vm_region_recurse(
        mach_task_self(), &region, &size, &depth,
        reinterpret_cast<vm_region_recurse_info_t>(&info), &count);
    return result == KERN_SUCCESS && address >= region && address < region + size &&
        (info.protection & VM_PROT_WRITE) != 0 && (info.protection & VM_PROT_EXECUTE) == 0;
}

std::vector<uint64_t> find_component_objects(uint64_t runtime_vtable) {
    std::vector<uint64_t> found;
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 1;
    while (found.size() < kMaxObjectCount) {
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        const kern_return_t result = mach_vm_region_recurse(
            mach_task_self(), &address, &size, &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info), &count);
        if (result != KERN_SUCCESS) break;
        const bool readable = (info.protection & VM_PROT_READ) != 0;
        const bool writable = (info.protection & VM_PROT_WRITE) != 0;
        if (!readable || !writable || (info.protection & VM_PROT_EXECUTE) || size < sizeof(uint64_t) || size > kMaxRegionSize) {
            address += size;
            continue;
        }
        std::vector<uint8_t> bytes(static_cast<size_t>(size));
        mach_vm_size_t read_size = 0;
        const kern_return_t read_result = mach_vm_read_overwrite(
            mach_task_self(), address, size, reinterpret_cast<mach_vm_address_t>(bytes.data()), &read_size);
        if (read_result != KERN_SUCCESS || read_size < sizeof(uint64_t)) {
            address += size;
            continue;
        }
        for (mach_vm_size_t offset = 0; offset + sizeof(uint64_t) <= read_size && found.size() < kMaxObjectCount; offset += sizeof(uint64_t)) {
            uint64_t vtable = 0;
            memcpy(&vtable, bytes.data() + offset, sizeof(vtable));
            if (vtable == runtime_vtable) found.push_back(address + offset);
        }
        address += size;
    }
    return found;
}

std::vector<FieldSample> sample_component_fields(const std::vector<uint64_t> &objects) {
    std::vector<FieldSample> samples;
    for (uint64_t object : objects) {
        std::array<uint8_t, kObjectProbeBytes> bytes{};
        mach_vm_size_t read_size = 0;
        if (mach_vm_read_overwrite(mach_task_self(), object, bytes.size(),
                reinterpret_cast<mach_vm_address_t>(bytes.data()), &read_size) != KERN_SUCCESS) {
            continue;
        }
        for (uint32_t offset = sizeof(uint64_t); offset + sizeof(float) <= read_size; offset += sizeof(float)) {
            float value = 0.0f;
            memcpy(&value, bytes.data() + offset, sizeof(value));
            if (!std::isfinite(value) || value <= 0.0f || value > 100000.0f) continue;
            samples.push_back({{object, offset}, value});
        }
    }
    return samples;
}

std::string calibration_event_path() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_capture_session_dir.empty()) return g_capture_session_dir + "/axiom_calibration.jsonl";
    const char *capture_dir = getenv("CRIMSONLOOKER_CAPTURE_DIR");
    if (capture_dir != nullptr && capture_dir[0] == '/') return std::string(capture_dir) + "/axiom_calibration.jsonl";
    return "/tmp/axiom_calibration.jsonl";
}

void append_calibration_event(const std::string &event, const std::string &label,
                              const std::string &detail, const Fingerprint *fingerprint = nullptr) {
    const std::string path = calibration_event_path();
    std::error_code error;
    std::filesystem::create_directories(std::filesystem::path(path).parent_path(), error);
    if (FILE *file = fopen(path.c_str(), "a")) {
        fprintf(file, "{\"schema_version\":1,\"event\":\"%s\",\"label\":\"%s\",\"detail\":\"%s\"",
            event.c_str(), label.c_str(), detail.c_str());
        if (fingerprint != nullptr) {
            fprintf(file, ",\"bundle_version\":\"%s\",\"mach_uuid\":\"%s\"",
                fingerprint->bundle_version.c_str(), fingerprint->mach_uuid.c_str());
        }
        fprintf(file, "}\n");
        fclose(file);
    }
}

Config load_runtime_config() {
    Config config;
    const char *ini_path = getenv("CRIMSONLOOKER_AXIOM_INI");
    if (ini_path != nullptr && ini_path[0] != '\0') {
        Config parsed;
        if (cdumm::axiom::load_config_file(ini_path, &parsed)) config = std::move(parsed);
        else axiom_log("config unreadable: %s", ini_path);
    }
    bool enabled = false;
    if (parse_enabled(getenv("CRIMSONLOOKER_AXIOM_ENABLED"), &enabled)) config.enabled = enabled;
    float range = 0.0f;
    if (parse_range_env(getenv("CRIMSONLOOKER_AXIOM_RANGE"), &range)) config.range = range;
    else if (parse_range_env(getenv("CRIMSONLOOKER_AXIOM_MAX_RANGE"), &range)) config.range = range;
    else if (getenv("CRIMSONLOOKER_AXIOM_RANGE") != nullptr || getenv("CRIMSONLOOKER_AXIOM_MAX_RANGE") != nullptr) config.valid = false;
    const char *profile_env = getenv("CRIMSONLOOKER_AXIOM_PROFILE");
    if (profile_env != nullptr && profile_env[0] != '\0') config.profile_path = profile_env;
    if (config.profile_path.empty()) config.profile_path = default_profile_path();
    return config;
}

bool load_profile(const std::string &path, Profile *out) {
    std::string json;
    return read_file(path, &json) && cdumm::axiom::parse_profile_json(json, out);
}

bool save_profile(const std::string &path, const Profile &profile) {
    return write_file_atomic(path, cdumm::axiom::profile_to_json(profile));
}

bool patch_profile_value(const Profile &profile, const GameImage &image, float value, const char *reason) {
    const uint64_t runtime_vtable = profile.vtable_vmaddr + image.slide;
    const std::vector<uint64_t> objects = find_component_objects(runtime_vtable);
    if (objects.empty()) {
        axiom_log("%s: RemoteCatch component not present yet", reason);
        return false;
    }
    for (uint64_t object : objects) {
        const uint64_t field = object + profile.field_offset;
        if (!object_address_is_writable(field)) continue;
        float before = 0.0f;
        mach_vm_size_t count = sizeof(before);
        if (mach_vm_read_overwrite(mach_task_self(), field, sizeof(before),
                reinterpret_cast<mach_vm_address_t>(&before), &count) != KERN_SUCCESS || count != sizeof(before)) continue;
        if (fabsf(before - profile.expected_value) > 0.01f) continue;
        const kern_return_t result = mach_vm_write(mach_task_self(), field,
            reinterpret_cast<vm_offset_t>(&value), sizeof(value));
        if (result == KERN_SUCCESS) {
            axiom_log("%s: RemoteCatch field object=0x%llx offset=0x%x %.3f -> %.3f",
                reason, static_cast<unsigned long long>(object), profile.field_offset, before, value);
            return true;
        }
    }
    axiom_log("%s: profile preimage did not match a writable RemoteCatch component", reason);
    return false;
}

bool collect_calibration_snapshot(const std::string &phase) {
    GameImage image;
    Fingerprint fingerprint;
    if (!current_fingerprint(&image, &fingerprint)) {
        append_calibration_event("snapshot_rejected", phase, "game fingerprint unavailable");
        return false;
    }
    uint64_t runtime_vtable = 0;
    if (!find_remote_catch_vtable(image, &runtime_vtable)) {
        append_calibration_event("snapshot_rejected", phase, "RemoteCatch vtable unavailable", &fingerprint);
        return false;
    }
    const std::vector<uint64_t> objects = find_component_objects(runtime_vtable);
    CalibrationSnapshot snapshot{phase, runtime_vtable, runtime_vtable - image.slide, sample_component_fields(objects)};
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_snapshots.push_back(std::move(snapshot));
        if (g_snapshots.size() > 12) g_snapshots.erase(g_snapshots.begin());
    }
    std::ostringstream detail;
    detail << "objects=" << objects.size() << " candidate_fields=";
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        detail << g_snapshots.back().fields.size() << " vtable_vmaddr=0x" << std::hex << (runtime_vtable - image.slide);
    }
    append_calibration_event("snapshot", phase, detail.str(), &fingerprint);
    axiom_log("calibration snapshot %s: %s", phase.c_str(), detail.str().c_str());
    return true;
}

bool select_calibration_candidate() {
    GameImage image;
    Fingerprint fingerprint;
    if (!current_fingerprint(&image, &fingerprint)) {
        append_calibration_event("candidate_rejected", "axiom:select", "game fingerprint unavailable");
        return false;
    }

    std::map<FieldKey, CandidateStats> candidates;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const CalibrationSnapshot &snapshot : g_snapshots) {
            if (snapshot.vtable_vmaddr == 0) continue;
            for (const FieldSample &field : snapshot.fields) {
                CandidateStats &stats = candidates[field.key];
                if (snapshot.phase == "idle") stats.idle++;
                else if (snapshot.phase == "charging") stats.charging++;
                else if (snapshot.phase == "release") stats.release++;
                if (!stats.has_value) {
                    stats.first_value = field.value;
                    stats.has_value = true;
                }
                stats.min_value = std::min(stats.min_value, field.value);
                stats.max_value = std::max(stats.max_value, field.value);
            }
        }
    }

    struct Ranked { FieldKey key; CandidateStats stats; int score; };
    std::vector<Ranked> ranked;
    for (const auto &[key, stats] : candidates) {
        if (stats.idle < 2 || stats.charging < 2 || stats.release < 2 || !stats.has_value) continue;
        if (stats.max_value - stats.min_value > 0.01f) continue;
        int score = 60;
        if (stats.first_value >= 10.0f && stats.first_value <= 10000.0f) score += 8;
        for (float familiar : {100.0f, 200.0f, 500.0f, 1000.0f, 2000.0f, 2500.0f, 5000.0f}) {
            if (fabsf(stats.first_value - familiar) < 0.01f) score += 4;
        }
        ranked.push_back({key, stats, score});
    }
    std::sort(ranked.begin(), ranked.end(), [](const Ranked &a, const Ranked &b) {
        return a.score != b.score ? a.score > b.score : a.key.offset < b.key.offset;
    });
    if (ranked.empty()) {
        append_calibration_event("candidate_rejected", "axiom:select", "need two idle, charging, and release snapshots", &fingerprint);
        return false;
    }
    if (ranked.size() > 1 && ranked[0].score - ranked[1].score < 4) {
        std::ostringstream detail;
        detail << "ambiguous candidates=" << ranked.size() << " top_offsets=0x" << std::hex
               << ranked[0].key.offset << ",0x" << ranked[1].key.offset;
        append_calibration_event("candidate_rejected", "axiom:select", detail.str(), &fingerprint);
        axiom_log("calibration rejected: %s", detail.str().c_str());
        return false;
    }

    uint64_t runtime_vtable = 0;
    if (!find_remote_catch_vtable(image, &runtime_vtable)) return false;
    Profile profile;
    profile.fingerprint = fingerprint;
    profile.vtable_vmaddr = runtime_vtable - image.slide;
    profile.field_offset = ranked[0].key.offset;
    profile.expected_value = ranked[0].stats.first_value;
    profile.validation_range = cdumm::axiom::kValidationRange;
    profile.verified = false;
    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        path = g_profile_path;
    }
    if (!save_profile(path, profile)) {
        append_calibration_event("candidate_rejected", "axiom:select", "could not persist profile", &fingerprint);
        return false;
    }
    std::ostringstream detail;
    detail << "pending profile offset=0x" << std::hex << profile.field_offset
           << " expected=" << std::dec << profile.expected_value;
    append_calibration_event("candidate_pending", "axiom:select", detail.str(), &fingerprint);
    axiom_log("calibration candidate pending: %s", detail.str().c_str());
    return true;
}

bool apply_validation_range() {
    GameImage image;
    Fingerprint fingerprint;
    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        path = g_profile_path;
    }
    Profile profile;
    if (!current_fingerprint(&image, &fingerprint) || !load_profile(path, &profile) ||
        profile.verified || !cdumm::axiom::profile_matches(profile, fingerprint)) {
        append_calibration_event("validation_rejected", "axiom:validate", "pending profile missing or fingerprint mismatch", &fingerprint);
        return false;
    }
    const bool applied = patch_profile_value(profile, image, profile.validation_range, "validation");
    if (applied) {
        g_validation_applied = true;
        append_calibration_event("validation_applied", "axiom:validate", "temporary short range applied", &fingerprint);
    }
    return applied;
}

bool confirm_profile() {
    if (!g_validation_applied) {
        append_calibration_event("confirm_rejected", "axiom:confirm", "run the temporary validation first");
        return false;
    }
    GameImage image;
    Fingerprint fingerprint;
    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        path = g_profile_path;
    }
    Profile profile;
    if (!current_fingerprint(&image, &fingerprint) || !load_profile(path, &profile) ||
        !cdumm::axiom::profile_matches(profile, fingerprint)) {
        append_calibration_event("confirm_rejected", "axiom:confirm", "profile fingerprint mismatch", &fingerprint);
        return false;
    }
    profile.verified = true;
    if (!save_profile(path, profile)) return false;
    append_calibration_event("profile_verified", "axiom:confirm", "profile verified; next active launch uses Range", &fingerprint);
    axiom_log("calibration profile verified: %s", path.c_str());
    return true;
}

void write_hook_ready(bool patched) {
    const char *capture_dir = getenv("CRIMSONLOOKER_CAPTURE_DIR");
    const std::string path = (capture_dir != nullptr && capture_dir[0] == '/')
        ? std::string(capture_dir) + "/../hook_ready.json"
        : "/tmp/crimsonlooker_hook_ready.json";
    Config config;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        config = g_config;
    }
    if (FILE *file = fopen(path.c_str(), "w")) {
        fprintf(file,
            "{\n  \"hook_loaded\": true,\n  \"axiom_enabled\": %s,\n  \"axiom_patched\": %s,\n  \"axiom_range\": %.1f\n}\n",
            config.enabled ? "true" : "false", patched ? "true" : "false", config.range);
        fclose(file);
    }
}

void *axiom_thread_main(void *) {
    // The JSON contract activates the automatic Range/Limit/Pull resolver.
    // With no JSON present, preserve the established calibration/profile path
    // byte-for-byte so existing CrimsonLooker users are not migrated silently.
    if (axiom_force_json_mode_requested()) {
        axiom_force_run_json_service();
        return nullptr;
    }
    const Config config = load_runtime_config();
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_config = config;
        g_profile_path = config.profile_path;
    }
    write_hook_ready(false);
    if (!config.valid) {
        axiom_log("disabled: invalid AxiomForce.ini range or enabled value");
        return nullptr;
    }
    if (!config.enabled) {
        axiom_log("disabled: set Enabled=true after calibration; Range=%.1f is ready", config.range);
        return nullptr;
    }

    Profile profile;
    if (!load_profile(config.profile_path, &profile)) {
        axiom_log("disabled: no calibration profile at %s", config.profile_path.c_str());
        return nullptr;
    }
    GameImage image;
    Fingerprint fingerprint;
    if (!current_fingerprint(&image, &fingerprint) || !cdumm::axiom::profile_is_ready(profile, fingerprint)) {
        axiom_log("disabled: calibration profile does not match this Crimson Desert build");
        return nullptr;
    }
    for (int attempt = 1; attempt <= kActivePatchAttempts; ++attempt) {
        if (patch_profile_value(profile, image, config.range, "active")) {
            g_patch_success = true;
            write_hook_ready(true);
            return nullptr;
        }
        sleep(kActivePatchIntervalSec);
    }
    axiom_log("inactive: calibrated component was not created during the patch window");
    return nullptr;
}

}  // namespace

extern "C" void axiom_set_capture_session_dir(const char *dir) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_capture_session_dir = (dir != nullptr && dir[0] != '\0') ? dir : "";
}

extern "C" void axiom_record_calibration_snapshot(const char *label) {
    const std::string action = label == nullptr ? "" : label;
    if (action == "axiom:idle" || action == "axiom:charging" || action == "axiom:release") {
        collect_calibration_snapshot(action.substr(strlen("axiom:")));
    } else if (action == "axiom:select") {
        select_calibration_candidate();
    } else if (action == "axiom:validate") {
        apply_validation_range();
    } else if (action == "axiom:confirm") {
        confirm_profile();
    }
}

extern "C" bool axiom_probe_remote_catch_component(void) {
    GameImage image;
    Fingerprint fingerprint;
    if (!current_fingerprint(&image, &fingerprint)) {
        append_calibration_event(
            "component_probe_rejected", "axiom:auto-probe", "game fingerprint unavailable");
        return false;
    }
    uint64_t runtime_vtable = 0;
    if (!find_remote_catch_vtable(image, &runtime_vtable)) {
        append_calibration_event(
            "component_probe_rejected", "axiom:auto-probe", "RemoteCatch vtable unavailable", &fingerprint);
        return false;
    }
    const std::vector<uint64_t> objects = find_component_objects(runtime_vtable);
    if (objects.empty()) {
        append_calibration_event(
            "component_probe_rejected", "axiom:auto-probe", "RemoteCatch component not instantiated", &fingerprint);
        axiom_log("RemoteCatch automatic probe: vtable_vmaddr=0x%llx objects=0",
            static_cast<unsigned long long>(runtime_vtable - image.slide));
        return false;
    }

    const std::vector<FieldSample> fields = sample_component_fields(objects);
    std::set<std::pair<uint32_t, int>> familiar;
    for (const FieldSample &field : fields) {
        for (int expected : {20, 40, 100, 200}) {
            if (fabsf(field.value - static_cast<float>(expected)) <= 0.001f) {
                familiar.insert({field.key.offset, expected});
            }
        }
    }
    std::ostringstream detail;
    detail << "objects=" << objects.size()
           << " fields=" << fields.size()
           << " vtable_vmaddr=0x" << std::hex << (runtime_vtable - image.slide)
           << " familiar=";
    size_t emitted = 0;
    for (const auto &[offset, value] : familiar) {
        if (emitted++ > 0) detail << ',';
        detail << "0x" << std::hex << offset << '=' << std::dec << value;
        if (emitted >= 32) break;
    }
    if (emitted == 0) detail << "none";
    append_calibration_event("component_probe", "axiom:auto-probe", detail.str(), &fingerprint);
    axiom_log("RemoteCatch automatic probe: %s", detail.str().c_str());
    return true;
}

extern "C" void start_axiom_patch_thread(void) {
    const bool automatic = axiom_force_json_mode_requested();
    pthread_t thread{};
    if (pthread_create(&thread, nullptr, axiom_thread_main, nullptr) == 0) {
        pthread_detach(thread);
        axiom_log("%s patch thread scheduled", automatic ? "automatic Axiom Force" : "calibration-gated");
    } else {
        axiom_log("ERROR: failed to start patch thread");
    }
}
