#include "axiom_runtime.h"

#include <cctype>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>

namespace cdumm::axiom {
namespace {

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string lower(std::string value) {
    for (char &ch : value) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return value;
}

bool parse_bool(const std::string &raw, bool *out) {
    const std::string value = lower(trim(raw));
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        *out = true;
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        *out = false;
        return true;
    }
    return false;
}

bool parse_float(const std::string &raw, float *out) {
    char *end = nullptr;
    const float value = std::strtof(trim(raw).c_str(), &end);
    if (end == nullptr || *end != '\0' || !std::isfinite(value)) return false;
    *out = value;
    return true;
}

bool json_string(const std::string &json, const char *key, std::string *out) {
    const std::string needle = std::string("\"") + key + "\"";
    const auto key_pos = json.find(needle);
    if (key_pos == std::string::npos) return false;
    const auto colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) return false;
    const auto start = json.find('"', colon + 1);
    if (start == std::string::npos) return false;
    const auto end = json.find('"', start + 1);
    if (end == std::string::npos) return false;
    *out = json.substr(start + 1, end - start - 1);
    return true;
}

bool json_number(const std::string &json, const char *key, double *out) {
    const std::string needle = std::string("\"") + key + "\"";
    const auto key_pos = json.find(needle);
    if (key_pos == std::string::npos) return false;
    const auto colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) return false;
    const char *begin = json.c_str() + colon + 1;
    char *end = nullptr;
    const double value = std::strtod(begin, &end);
    if (end == begin || !std::isfinite(value)) return false;
    *out = value;
    return true;
}

bool json_bool(const std::string &json, const char *key, bool *out) {
    const std::string needle = std::string("\"") + key + "\"";
    const auto key_pos = json.find(needle);
    if (key_pos == std::string::npos) return false;
    const auto colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) return false;
    const std::string tail = trim(json.substr(colon + 1));
    if (tail.rfind("true", 0) == 0) {
        *out = true;
        return true;
    }
    if (tail.rfind("false", 0) == 0) {
        *out = false;
        return true;
    }
    return false;
}

}  // namespace

bool is_valid_range(float value) {
    return std::isfinite(value) && value > 0.0f;
}

Config parse_config_text(const std::string &text) {
    Config config;
    bool primary_range_seen = false;
    bool legacy_range_seen = false;
    float primary_range = kDefaultRange;
    float legacy_range = kDefaultRange;

    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        const auto comment = line.find_first_of(";#");
        if (comment != std::string::npos) line.erase(comment);
        line = trim(line);
        if (line.empty() || line.front() == '[') continue;
        const auto equals = line.find('=');
        if (equals == std::string::npos) continue;
        const std::string key = lower(trim(line.substr(0, equals)));
        const std::string value = trim(line.substr(equals + 1));
        if (key == "enabled") {
            bool enabled = false;
            if (!parse_bool(value, &enabled)) config.valid = false;
            else config.enabled = enabled;
        } else if (key == "range") {
            primary_range_seen = true;
            if (!parse_float(value, &primary_range) || !is_valid_range(primary_range)) config.valid = false;
        } else if (key == "maxrange") {
            legacy_range_seen = true;
            if (!parse_float(value, &legacy_range) || !is_valid_range(legacy_range)) config.valid = false;
        } else if (key == "profilefile") {
            config.profile_path = value;
        }
    }

    if (primary_range_seen) config.range = primary_range;
    else if (legacy_range_seen) config.range = legacy_range;
    return config;
}

bool load_config_file(const std::string &path, Config *out) {
    if (out == nullptr) return false;
    std::ifstream input(path);
    if (!input) return false;
    std::ostringstream contents;
    contents << input.rdbuf();
    *out = parse_config_text(contents.str());
    return true;
}

bool parse_profile_json(const std::string &json, Profile *out) {
    if (out == nullptr) return false;
    Profile profile;
    std::string vtable;
    double field_offset = 0.0;
    double expected_value = 0.0;
    double validation_range = kValidationRange;
    if (!json_string(json, "bundle_version", &profile.fingerprint.bundle_version) ||
        !json_string(json, "mach_uuid", &profile.fingerprint.mach_uuid) ||
        !json_string(json, "vtable_vmaddr", &vtable) ||
        !json_number(json, "field_offset", &field_offset) ||
        !json_number(json, "expected_value", &expected_value) ||
        !json_bool(json, "verified", &profile.verified)) {
        return false;
    }
    (void)json_number(json, "validation_range", &validation_range);
    char *end = nullptr;
    profile.vtable_vmaddr = std::strtoull(vtable.c_str(), &end, 0);
    if (end == vtable.c_str() || *end != '\0' || profile.vtable_vmaddr == 0 ||
        field_offset < 0.0 || field_offset > static_cast<double>(std::numeric_limits<uint32_t>::max()) ||
        !std::isfinite(expected_value) || !is_valid_range(static_cast<float>(validation_range))) {
        return false;
    }
    profile.field_offset = static_cast<uint32_t>(field_offset);
    profile.expected_value = static_cast<float>(expected_value);
    profile.validation_range = static_cast<float>(validation_range);
    *out = profile;
    return true;
}

std::string profile_to_json(const Profile &profile) {
    std::ostringstream out;
    out << "{\n"
        << "  \"schema_version\": 1,\n"
        << "  \"bundle_version\": \"" << profile.fingerprint.bundle_version << "\",\n"
        << "  \"mach_uuid\": \"" << profile.fingerprint.mach_uuid << "\",\n"
        << "  \"vtable_vmaddr\": \"0x" << std::hex << profile.vtable_vmaddr << std::dec << "\",\n"
        << "  \"field_offset\": " << profile.field_offset << ",\n"
        << std::fixed << std::setprecision(3)
        << "  \"expected_value\": " << profile.expected_value << ",\n"
        << "  \"validation_range\": " << profile.validation_range << ",\n"
        << "  \"verified\": " << (profile.verified ? "true" : "false") << "\n"
        << "}\n";
    return out.str();
}

bool profile_matches(const Profile &profile, const Fingerprint &current) {
    return !profile.fingerprint.bundle_version.empty() &&
           !profile.fingerprint.mach_uuid.empty() &&
           profile.fingerprint.bundle_version == current.bundle_version &&
           profile.fingerprint.mach_uuid == current.mach_uuid;
}

bool profile_is_ready(const Profile &profile, const Fingerprint &current) {
    return profile.verified && profile_matches(profile, current) &&
           profile.vtable_vmaddr != 0 && std::isfinite(profile.expected_value);
}

}  // namespace cdumm::axiom
