#include "axiom_force_runtime.h"

#include <cctype>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace cdumm::axiom_force {
namespace {

bool json_value_start(const std::string &json, const char *key, size_t *out) {
    if (key == nullptr || out == nullptr) return false;
    const std::string needle = std::string("\"") + key + "\"";
    const size_t key_pos = json.find(needle);
    if (key_pos == std::string::npos) return false;
    const size_t colon = json.find(':', key_pos + needle.size());
    if (colon == std::string::npos) return false;
    *out = json.find_first_not_of(" \t\r\n", colon + 1);
    return *out != std::string::npos;
}

bool json_string(const std::string &json, const char *key, std::string *out) {
    size_t start = 0;
    if (out == nullptr || !json_value_start(json, key, &start) || json[start] != '"') return false;
    std::string value;
    bool escaped = false;
    for (size_t i = start + 1; i < json.size(); ++i) {
        const char ch = json[i];
        if (escaped) {
            switch (ch) {
                case '"': case '\\': case '/': value.push_back(ch); break;
                case 'b': value.push_back('\b'); break;
                case 'f': value.push_back('\f'); break;
                case 'n': value.push_back('\n'); break;
                case 'r': value.push_back('\r'); break;
                case 't': value.push_back('\t'); break;
                default: return false;
            }
            escaped = false;
        } else if (ch == '\\') {
            escaped = true;
        } else if (ch == '"') {
            *out = std::move(value);
            return true;
        } else {
            value.push_back(ch);
        }
    }
    return false;
}

bool json_bool(const std::string &json, const char *key, bool *out) {
    size_t start = 0;
    if (out == nullptr || !json_value_start(json, key, &start)) return false;
    if (json.compare(start, 4, "true") == 0) {
        *out = true;
        return true;
    }
    if (json.compare(start, 5, "false") == 0) {
        *out = false;
        return true;
    }
    return false;
}

bool json_number(const std::string &json, const char *key, double *out) {
    size_t start = 0;
    if (out == nullptr || !json_value_start(json, key, &start)) return false;
    char *end = nullptr;
    const double value = std::strtod(json.c_str() + start, &end);
    if (end == json.c_str() + start || !std::isfinite(value)) return false;
    *out = value;
    return true;
}

bool json_u64(const std::string &json, const char *key, uint64_t *out) {
    if (out == nullptr) return false;
    std::string encoded;
    if (json_string(json, key, &encoded)) {
        char *end = nullptr;
        const unsigned long long value = std::strtoull(encoded.c_str(), &end, 0);
        if (end == encoded.c_str() || *end != '\0') return false;
        *out = static_cast<uint64_t>(value);
        return true;
    }
    double numeric = 0.0;
    if (!json_number(json, key, &numeric) || numeric < 0.0) return false;
    *out = static_cast<uint64_t>(numeric);
    return true;
}

bool read_file(const std::string &path, std::string *out) {
    if (out == nullptr) return false;
    std::ifstream input(path);
    if (!input) return false;
    std::ostringstream contents;
    contents << input.rdbuf();
    *out = contents.str();
    return true;
}

bool valid_hex(const std::string &value) {
    if (value.empty() || (value.size() % 2) != 0) return false;
    for (unsigned char ch : value) {
        if (!std::isxdigit(ch)) return false;
    }
    return true;
}

bool parse_fingerprint(const std::string &json, const char *prefix, MaskedFingerprint *out) {
    if (out == nullptr) return false;
    const std::string delta_key = std::string(prefix) + "_fingerprint_start_delta";
    const std::string bytes_key = std::string(prefix) + "_fingerprint_bytes_hex";
    const std::string mask_key = std::string(prefix) + "_fingerprint_mask_hex";
    double delta = 0.0;
    MaskedFingerprint result;
    if (!json_number(json, delta_key.c_str(), &delta) ||
        !json_string(json, bytes_key.c_str(), &result.bytes_hex) ||
        !json_string(json, mask_key.c_str(), &result.mask_hex) ||
        delta < -4096.0 || delta > 4096.0 ||
        !valid_hex(result.bytes_hex) || !valid_hex(result.mask_hex) ||
        result.bytes_hex.size() != result.mask_hex.size()) {
        return false;
    }
    result.start_delta = static_cast<int32_t>(delta);
    *out = std::move(result);
    return true;
}

}  // namespace

bool is_valid_range(float value) {
    return std::isfinite(value) && value >= 20.0f && value <= 5000.0f;
}

bool is_valid_pull_speed(float value) {
    return std::isfinite(value) && value >= 40.0f && value <= 10000.0f;
}

bool is_valid_reload_interval(float value) {
    return std::isfinite(value) && value >= 0.25f && value <= 60.0f;
}

Config parse_config_json(const std::string &json) {
    Config config;
    double range = config.range;
    double pull = config.pull_speed;
    double reload = config.hot_reload_seconds;
    if (!json_string(json, "schema", &config.schema) ||
        config.schema != kConfigSchema ||
        !json_bool(json, "enabled", &config.enabled) ||
        !json_number(json, "range", &range) ||
        !json_number(json, "pull_speed", &pull) ||
        !json_bool(json, "patch_axiom_limit_range", &config.patch_axiom_limit_range) ||
        !json_number(json, "hot_reload_seconds", &reload)) {
        return config;
    }
    (void)json_string(json, "logging", &config.logging);
    config.range = static_cast<float>(range);
    config.pull_speed = static_cast<float>(pull);
    config.hot_reload_seconds = static_cast<float>(reload);
    config.valid = is_valid_range(config.range) &&
        is_valid_pull_speed(config.pull_speed) &&
        is_valid_reload_interval(config.hot_reload_seconds) &&
        (config.logging == "concise" || config.logging == "diagnostic");
    return config;
}

bool load_config_file(const std::string &path, Config *out) {
    std::string json;
    if (out == nullptr || !read_file(path, &json)) return false;
    *out = parse_config_json(json);
    return true;
}

bool parse_signature_json(const std::string &json, Signature *out) {
    if (out == nullptr) return false;
    Signature signature;
    double original_range = 0.0;
    double original_limit = 0.0;
    double original_pull = 0.0;
    if (!json_string(json, "build_uuid", &signature.build_uuid) ||
        !json_u64(json, "mach_o_size", &signature.mach_o_size) ||
        !json_u64(json, "range_unslid_vmaddr", &signature.range_unslid_vmaddr) ||
        !json_u64(json, "limit_unslid_vmaddr", &signature.limit_unslid_vmaddr) ||
        !json_u64(json, "pull_unslid_vmaddr", &signature.pull_unslid_vmaddr) ||
        !json_number(json, "original_range", &original_range) ||
        !json_number(json, "original_limit", &original_limit) ||
        !json_number(json, "original_pull", &original_pull) ||
        !parse_fingerprint(json, "range", &signature.range_fingerprint) ||
        !parse_fingerprint(json, "limit", &signature.limit_fingerprint) ||
        !parse_fingerprint(json, "pull", &signature.pull_fingerprint)) {
        return false;
    }
    signature.original_range = static_cast<float>(original_range);
    signature.original_limit = static_cast<float>(original_limit);
    signature.original_pull = static_cast<float>(original_pull);
    signature.valid = !signature.build_uuid.empty() && signature.mach_o_size > 0 &&
        signature.range_unslid_vmaddr > 0 && signature.limit_unslid_vmaddr > 0 &&
        signature.pull_unslid_vmaddr > 0 && std::isfinite(signature.original_range) &&
        std::isfinite(signature.original_limit) && std::isfinite(signature.original_pull);
    if (!signature.valid) return false;
    *out = std::move(signature);
    return true;
}

bool load_signature_file(const std::string &path, Signature *out) {
    std::string json;
    return out != nullptr && read_file(path, &json) && parse_signature_json(json, out);
}

}  // namespace cdumm::axiom_force
