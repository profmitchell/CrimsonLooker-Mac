#pragma once

#include <cstdint>
#include <string>

namespace cdumm::axiom_force {

constexpr const char *kConfigSchema = "cohenconcepts.crimsonlooker.axiom-force.v1";
constexpr float kDefaultRange = 100.0f;
constexpr float kDefaultPullSpeed = 200.0f;

struct Config {
    bool enabled = true;
    bool patch_axiom_limit_range = true;
    bool valid = false;
    float range = kDefaultRange;
    float pull_speed = kDefaultPullSpeed;
    float hot_reload_seconds = 1.0f;
    std::string schema;
    std::string logging = "concise";
};

struct MaskedFingerprint {
    int32_t start_delta = 0;
    std::string bytes_hex;
    std::string mask_hex;
};

struct Signature {
    bool valid = false;
    std::string build_uuid;
    uint64_t mach_o_size = 0;
    uint64_t range_unslid_vmaddr = 0;
    uint64_t limit_unslid_vmaddr = 0;
    uint64_t pull_unslid_vmaddr = 0;
    float original_range = 20.0f;
    float original_limit = 20.0f;
    float original_pull = 40.0f;
    MaskedFingerprint range_fingerprint;
    MaskedFingerprint limit_fingerprint;
    MaskedFingerprint pull_fingerprint;
};

Config parse_config_json(const std::string &json);
bool load_config_file(const std::string &path, Config *out);

bool parse_signature_json(const std::string &json, Signature *out);
bool load_signature_file(const std::string &path, Signature *out);

bool is_valid_range(float value);
bool is_valid_pull_speed(float value);
bool is_valid_reload_interval(float value);

}  // namespace cdumm::axiom_force
