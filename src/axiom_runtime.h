#pragma once

#include <cstdint>
#include <string>

namespace cdumm::axiom {

constexpr float kDefaultRange = 2500.0f;
constexpr float kValidationRange = 125.0f;

struct Config {
    bool enabled = false;
    bool valid = true;
    float range = kDefaultRange;
    std::string profile_path;
};

struct Fingerprint {
    std::string bundle_version;
    std::string mach_uuid;
};

struct Profile {
    Fingerprint fingerprint;
    uint64_t vtable_vmaddr = 0;
    uint32_t field_offset = 0;
    float expected_value = 0.0f;
    float validation_range = kValidationRange;
    bool verified = false;
};

// Parses the intentionally small AxiomForce.ini surface. ``Range`` is the
// primary key; ``MaxRange`` is accepted only as a compatibility alias.
Config parse_config_text(const std::string &text);
bool load_config_file(const std::string &path, Config *out);

bool is_valid_range(float value);

// Profiles are written by the live calibration code, never hand-applied to a
// game file. The expected_value is the in-memory preimage checked before any
// write, so a stale profile becomes a no-op.
bool parse_profile_json(const std::string &json, Profile *out);
std::string profile_to_json(const Profile &profile);
bool profile_matches(const Profile &profile, const Fingerprint &current);
bool profile_is_ready(const Profile &profile, const Fingerprint &current);

}  // namespace cdumm::axiom
