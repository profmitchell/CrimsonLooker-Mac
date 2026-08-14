#include "equipment_probe.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <unistd.h>

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <set>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

// -----------------------------------------------------------------------------
// Trinity semantic reference (Windows) — DATA LAYOUT HYPOTHESES ONLY.
//
// We intentionally do not port any x86-64 AOB signature or Windows address.
// This probe asks a narrower question: did Pearl Abyss keep the same 64-bit
// TrItemValue/equipment component layout in the native arm64 build?
//
// Trinity currently documents:
//   equip component +0x88 -> table descriptor
//   descriptor +0x08      -> TrItemValue+tag entry[]
//   descriptor +0x10      -> u32 entry count
//   entry stride          = 0xC8
//   entry +0x00           = i64 instance id
//   entry +0x08           = u16 type id
//   entry +0x0A           = u16 subtype/refinement
//   entry +0x10           = i64 quantity
//   entry +0xC0           = u16 equipment slot tag
//
// The component has a strong self-check:
//   component +0x08 -> owner/character
//   owner +0x68     -> sub-object
//   sub +0x38       -> the same equipment component
//
// Everything below is READ ONLY. A failed hypothesis produces a log, never a
// write, hook, trampoline, save edit, or best-guess mutation.
// -----------------------------------------------------------------------------

constexpr uint64_t kOffEquipCompOwner = 0x08;
constexpr uint64_t kOffEquipCompTable = 0x88;
constexpr uint64_t kOffOwnerSub       = 0x68;
constexpr uint64_t kOffSubEquipComp   = 0x38;
constexpr uint64_t kOffSubHolder      = 0xB8;
constexpr uint64_t kOffOwnerPossessor = 0xA0;
constexpr uint64_t kOffPossessorPawn  = 0xD0;

constexpr uint64_t kOffTableArray = 0x08;
constexpr uint64_t kOffTableCount = 0x10;

constexpr uint64_t kEntryStride   = 0xC8;
constexpr uint64_t kOffInstanceId = 0x00;
constexpr uint64_t kOffTypeId     = 0x08;
constexpr uint64_t kOffSubtype    = 0x0A;
constexpr uint64_t kOffQuantity   = 0x10;
constexpr uint64_t kOffSlotTag    = 0xC0;

constexpr size_t   kChunkBytes = 4 * 1024 * 1024;
constexpr uint64_t kScanBudgetBytes = 10ull * 1024ull * 1024ull * 1024ull;
constexpr int      kInitialDelaySeconds = 20;
constexpr int      kRetryDelaySeconds = 20;
constexpr int      kMaxDiscoveryPasses = 6;
constexpr int      kMaxCandidatesLogged = 8;
constexpr int      kMaxDescriptorValidations = 20000;

struct Region {
    uint64_t start = 0;
    uint64_t end = 0;
};

struct Slot {
    uint64_t address = 0;
    int64_t instanceId = 0;
    uint16_t typeId = 0;
    uint16_t subtype = 0;
    int64_t quantity = 0;
    uint16_t tag = 0;
};

struct Candidate {
    uint64_t descriptor = 0;
    uint64_t array = 0;
    uint32_t count = 0;
    int score = 0;
    int occupied = 0;
    int knownTags = 0;
    int uniqueTags = 0;
    int qtyOne = 0;
};

struct ComponentMatch {
    uint64_t component = 0;
    uint64_t owner = 0;
    uint64_t sub = 0;
    uint64_t holder = 0;
    uint64_t possessor = 0;
    uint64_t possessorBackref = 0;
    bool ownerRoundTrip = false;
    bool possessorRoundTrip = false;
};

pthread_mutex_t gProbeLogMutex = PTHREAD_MUTEX_INITIALIZER;

void dirname_in_place(char *path) {
    char *slash = strrchr(path, '/');
    if (!slash) {
        snprintf(path, PATH_MAX, "/tmp");
        return;
    }
    if (slash == path) {
        path[1] = '\0';
        return;
    }
    *slash = '\0';
}

const char *probe_path_impl() {
    const char *explicitPath = getenv("CRIMSONLOOKER_EQUIPMENT_LOG_PATH");
    if (explicitPath && explicitPath[0] == '/') return explicitPath;

    static char path[PATH_MAX] = "";
    if (path[0]) return path;

    // Keep the probe beside the normal CrimsonLooker log when CDUMM provides
    // one. Otherwise /tmp is guaranteed to be writable in the local workflow.
    const char *mainLog = getenv("CRIMSONLOOKER_LOG_PATH");
    if (mainLog && mainLog[0] == '/') {
        snprintf(path, sizeof(path), "%s", mainLog);
        dirname_in_place(path);
        strlcat(path, "/CrimsonLooker-EquipmentProbe.log", sizeof(path));
    } else {
        snprintf(path, sizeof(path), "/tmp/CrimsonLooker-EquipmentProbe.log");
    }
    return path;
}

void probe_log(const char *fmt, ...) {
    char line[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&gProbeLogMutex);
    if (FILE *f = fopen(probe_path_impl(), "a")) {
        fputs(line, f);
        fclose(f);
    }
    pthread_mutex_unlock(&gProbeLogMutex);
}

bool safe_read(uint64_t address, void *out, size_t size) {
    if (!out || size == 0 || address < 0x10000) return false;
    mach_vm_size_t copied = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        static_cast<mach_vm_address_t>(address),
        static_cast<mach_vm_size_t>(size),
        reinterpret_cast<mach_vm_address_t>(out),
        &copied);
    return kr == KERN_SUCCESS && copied == size;
}

template <typename T>
bool safe_read_value(uint64_t address, T *out) {
    return safe_read(address, out, sizeof(T));
}

bool pointerish(uint64_t value) {
    return value >= 0x100000000ull && value < 0x0000800000000000ull;
}

bool known_slot_tag(uint16_t tag) {
    switch (tag) {
        case 0: case 1: case 2: case 3: case 4: case 5: case 6:
        case 7: case 8: case 9: case 10: case 11: case 12: case 13:
        case 15: case 16: case 17: case 18: case 19: case 20: case 21:
            return true;
        default:
            return false;
    }
}

const char *slot_name(uint16_t tag) {
    switch (tag) {
        case 0: return "Main Hand";
        case 1: return "Off-Hand";
        case 2: return "Ranged Weapon";
        case 3: return "Helmet";
        case 4: return "Chest";
        case 5: return "Gloves";
        case 6: return "Boots";
        case 7: return "Earring 1";
        case 8: return "Earring 2";
        case 9: return "Necklace";
        case 10: return "Ring 1";
        case 11: return "Ring 2";
        case 12: return "Dagger";
        case 13: return "Two-Handed Weapon";
        case 15: return "Lantern";
        case 16: return "Cloak";
        case 17: return "Glasses";
        case 18: return "Mask";
        case 19: return "Backpack";
        case 20: return "Bracelet";
        case 21: return "Rocket";
        default: return "Unknown/Reserved";
    }
}

bool plausible_tag(uint16_t tag) {
    return tag <= 32;
}

std::vector<Region> collect_rw_regions(uint64_t *totalBytes) {
    std::vector<Region> regions;
    uint64_t total = 0;
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 0;

    for (size_t guard = 0; guard < 200000; ++guard) {
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(), &address, &size, &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info), &count);
        if (kr != KERN_SUCCESS) break;
        if (info.is_submap) {
            ++depth;
            continue;
        }

        if ((info.protection & VM_PROT_READ) &&
            (info.protection & VM_PROT_WRITE) &&
            !(info.protection & VM_PROT_EXECUTE) &&
            size >= 0x1000) {
            regions.push_back({static_cast<uint64_t>(address),
                               static_cast<uint64_t>(address + size)});
            total += static_cast<uint64_t>(size);
        }
        address += size;
    }

    if (totalBytes) *totalBytes = total;
    return regions;
}

bool in_regions(const std::vector<Region> &regions, uint64_t address, size_t size) {
    for (const Region &r : regions) {
        if (address >= r.start && address < r.end &&
            size <= r.end - address) return true;
    }
    return false;
}

bool parse_slot_bytes(const uint8_t *p, size_t available, uint64_t address, Slot *out) {
    if (!p || !out || available < kEntryStride) return false;
    Slot s{};
    s.address = address;
    memcpy(&s.instanceId, p + kOffInstanceId, sizeof(s.instanceId));
    memcpy(&s.typeId, p + kOffTypeId, sizeof(s.typeId));
    memcpy(&s.subtype, p + kOffSubtype, sizeof(s.subtype));
    memcpy(&s.quantity, p + kOffQuantity, sizeof(s.quantity));
    memcpy(&s.tag, p + kOffSlotTag, sizeof(s.tag));

    if (!plausible_tag(s.tag)) return false;
    if (s.typeId != 0xFFFF) {
        if (s.instanceId <= 0 || s.instanceId > 1000000000000000ll) return false;
        if (s.quantity < 0 || s.quantity > 1000000000ll) return false;
    }
    *out = s;
    return true;
}

bool read_table(uint64_t array, uint32_t count, std::vector<Slot> *slots) {
    if (!slots || !pointerish(array) || count == 0 || count > 64) return false;
    const size_t bytes = static_cast<size_t>(count) * static_cast<size_t>(kEntryStride);
    std::vector<uint8_t> raw(bytes);
    if (!safe_read(array, raw.data(), raw.size())) return false;

    slots->clear();
    slots->reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        Slot s{};
        const size_t off = static_cast<size_t>(i) * static_cast<size_t>(kEntryStride);
        if (!parse_slot_bytes(raw.data() + off, raw.size() - off,
                              array + static_cast<uint64_t>(off), &s)) {
            return false;
        }
        slots->push_back(s);
    }
    return true;
}

bool score_table(uint64_t descriptor, uint64_t array, uint32_t count, Candidate *out) {
    std::vector<Slot> slots;
    if (!read_table(array, count, &slots)) return false;

    std::set<uint16_t> unique;
    int occupied = 0;
    int known = 0;
    int qtyOne = 0;

    for (const Slot &s : slots) {
        unique.insert(s.tag);
        if (known_slot_tag(s.tag)) ++known;
        if (s.typeId != 0xFFFF) {
            ++occupied;
            if (s.quantity == 1) ++qtyOne;
        }
    }

    // Strong enough to reject random heap vectors while allowing a partially
    // equipped early-game character.
    if (count < 5 || occupied < 3 || known < 4 || unique.size() < 4) return false;

    Candidate c{};
    c.descriptor = descriptor;
    c.array = array;
    c.count = count;
    c.occupied = occupied;
    c.knownTags = known;
    c.uniqueTags = static_cast<int>(unique.size());
    c.qtyOne = qtyOne;
    c.score = known * 9 + c.uniqueTags * 6 + occupied * 5 + qtyOne * 3 +
              static_cast<int>(count);
    *out = c;
    return true;
}

std::vector<Candidate> discover_tables(const std::vector<Region> &regions,
                                       uint64_t *bytesScanned,
                                       int *descriptorsValidated,
                                       bool *budgetHit,
                                       bool *validationCapHit) {
    std::vector<Candidate> found;
    std::unordered_set<uint64_t> seenArrays;
    uint64_t scanned = 0;
    int validations = 0;
    bool hitBudget = false;
    bool hitValidationCap = false;

    for (const Region &region : regions) {
        if (scanned >= kScanBudgetBytes) { hitBudget = true; break; }

        for (uint64_t cur = region.start; cur < region.end;) {
            if (scanned >= kScanBudgetBytes) { hitBudget = true; break; }
            const uint64_t remain = region.end - cur;
            const size_t want = static_cast<size_t>(std::min<uint64_t>(remain, kChunkBytes));
            std::vector<uint8_t> buf(want);
            mach_vm_size_t copied = 0;
            kern_return_t kr = mach_vm_read_overwrite(
                mach_task_self(),
                static_cast<mach_vm_address_t>(cur),
                static_cast<mach_vm_size_t>(want),
                reinterpret_cast<mach_vm_address_t>(buf.data()),
                &copied);
            if (kr != KERN_SUCCESS || copied < 24) {
                cur += want;
                continue;
            }

            const size_t usable = static_cast<size_t>(copied);
            for (size_t off = 0; off + 24 <= usable; off += 8) {
                uint64_t array = 0;
                uint32_t count = 0;
                memcpy(&array, buf.data() + off + kOffTableArray, sizeof(array));
                memcpy(&count, buf.data() + off + kOffTableCount, sizeof(count));

                if (!pointerish(array) || count < 5 || count > 64) continue;
                if (!in_regions(regions, array,
                                static_cast<size_t>(count) * static_cast<size_t>(kEntryStride))) continue;
                if (!seenArrays.insert(array).second) continue;

                if (++validations > kMaxDescriptorValidations) {
                    hitValidationCap = true;
                    break;
                }

                Candidate c{};
                if (score_table(cur + off, array, count, &c)) found.push_back(c);
            }

            scanned += usable;
            cur += usable;
            if (hitValidationCap) break;
        }
        if (hitValidationCap) break;
    }

    std::sort(found.begin(), found.end(), [](const Candidate &a, const Candidate &b) {
        return a.score > b.score;
    });

    if (bytesScanned) *bytesScanned = scanned;
    if (descriptorsValidated) *descriptorsValidated = validations;
    if (budgetHit) *budgetHit = hitBudget;
    if (validationCapHit) *validationCapHit = hitValidationCap;
    return found;
}

bool validate_component(uint64_t component, uint64_t expectedDescriptor, ComponentMatch *out) {
    if (!pointerish(component) || !out) return false;

    uint64_t descriptor = 0;
    uint64_t owner = 0;
    if (!safe_read_value(component + kOffEquipCompTable, &descriptor) ||
        descriptor != expectedDescriptor) return false;
    if (!safe_read_value(component + kOffEquipCompOwner, &owner) || !pointerish(owner)) return false;

    ComponentMatch m{};
    m.component = component;
    m.owner = owner;

    uint64_t sub = 0;
    uint64_t backComp = 0;
    if (safe_read_value(owner + kOffOwnerSub, &sub) && pointerish(sub)) {
        m.sub = sub;
        safe_read_value(sub + kOffSubHolder, &m.holder);
        if (safe_read_value(sub + kOffSubEquipComp, &backComp) && backComp == component) {
            m.ownerRoundTrip = true;
        }
    }

    uint64_t possessor = 0;
    uint64_t pawn = 0;
    if (safe_read_value(owner + kOffOwnerPossessor, &possessor) && pointerish(possessor)) {
        m.possessor = possessor;
        if (safe_read_value(possessor + kOffPossessorPawn, &pawn)) {
            m.possessorBackref = pawn;
            m.possessorRoundTrip = pawn == owner;
        }
    }

    // The owner -> sub -> component round-trip is the load-bearing proof.
    if (!m.ownerRoundTrip) return false;
    *out = m;
    return true;
}

bool find_component_for_descriptor(const std::vector<Region> &regions,
                                   uint64_t descriptor,
                                   ComponentMatch *out) {
    const uint8_t *needle = reinterpret_cast<const uint8_t *>(&descriptor);

    for (const Region &region : regions) {
        for (uint64_t cur = region.start; cur < region.end;) {
            const uint64_t remain = region.end - cur;
            const size_t want = static_cast<size_t>(std::min<uint64_t>(remain, kChunkBytes));
            std::vector<uint8_t> buf(want);
            mach_vm_size_t copied = 0;
            kern_return_t kr = mach_vm_read_overwrite(
                mach_task_self(), cur, want,
                reinterpret_cast<mach_vm_address_t>(buf.data()), &copied);
            if (kr != KERN_SUCCESS || copied < sizeof(uint64_t)) {
                cur += want;
                continue;
            }

            const size_t usable = static_cast<size_t>(copied);
            for (size_t off = 0; off + sizeof(uint64_t) <= usable; off += 8) {
                if (memcmp(buf.data() + off, needle, sizeof(uint64_t)) != 0) continue;
                const uint64_t refAddress = cur + off;
                if (refAddress < kOffEquipCompTable) continue;
                const uint64_t component = refAddress - kOffEquipCompTable;
                ComponentMatch m{};
                if (validate_component(component, descriptor, &m)) {
                    *out = m;
                    return true;
                }
            }
            cur += usable;
        }
    }
    return false;
}

void dump_candidate(const Candidate &c, const char *prefix) {
    probe_log("%s descriptor=0x%llx array=0x%llx count=%u score=%d occupied=%d knownTags=%d uniqueTags=%d qtyOne=%d\n",
              prefix,
              static_cast<unsigned long long>(c.descriptor),
              static_cast<unsigned long long>(c.array),
              c.count, c.score, c.occupied, c.knownTags, c.uniqueTags, c.qtyOne);

    std::vector<Slot> slots;
    if (!read_table(c.array, c.count, &slots)) {
        probe_log("%s table changed/unreadable before dump\n", prefix);
        return;
    }

    for (size_t i = 0; i < slots.size(); ++i) {
        const Slot &s = slots[i];
        probe_log("  slot[%zu] tag=%u (%s) typeId=%u instanceId=%lld qty=%lld subtype=%u addr=0x%llx%s\n",
                  i,
                  static_cast<unsigned>(s.tag), slot_name(s.tag),
                  static_cast<unsigned>(s.typeId),
                  static_cast<long long>(s.instanceId),
                  static_cast<long long>(s.quantity),
                  static_cast<unsigned>(s.subtype),
                  static_cast<unsigned long long>(s.address),
                  s.typeId == 0xFFFF ? " EMPTY" : "");
    }
}

uint64_t snapshot_hash(uint64_t descriptor, uint64_t *arrayOut, uint32_t *countOut) {
    uint64_t array = 0;
    uint32_t count = 0;
    if (!safe_read_value(descriptor + kOffTableArray, &array) ||
        !safe_read_value(descriptor + kOffTableCount, &count) ||
        !pointerish(array) || count == 0 || count > 64) return 0;

    std::vector<Slot> slots;
    if (!read_table(array, count, &slots)) return 0;

    uint64_t h = 1469598103934665603ull;
    auto mix = [&h](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            h ^= static_cast<uint8_t>(v & 0xFF);
            h *= 1099511628211ull;
            v >>= 8;
        }
    };
    for (const Slot &s : slots) {
        mix(static_cast<uint64_t>(s.instanceId));
        mix(s.typeId);
        mix(s.tag);
        mix(static_cast<uint64_t>(s.quantity));
        mix(s.subtype);
    }
    if (arrayOut) *arrayOut = array;
    if (countOut) *countOut = count;
    return h;
}

void monitor_resolved_table(uint64_t descriptor) {
    probe_log("monitor: watching resolved equipment table for changes; change gear normally if you want an A/B capture\n");
    uint64_t lastHash = 0;

    while (true) {
        uint64_t array = 0;
        uint32_t count = 0;
        const uint64_t h = snapshot_hash(descriptor, &array, &count);
        if (h != 0 && h != lastHash) {
            Candidate c{};
            if (score_table(descriptor, array, count, &c)) {
                probe_log("\n=== EQUIPMENT SNAPSHOT CHANGED ===\n");
                dump_candidate(c, "snapshot:");
                probe_log("=== END SNAPSHOT ===\n\n");
                lastHash = h;
            }
        }
        sleep(2);
    }
}

void *equipment_probe_thread_main(void *) {
    // Start a fresh evidence file each launch. The normal CrimsonLooker log
    // remains append-only; this file is intentionally one-run-per-launch.
    if (FILE *f = fopen(probe_path_impl(), "w")) {
        fprintf(f,
                "CrimsonLooker Equipment Probe\n"
                "mode: READ-ONLY / NO HOOKS / NO GAME WRITES\n"
                "reference: Trinity data-layout semantics only; no Windows AOB/address reuse\n"
                "log: %s\n\n",
                probe_path_impl());
        fclose(f);
    }

    probe_log("startup: waiting %d seconds for Crimson Desert world/player objects to initialize\n",
              kInitialDelaySeconds);
    sleep(kInitialDelaySeconds);

    for (int pass = 1; pass <= kMaxDiscoveryPasses; ++pass) {
        uint64_t rwBytes = 0;
        std::vector<Region> regions = collect_rw_regions(&rwBytes);
        probe_log("\n=== DISCOVERY PASS %d/%d ===\n", pass, kMaxDiscoveryPasses);
        probe_log("memory: rw_nonexec_regions=%zu rw_bytes=%llu\n",
                  regions.size(), static_cast<unsigned long long>(rwBytes));

        uint64_t scanned = 0;
        int validations = 0;
        bool budgetHit = false;
        bool validationCapHit = false;
        std::vector<Candidate> candidates = discover_tables(
            regions, &scanned, &validations, &budgetHit, &validationCapHit);

        probe_log("scan: bytes=%llu descriptors_validated=%d candidates=%zu budget_hit=%s validation_cap_hit=%s\n",
                  static_cast<unsigned long long>(scanned), validations, candidates.size(),
                  budgetHit ? "yes" : "no", validationCapHit ? "yes" : "no");

        if (candidates.empty()) {
            probe_log("result: NO EQUIPMENT-TABLE CANDIDATE. This argues that at least one Trinity data-layout assumption (descriptor +8/+10, 0xC8 stride, item fields, or slot-tag +0xC0) differs on arm64, OR the player was not in-world yet.\n");
        } else {
            const int n = std::min<int>(kMaxCandidatesLogged, static_cast<int>(candidates.size()));
            for (int i = 0; i < n; ++i) {
                char label[64];
                snprintf(label, sizeof(label), "candidate[%d]:", i);
                dump_candidate(candidates[static_cast<size_t>(i)], label);
            }

            for (int i = 0; i < n; ++i) {
                ComponentMatch match{};
                const Candidate &c = candidates[static_cast<size_t>(i)];
                if (!find_component_for_descriptor(regions, c.descriptor, &match)) continue;

                probe_log("\n*** RESOLVED EQUIPMENT COMPONENT ***\n");
                probe_log("proof: table shape + component->owner + owner->sub + sub->component round-trip all matched Trinity semantics\n");
                probe_log("component=0x%llx descriptor=0x%llx owner=0x%llx sub=0x%llx holder=0x%llx\n",
                          static_cast<unsigned long long>(match.component),
                          static_cast<unsigned long long>(c.descriptor),
                          static_cast<unsigned long long>(match.owner),
                          static_cast<unsigned long long>(match.sub),
                          static_cast<unsigned long long>(match.holder));
                probe_log("possessor=0x%llx possessor_backref=0x%llx possessor_roundtrip=%s\n",
                          static_cast<unsigned long long>(match.possessor),
                          static_cast<unsigned long long>(match.possessorBackref),
                          match.possessorRoundTrip ? "YES" : "no/not-resolved");
                dump_candidate(c, "RESOLVED:");
                probe_log("*** SUCCESS: READ-ONLY EQUIPMENT MILESTONE PASSED ***\n\n");

                monitor_resolved_table(c.descriptor);
                return nullptr;
            }

            probe_log("result: EQUIPMENT-LIKE TABLE(S) FOUND, but no component passed the +0x88 / owner->sub->component round-trip. This is useful partial evidence: TrItemValue/equipment-table layout may be shared while component pointer offsets differ on arm64.\n");
        }

        if (pass < kMaxDiscoveryPasses) {
            probe_log("retry: waiting %d seconds; no manual action required (being fully loaded in-world helps)\n",
                      kRetryDelaySeconds);
            sleep(kRetryDelaySeconds);
        }
    }

    probe_log("\n*** PROBE COMPLETE WITHOUT FULL RESOLUTION ***\n");
    probe_log("Do not repeat the same test unchanged. Use this log to choose the next hypothesis.\n");
    return nullptr;
}

} // namespace

const char *equipment_probe_log_path() {
    return probe_path_impl();
}

void start_equipment_probe_thread() {
    const char *disable = getenv("CRIMSONLOOKER_EQUIPMENT_PROBE");
    if (disable && (!strcmp(disable, "0") || !strcasecmp(disable, "false") || !strcasecmp(disable, "off"))) {
        return;
    }

    pthread_t thread{};
    if (pthread_create(&thread, nullptr, equipment_probe_thread_main, nullptr) == 0) {
        pthread_detach(thread);
    }
}
