// Bounded research capture: calibrated Axiom snapshots, inventory strings, equip PAC paths.
// Trigger by touching equip_arm.trigger (see docs/CAPTURE_RESEARCH.md).

#include "capture_research.h"
#include "axiom_patch.h"

#include <ctype.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <vector>

static const size_t kMaxPacRing = 64;
static const size_t kMaxStringHits = 48;

static pthread_mutex_t g_pac_ring_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_pac_ring[kMaxPacRing][PATH_MAX];
static size_t g_pac_ring_head = 0;
static time_t g_last_trigger_mtime = 0;
static char g_session_dir[PATH_MAX] = "";

void capture_research_set_session_dir(const char *dir) {
    if (dir == nullptr || dir[0] == '\0') {
        g_session_dir[0] = '\0';
        axiom_set_capture_session_dir(nullptr);
        return;
    }
    snprintf(g_session_dir, sizeof(g_session_dir), "%s", dir);
    axiom_set_capture_session_dir(dir);
}

struct StringHit {
    char text[256];
};

static void research_log(const char *fmt, ...) {
    const char *log_path = getenv("CRIMSONLOOKER_LOG_PATH");
    char fallback[PATH_MAX];
    if (log_path == nullptr || log_path[0] != '/') {
        snprintf(fallback, sizeof(fallback), "/tmp/CrimsonLooker.log");
        log_path = fallback;
    }
    FILE *f = fopen(log_path, "a");
    if (f == nullptr) return;
    fputs("research: ", f);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static bool path_looks_researchable(const char *path) {
    if (path == nullptr || path[0] == '\0') return false;
    char lower[PATH_MAX];
    snprintf(lower, sizeof(lower), "%s", path);
    for (char *p = lower; *p; ++p) *p = static_cast<char>(tolower(static_cast<unsigned char>(*p)));
    return strstr(lower, ".pac") != nullptr ||
           strstr(lower, ".paz") != nullptr ||
           strstr(lower, "equip") != nullptr ||
           strstr(lower, "inventory") != nullptr ||
           strstr(lower, "item") != nullptr ||
           strstr(lower, "character/") != nullptr ||
           strstr(lower, "cd_ph") != nullptr;
}

void capture_research_note_path(const char *path) {
    if (!path_looks_researchable(path)) return;
    pthread_mutex_lock(&g_pac_ring_mutex);
    snprintf(g_pac_ring[g_pac_ring_head % kMaxPacRing], PATH_MAX, "%s", path);
    g_pac_ring_head++;
    pthread_mutex_unlock(&g_pac_ring_mutex);
}

static void pac_ring_copy(std::vector<std::string> &out) {
    pthread_mutex_lock(&g_pac_ring_mutex);
    size_t count = g_pac_ring_head < kMaxPacRing ? g_pac_ring_head : kMaxPacRing;
    for (size_t i = 0; i < count; ++i) {
        size_t idx = (g_pac_ring_head - count + i) % kMaxPacRing;
        if (g_pac_ring[idx][0] != '\0') {
            out.emplace_back(g_pac_ring[idx]);
        }
    }
    pthread_mutex_unlock(&g_pac_ring_mutex);
}

static const char *research_trigger_path(char *buf, size_t buflen) {
    const char *env = getenv("CRIMSONLOOKER_RESEARCH_TRIGGER");
    if (env != nullptr && env[0] == '/') {
        snprintf(buf, buflen, "%s", env);
        return buf;
    }
    const char *capture_dir = getenv("CRIMSONLOOKER_CAPTURE_DIR");
    if (capture_dir != nullptr && capture_dir[0] == '/') {
        snprintf(buf, buflen, "%s/equip_arm.trigger", capture_dir);
        return buf;
    }
    snprintf(buf, buflen, "/tmp/crimsonlooker_equip_arm.trigger");
    return buf;
}

static const char *research_output_path(char *buf, size_t buflen) {
    if (g_session_dir[0] != '\0') {
        snprintf(buf, buflen, "%s/research.jsonl", g_session_dir);
        return buf;
    }
    const char *capture_dir = getenv("CRIMSONLOOKER_CAPTURE_DIR");
    if (capture_dir != nullptr && capture_dir[0] == '/') {
        snprintf(buf, buflen, "%s/research.jsonl", capture_dir);
        return buf;
    }
    snprintf(buf, buflen, "/tmp/crimsonlooker_research.jsonl");
    return buf;
}

static void json_escape(FILE *f, const char *s) {
    fputc('"', f);
    if (s == nullptr) {
        fputc('"', f);
        return;
    }
    for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; ++p) {
        if (*p == '"' || *p == '\\') fputc('\\', f);
        fputc(static_cast<char>(*p), f);
    }
    fputc('"', f);
}

static bool string_has_inventory_keyword(const std::string &value) {
    static const char *keywords[] = {
        "inventory", "equip", "iteminfo", "occupiedequip", "loadout", "weapon",
        "itemslot", "equipslot", "gear", "donor", "axiom", "superaxiom", "catchtarget",
        "inventorychange", "equipable", "main_weapon", "cd_phm", "cd_phw",
    };
    std::string lower = value;
    for (char &c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    for (const char *kw : keywords) {
        if (lower.find(kw) != std::string::npos) return true;
    }
    return false;
}

static int scan_binary_strings(const char *path, std::vector<StringHit> &hits) {
    if (path == nullptr || path[0] == '\0') return 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    std::string current;
    unsigned char buffer[16384];
    size_t total = 0;
    const size_t kMaxScan = 64 * 1024 * 1024;

    while (total < kMaxScan && hits.size() < kMaxStringHits) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got <= 0) break;
        total += static_cast<size_t>(got);
        for (ssize_t i = 0; i < got; ++i) {
            unsigned char c = buffer[i];
            if ((c >= 32 && c <= 126) || c == '\t') {
                if (current.size() < 240) current.push_back(static_cast<char>(c));
                continue;
            }
            if (current.size() >= 6 && string_has_inventory_keyword(current)) {
                StringHit hit{};
                snprintf(hit.text, sizeof(hit.text), "%s", current.c_str());
                hits.push_back(hit);
            }
            current.clear();
        }
    }
    if (current.size() >= 6 && string_has_inventory_keyword(current) && hits.size() < kMaxStringHits) {
        StringHit hit{};
        snprintf(hit.text, sizeof(hit.text), "%s", current.c_str());
        hits.push_back(hit);
    }
    close(fd);
    return static_cast<int>(hits.size());
}

static void find_game_image(uint32_t *out_index, intptr_t *out_slide, char *path, size_t pathlen) {
    *out_index = 0;
    *out_slide = 0;
    if (path) path[0] = '\0';
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (name != nullptr && strstr(name, "CrimsonDesert.app/Contents/MacOS/CrimsonDesert") != nullptr) {
            *out_index = i;
            *out_slide = _dyld_get_image_vmaddr_slide(i);
            if (path && pathlen > 0) snprintf(path, pathlen, "%s", name);
            return;
        }
    }
}

static void append_research_snapshot(const char *trigger_label) {
    char out_path[PATH_MAX];
    research_output_path(out_path, sizeof(out_path));
    axiom_record_calibration_snapshot(trigger_label);

    uint32_t image_index = 0;
    intptr_t slide = 0;
    char exe_path[PATH_MAX] = "";
    find_game_image(&image_index, &slide, exe_path, sizeof(exe_path));

    std::vector<StringHit> string_hits;
    if (exe_path[0] != '\0') {
        scan_binary_strings(exe_path, string_hits);
    }

    std::vector<std::string> pac_paths;
    pac_ring_copy(pac_paths);

    FILE *f = fopen(out_path, "a");
    if (f == nullptr) {
        research_log("failed to open %s", out_path);
        return;
    }

    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_now);

    fprintf(f, "{");
    fprintf(f, "\"schema_version\":1,");
    fprintf(f, "\"event\":\"research_snapshot\",");
    fprintf(f, "\"timestamp\":"); json_escape(f, ts); fprintf(f, ",");
    fprintf(f, "\"trigger_label\":"); json_escape(f, trigger_label ? trigger_label : "equip_arm"); fprintf(f, ",");
    fprintf(f, "\"pid\":%d,", getpid());
    fprintf(f, "\"game_image_index\":%u,\"game_slide\":\"0x%lx\",", image_index, static_cast<long>(slide));
    // Kept as an empty compatibility field for older capture analyzers. The
    // actual Axiom evidence now lives in axiom_calibration.jsonl and is tied
    // to RemoteCatch objects rather than guessed global float pairs.
    fprintf(f, "\"memory_hit_count\":0,\"memory_hits\":[],\"string_hit_count\":%zu,\"string_hits\":[", string_hits.size());
    for (size_t i = 0; i < string_hits.size(); ++i) {
        if (i > 0) fputc(',', f);
        fprintf(f, "{\"text\":"); json_escape(f, string_hits[i].text); fprintf(f, "}");
    }
    fprintf(f, "],\"recent_pac_paths\":[");
    for (size_t i = 0; i < pac_paths.size(); ++i) {
        if (i > 0) fputc(',', f);
        json_escape(f, pac_paths[i].c_str());
    }
    fprintf(f, "]}\n");
    fclose(f);

    research_log(
        "snapshot label=%s calibration=RemoteCatch string_hits=%zu pac_paths=%zu -> %s",
        trigger_label ? trigger_label : "equip_arm",
        string_hits.size(),
        pac_paths.size(),
        out_path);
}

static void read_trigger_label(const char *trigger_path, char *label, size_t label_size) {
    label[0] = '\0';
    FILE *f = fopen(trigger_path, "r");
    if (f == nullptr) {
        snprintf(label, label_size, "equip_arm");
        return;
    }
    if (fgets(label, static_cast<int>(label_size), f) == nullptr) {
        snprintf(label, label_size, "equip_arm");
    } else {
        size_t n = strlen(label);
        while (n > 0 && (label[n - 1] == '\n' || label[n - 1] == '\r' || isspace(static_cast<unsigned char>(label[n - 1])))) {
            label[--n] = '\0';
        }
        if (label[0] == '\0') snprintf(label, label_size, "equip_arm");
    }
    fclose(f);
}

static void *research_thread_main(void *) {
    char trigger_path[PATH_MAX];
    research_trigger_path(trigger_path, sizeof(trigger_path));
    research_log("thread started trigger=%s", trigger_path);

    while (true) {
        struct stat st{};
        if (stat(trigger_path, &st) == 0) {
            if (st.st_mtime != g_last_trigger_mtime) {
                g_last_trigger_mtime = st.st_mtime;
                char label[128];
                read_trigger_label(trigger_path, label, sizeof(label));
                append_research_snapshot(label);
            }
        }
        usleep(500000);
    }
    return nullptr;
}

void start_capture_research_thread(void) {
    pthread_t thread{};
    if (pthread_create(&thread, nullptr, research_thread_main, nullptr) == 0) {
        pthread_detach(thread);
    } else {
        research_log("failed to start research thread");
    }
}
