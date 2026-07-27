// CrimsonLooker v4 - runtime reporter/session capture + companion bridge for macOS.
// Runs on dylib load, logs process state, writes a JSON report, and can
// record bounded read-only session evidence when CDUMM enables capture.
// Also patches live Axiom Force range floats in-process (RAM only).
// Does not hook game functions, edit saves, or modify game package files.

#include "axiom_patch.h"
#include "capture_research.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/arch.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <algorithm>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>

static const size_t kMaxSampledRegions = 128;
static const size_t kMaxStringScanBytes = 256 * 1024 * 1024;
static const size_t kMaxStringHitsPerFile = 80;
static const size_t kMaxCaptureClues = 240;
static const size_t kMaxDirectoryEntries = 800;
static pthread_mutex_t g_capture_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_file_event_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool g_capture_active = false;
static char g_capture_session_id[128] = "";
static char g_file_activity_path[PATH_MAX] = "";
static thread_local bool g_interpose_guard = false;

extern "C" int __open_nocancel(const char *path, int flags, ...);
extern "C" int __openat_nocancel(int fd, const char *path, int flags, ...);

static void dirname_of(char *path) {
    char *slash = strrchr(path, '/');
    if (slash == nullptr) {
        path[0] = '.';
        path[1] = '\0';
        return;
    }
    if (slash == path) {
        path[1] = '\0';
        return;
    }
    *slash = '\0';
}

static const char *dylib_path() {
    static char path[PATH_MAX];
    if (path[0] != '\0') {
        return path;
    }
    Dl_info info;
    if (dladdr(reinterpret_cast<void *>(&dylib_path), &info) != 0 && info.dli_fname != nullptr) {
        snprintf(path, sizeof(path), "%s", info.dli_fname);
        return path;
    }
    snprintf(path, sizeof(path), "CrimsonLooker.dylib");
    return path;
}

static void path_next_to_dylib(const char *filename, char *out, size_t out_size) {
    snprintf(out, out_size, "%s", dylib_path());
    dirname_of(out);
    strlcat(out, "/", out_size);
    strlcat(out, filename, out_size);
}

static const char *log_path() {
    const char *env_path = getenv("CRIMSONLOOKER_LOG_PATH");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        path_next_to_dylib("CrimsonLooker.log", fallback, sizeof(fallback));
    }
    return fallback;
}

static const char *report_path() {
    const char *env_path = getenv("CRIMSONLOOKER_REPORT_PATH");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        path_next_to_dylib("CrimsonLooker.report.json", fallback, sizeof(fallback));
    }
    return fallback;
}

static const char *control_path() {
    const char *env_path = getenv("CRIMSONLOOKER_CONTROL_PATH");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        path_next_to_dylib("CrimsonLooker.control", fallback, sizeof(fallback));
    }
    return fallback;
}

static const char *capture_base_dir() {
    const char *env_path = getenv("CRIMSONLOOKER_CAPTURE_DIR");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        path_next_to_dylib("captures", fallback, sizeof(fallback));
    }
    return fallback;
}

static void append_line(const char *line) {
    if (!line || !line[0]) {
        return;
    }
    int fd = open(log_path(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        return;
    }
    size_t len = strlen(line);
    if (len > 0) {
        (void)write(fd, line, len);
    }
    (void)close(fd);
}

static bool mkdir_p(const char *path) {
    if (path == nullptr || path[0] == '\0') {
        return false;
    }
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t len = strlen(tmp);
    if (len == 0) {
        return false;
    }
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = '\0';
    }
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return false;
            }
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST;
}

static void json_string(FILE *f, const char *s) {
    fputc('"', f);
    if (s != nullptr) {
        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(s); *p; ++p) {
            switch (*p) {
                case '\\': fputs("\\\\", f); break;
                case '"': fputs("\\\"", f); break;
                case '\b': fputs("\\b", f); break;
                case '\f': fputs("\\f", f); break;
                case '\n': fputs("\\n", f); break;
                case '\r': fputs("\\r", f); break;
                case '\t': fputs("\\t", f); break;
                default:
                    if (*p < 0x20) {
                        fprintf(f, "\\u%04x", *p);
                    } else {
                        fputc(*p, f);
                    }
                    break;
            }
        }
    }
    fputc('"', f);
}

static void get_timestamp(char *out, size_t out_size) {
    time_t now = time(nullptr);
    struct tm tm_buf;
    if (localtime_r(&now, &tm_buf) == nullptr ||
        strftime(out, out_size, "%Y-%m-%d %H:%M:%S", &tm_buf) == 0) {
        snprintf(out, out_size, "unknown");
    }
}

static void get_executable_path(char *out, size_t out_size, char *err, size_t err_size) {
    uint32_t size = static_cast<uint32_t>(out_size);
    if (_NSGetExecutablePath(out, &size) == 0) {
        char resolved[PATH_MAX];
        if (realpath(out, resolved) != nullptr) {
            snprintf(out, out_size, "%s", resolved);
        }
        return;
    }
    snprintf(out, out_size, "");
    snprintf(err, err_size, "_NSGetExecutablePath buffer too small");
}

static void get_executable_path(char *out, size_t out_size) {
    char err[128] = "";
    get_executable_path(out, out_size, err, sizeof(err));
}

static const char *protection_string(vm_prot_t protection, char *out, size_t out_size) {
    snprintf(
        out,
        out_size,
        "%c%c%c",
        (protection & VM_PROT_READ) ? 'r' : '-',
        (protection & VM_PROT_WRITE) ? 'w' : '-',
        (protection & VM_PROT_EXECUTE) ? 'x' : '-');
    return out;
}

struct MemorySummary {
    uint64_t region_count;
    uint64_t total_bytes;
    uint64_t readable_regions;
    uint64_t writable_regions;
    uint64_t executable_regions;
    kern_return_t final_status;
    char error[128];
};

static MemorySummary collect_memory_summary() {
    MemorySummary summary{};
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 0;

    while (summary.region_count < 100000) {
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(),
            &address,
            &size,
            &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info),
            &count);

        if (kr != KERN_SUCCESS) {
            summary.final_status = kr;
            if (kr != KERN_INVALID_ADDRESS) {
                snprintf(summary.error, sizeof(summary.error), "mach_vm_region_recurse failed: %d", kr);
            }
            break;
        }
        if (info.is_submap) {
            depth++;
            continue;
        }
        summary.region_count++;
        summary.total_bytes += size;
        if (info.protection & VM_PROT_READ) {
            summary.readable_regions++;
        }
        if (info.protection & VM_PROT_WRITE) {
            summary.writable_regions++;
        }
        if (info.protection & VM_PROT_EXECUTE) {
            summary.executable_regions++;
        }
        address += size;
    }
    return summary;
}

static void write_memory_summary_object(FILE *f, const MemorySummary &summary) {
    fprintf(
        f,
        "{\"region_count\":%llu,\"total_bytes\":%llu,"
        "\"readable_regions\":%llu,\"writable_regions\":%llu,\"executable_regions\":%llu,"
        "\"final_status\":%d",
        static_cast<unsigned long long>(summary.region_count),
        static_cast<unsigned long long>(summary.total_bytes),
        static_cast<unsigned long long>(summary.readable_regions),
        static_cast<unsigned long long>(summary.writable_regions),
        static_cast<unsigned long long>(summary.executable_regions),
        summary.final_status);
    if (summary.error[0] != '\0') {
        fputs(",\"error\":", f);
        json_string(f, summary.error);
    }
    fputc('}', f);
}

static MemorySummary write_memory_map(FILE *f) {
    MemorySummary summary{};
    mach_vm_address_t address = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    size_t sampled = 0;

    fputs("\"memory_map\":{\"sampled_regions\":[", f);
    while (summary.region_count < 100000) {
        vm_region_submap_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(
            mach_task_self(),
            &address,
            &size,
            &depth,
            reinterpret_cast<vm_region_recurse_info_t>(&info),
            &count);

        if (kr != KERN_SUCCESS) {
            summary.final_status = kr;
            if (kr != KERN_INVALID_ADDRESS) {
                snprintf(summary.error, sizeof(summary.error), "mach_vm_region_recurse failed: %d", kr);
            }
            break;
        }

        if (info.is_submap) {
            depth++;
            continue;
        }

        summary.region_count++;
        summary.total_bytes += size;
        if (info.protection & VM_PROT_READ) {
            summary.readable_regions++;
        }
        if (info.protection & VM_PROT_WRITE) {
            summary.writable_regions++;
        }
        if (info.protection & VM_PROT_EXECUTE) {
            summary.executable_regions++;
        }

        if (sampled < kMaxSampledRegions) {
            char prot[8];
            char max_prot[8];
            if (sampled > 0) {
                fputc(',', f);
            }
            fprintf(
                f,
                "{\"address\":\"0x%llx\",\"size\":%llu,\"protection\":",
                static_cast<unsigned long long>(address),
                static_cast<unsigned long long>(size));
            json_string(f, protection_string(info.protection, prot, sizeof(prot)));
            fputs(",\"max_protection\":", f);
            json_string(f, protection_string(info.max_protection, max_prot, sizeof(max_prot)));
            fprintf(f, ",\"depth\":%u}", depth);
            sampled++;
        }

        address += size;
    }

    fprintf(
        f,
        "],\"sampled_region_count\":%zu,\"region_count\":%llu,\"total_bytes\":%llu,"
        "\"readable_regions\":%llu,\"writable_regions\":%llu,\"executable_regions\":%llu,"
        "\"final_status\":%d}",
        sampled,
        static_cast<unsigned long long>(summary.region_count),
        static_cast<unsigned long long>(summary.total_bytes),
        static_cast<unsigned long long>(summary.readable_regions),
        static_cast<unsigned long long>(summary.writable_regions),
        static_cast<unsigned long long>(summary.executable_regions),
        summary.final_status);
    return summary;
}

static bool paths_equal(const char *a, const char *b) {
    if (a == nullptr || b == nullptr) {
        return false;
    }
    char ra[PATH_MAX];
    char rb[PATH_MAX];
    const char *pa = realpath(a, ra) != nullptr ? ra : a;
    const char *pb = realpath(b, rb) != nullptr ? rb : b;
    return strcmp(pa, pb) == 0;
}

static bool env_flag_enabled(const char *name) {
    const char *value = getenv(name);
    return value != nullptr && (
        strcmp(value, "1") == 0 ||
        strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0);
}

static std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(tolower(c));
    });
    return value;
}

static bool contains_keyword(const std::string &value) {
    static const char *keywords[] = {
        "weapon", "sword", "blade", "tassel", "cloth", "chain", "physics", "physx",
        "havok", "hkx", "camera", "photo", "fov", "axiom", "force", "pull", "cooldown",
        "target", "mesh", "skeleton", "animation", "anim", "material", "effect", "vfx",
        "equip", "inventory", "item", "slot", "loadout", "gear", "lantern", "bow", "armor",
        "phm_", "phw_", "cd_ph", "character/", "superaxiom",
        ".pac", ".pam", ".paz", ".pak", ".hkx", ".hkt", ".bnk", ".wem", ".json", ".xml"
    };
    std::string lower = lowercase(value);
    for (const char *keyword : keywords) {
        if (lower.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

static bool starts_with(const char *value, const char *prefix) {
    if (value == nullptr || prefix == nullptr) {
        return false;
    }
    return strncmp(value, prefix, strlen(prefix)) == 0;
}

static bool should_log_file_path(const char *path) {
    if (path == nullptr || path[0] == '\0') {
        return false;
    }
    if (strstr(path, "CrimsonLooker") != nullptr ||
        strstr(path, "/runtime/captures/") != nullptr ||
        strstr(path, "/runtime/CrimsonLooker.") != nullptr) {
        return false;
    }
    if (starts_with(path, "/dev/") || starts_with(path, "/private/var/folders/")) {
        return contains_keyword(path);
    }
    if (starts_with(path, "/System/Library/") ||
        starts_with(path, "/usr/lib/") ||
        starts_with(path, "/Library/Apple/")) {
        return env_flag_enabled("CRIMSONLOOKER_LOG_SYSTEM_FILES") || contains_keyword(path);
    }
    return true;
}

static void set_capture_file_activity_state(bool active, const char *session_id, const char *path) {
    pthread_mutex_lock(&g_capture_state_mutex);
    g_capture_active = active;
    if (active) {
        snprintf(g_capture_session_id, sizeof(g_capture_session_id), "%s", session_id ? session_id : "");
        snprintf(g_file_activity_path, sizeof(g_file_activity_path), "%s", path ? path : "");
        if (path != nullptr && path[0] != '\0') {
            char dir[PATH_MAX];
            snprintf(dir, sizeof(dir), "%s", path);
            dirname_of(dir);
            capture_research_set_session_dir(dir);
        }
    } else {
        g_capture_session_id[0] = '\0';
        g_file_activity_path[0] = '\0';
        capture_research_set_session_dir(nullptr);
    }
    pthread_mutex_unlock(&g_capture_state_mutex);
}

static bool get_capture_file_activity_state(char *session_id, size_t session_size, char *path, size_t path_size) {
    pthread_mutex_lock(&g_capture_state_mutex);
    bool active = g_capture_active && g_file_activity_path[0] != '\0';
    if (active) {
        snprintf(session_id, session_size, "%s", g_capture_session_id);
        snprintf(path, path_size, "%s", g_file_activity_path);
    }
    pthread_mutex_unlock(&g_capture_state_mutex);
    return active;
}

static void append_file_activity_event(
    const char *api,
    const char *path,
    const char *mode_text,
    int flags,
    int result,
    int saved_errno) {
    if (g_interpose_guard || !should_log_file_path(path)) {
        return;
    }

    char session_id[128];
    char event_path[PATH_MAX];
    if (!get_capture_file_activity_state(session_id, sizeof(session_id), event_path, sizeof(event_path))) {
        return;
    }

    g_interpose_guard = true;
    pthread_mutex_lock(&g_file_event_mutex);
    FILE *f = fopen(event_path, "a");
    if (f != nullptr) {
        char ts[64];
        get_timestamp(ts, sizeof(ts));
        fputc('{', f);
        fputs("\"schema_version\":1,", f);
        fputs("\"timestamp\":", f); json_string(f, ts); fputc(',', f);
        fputs("\"event\":\"file_activity\",", f);
        fputs("\"session_id\":", f); json_string(f, session_id); fputc(',', f);
        fprintf(f, "\"pid\":%d,", getpid());
        fputs("\"api\":", f); json_string(f, api); fputc(',', f);
        fputs("\"path\":", f); json_string(f, path); fputc(',', f);
        fputs("\"mode\":", f); json_string(f, mode_text); fputc(',', f);
        fprintf(f, "\"flags\":%d,\"result\":%d,\"errno\":%d", flags, result, saved_errno);
        fputs("}\n", f);
        fclose(f);
    }
    pthread_mutex_unlock(&g_file_event_mutex);
    capture_research_note_path(path);
    g_interpose_guard = false;
}

static int crimson_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & O_CREAT) != 0;
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    int result = static_cast<int>(has_mode ? syscall(SYS_open, path, flags, mode) : syscall(SYS_open, path, flags));
    int saved_errno = errno;
    append_file_activity_event("open", path, "", flags, result, saved_errno);
    errno = saved_errno;
    return result;
}

static int crimson_openat(int fd, const char *path, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & O_CREAT) != 0;
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    int result = static_cast<int>(has_mode ? syscall(SYS_openat, fd, path, flags, mode) : syscall(SYS_openat, fd, path, flags));
    int saved_errno = errno;
    append_file_activity_event("openat", path, "", flags, result, saved_errno);
    errno = saved_errno;
    return result;
}

static int crimson_open_nocancel(const char *path, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & O_CREAT) != 0;
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    int result = static_cast<int>(has_mode ? syscall(SYS_open_nocancel, path, flags, mode) : syscall(SYS_open_nocancel, path, flags));
    int saved_errno = errno;
    append_file_activity_event("open_nocancel", path, "", flags, result, saved_errno);
    errno = saved_errno;
    return result;
}

static int crimson_openat_nocancel(int fd, const char *path, int flags, ...) {
    mode_t mode = 0;
    bool has_mode = (flags & O_CREAT) != 0;
    if (has_mode) {
        va_list ap;
        va_start(ap, flags);
        mode = static_cast<mode_t>(va_arg(ap, int));
        va_end(ap);
    }
    int result = static_cast<int>(has_mode ? syscall(SYS_openat_nocancel, fd, path, flags, mode) : syscall(SYS_openat_nocancel, fd, path, flags));
    int saved_errno = errno;
    append_file_activity_event("openat_nocancel", path, "", flags, result, saved_errno);
    errno = saved_errno;
    return result;
}

struct InterposePair {
    const void *replacement;
    const void *replacee;
};

__attribute__((used, section("__DATA,__interpose")))
static const InterposePair kInterposePairs[] = {
    {reinterpret_cast<const void *>(crimson_open), reinterpret_cast<const void *>(open)},
    {reinterpret_cast<const void *>(crimson_openat), reinterpret_cast<const void *>(openat)},
    {reinterpret_cast<const void *>(crimson_open_nocancel), reinterpret_cast<const void *>(__open_nocancel)},
    {reinterpret_cast<const void *>(crimson_openat_nocancel), reinterpret_cast<const void *>(__openat_nocancel)},
};

static bool looks_like_asset_string(const std::string &value) {
    if (value.size() < 4 || value.size() > 320) {
        return false;
    }
    bool pathish = value.find('/') != std::string::npos ||
                   value.find('\\') != std::string::npos ||
                   value.find('.') != std::string::npos ||
                   value.find('_') != std::string::npos;
    return pathish && contains_keyword(value);
}

static void add_unique(std::vector<std::string> &items, const std::string &value, size_t max_items) {
    if (value.empty() || items.size() >= max_items) {
        return;
    }
    if (std::find(items.begin(), items.end(), value) == items.end()) {
        items.push_back(value);
    }
}

static void scan_binary_strings_for_clues(
    const char *path,
    std::vector<std::string> &clues,
    std::vector<std::string> &errors) {
    if (path == nullptr || path[0] == '\0' || clues.size() >= kMaxCaptureClues) {
        return;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return;
    }

    std::string current;
    current.reserve(256);
    unsigned char buffer[16384];
    size_t total = 0;
    size_t hits = 0;
    while (total < kMaxStringScanBytes && hits < kMaxStringHitsPerFile && clues.size() < kMaxCaptureClues) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0) {
            errors.push_back(std::string("string scan read failed: ") + path);
            break;
        }
        if (got == 0) {
            break;
        }
        total += static_cast<size_t>(got);
        for (ssize_t i = 0; i < got; ++i) {
            unsigned char c = buffer[i];
            if ((c >= 32 && c <= 126) || c == '\t') {
                if (current.size() < 512) {
                    current.push_back(static_cast<char>(c));
                }
                continue;
            }
            if (looks_like_asset_string(current)) {
                add_unique(clues, std::string("string:") + current, kMaxCaptureClues);
                hits++;
            }
            current.clear();
        }
    }
    if (looks_like_asset_string(current) && hits < kMaxStringHitsPerFile) {
        add_unique(clues, std::string("string:") + current, kMaxCaptureClues);
    }
    close(fd);
}

static void scan_directory_for_clues(
    const char *path,
    std::vector<std::string> &clues,
    std::vector<std::string> &errors,
    size_t depth = 0,
    size_t *visited = nullptr) {
    if (path == nullptr || path[0] == '\0' || depth > 3 || clues.size() >= kMaxCaptureClues) {
        return;
    }
    size_t local_visited = 0;
    if (visited == nullptr) {
        visited = &local_visited;
    }
    if (*visited >= kMaxDirectoryEntries) {
        return;
    }
    DIR *dir = opendir(path);
    if (dir == nullptr) {
        return;
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr && *visited < kMaxDirectoryEntries && clues.size() < kMaxCaptureClues) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        (*visited)++;
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, name);
        if (contains_keyword(child)) {
            add_unique(clues, std::string("path:") + child, kMaxCaptureClues);
        }
        struct stat st{};
        if (lstat(child, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode) && depth < 3) {
            scan_directory_for_clues(child, clues, errors, depth + 1, visited);
        } else if (S_ISREG(st.st_mode) && looks_like_asset_string(child)) {
            add_unique(clues, std::string("file:") + child, kMaxCaptureClues);
        }
    }
    closedir(dir);
    (void)errors;
}

static std::vector<std::string> gather_asset_clues(std::vector<std::string> &errors) {
    std::vector<std::string> clues;
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count && clues.size() < kMaxCaptureClues; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (name != nullptr && contains_keyword(name)) {
            add_unique(clues, std::string("dyld:") + name, kMaxCaptureClues);
        }
    }

    char exe_path[PATH_MAX];
    get_executable_path(exe_path, sizeof(exe_path));
    scan_binary_strings_for_clues(exe_path, clues, errors);

    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        scan_directory_for_clues(cwd, clues, errors);
    }

    char app_contents[PATH_MAX];
    snprintf(app_contents, sizeof(app_contents), "%s", exe_path);
    dirname_of(app_contents);
    dirname_of(app_contents);
    scan_directory_for_clues(app_contents, clues, errors);
    return clues;
}

struct CaptureControl {
    bool capture = false;
    std::string session_id;
    std::string output_dir;
};

static std::string trim(const std::string &value) {
    size_t start = 0;
    while (start < value.size() && isspace(static_cast<unsigned char>(value[start]))) {
        start++;
    }
    size_t end = value.size();
    while (end > start && isspace(static_cast<unsigned char>(value[end - 1]))) {
        end--;
    }
    return value.substr(start, end - start);
}

static CaptureControl read_capture_control() {
    CaptureControl control;
    FILE *f = fopen(control_path(), "r");
    if (f == nullptr) {
        return control;
    }
    char line[PATH_MAX + 64];
    while (fgets(line, sizeof(line), f) != nullptr) {
        std::string item = trim(line);
        if (item.empty() || item[0] == '#') {
            continue;
        }
        size_t eq = item.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = trim(item.substr(0, eq));
        std::string value = trim(item.substr(eq + 1));
        if (key == "capture") {
            control.capture = value == "1" || value == "true" || value == "yes";
        } else if (key == "session_id") {
            control.session_id = value;
        } else if (key == "output_dir") {
            control.output_dir = value;
        }
    }
    fclose(f);
    if (control.session_id.empty()) {
        char ts[64];
        get_timestamp(ts, sizeof(ts));
        control.session_id = ts;
        std::replace(control.session_id.begin(), control.session_id.end(), ' ', '_');
        std::replace(control.session_id.begin(), control.session_id.end(), ':', '-');
    }
    if (control.output_dir.empty()) {
        control.output_dir = std::string(capture_base_dir()) + "/" + control.session_id;
    }
    return control;
}

static void write_string_array(FILE *f, const std::vector<std::string> &items) {
    fputc('[', f);
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) {
            fputc(',', f);
        }
        json_string(f, items[i].c_str());
    }
    fputc(']', f);
}

static void append_capture_event(
    const std::string &capture_file,
    const char *event,
    const CaptureControl &control,
    const std::vector<std::string> &new_images,
    const std::vector<std::string> &asset_clues,
    const std::vector<std::string> &errors) {
    FILE *f = fopen(capture_file.c_str(), "a");
    if (f == nullptr) {
        return;
    }
    char ts[64];
    get_timestamp(ts, sizeof(ts));
    char exe_path[PATH_MAX];
    get_executable_path(exe_path, sizeof(exe_path));
    char cwd[PATH_MAX] = "";
    (void)getcwd(cwd, sizeof(cwd));
    MemorySummary memory = collect_memory_summary();

    g_interpose_guard = true;
    fputc('{', f);
    fputs("\"schema_version\":1,", f);
    fputs("\"timestamp\":", f); json_string(f, ts); fputc(',', f);
    fputs("\"event\":", f); json_string(f, event); fputc(',', f);
    fputs("\"session_id\":", f); json_string(f, control.session_id.c_str()); fputc(',', f);
    fprintf(f, "\"pid\":%d,", getpid());
    fputs("\"process_path\":", f); json_string(f, exe_path); fputc(',', f);
    fputs("\"current_working_directory\":", f); json_string(f, cwd); fputc(',', f);
    std::string file_activity = control.output_dir + "/filetrace.jsonl";
    fputs("\"file_activity_path\":", f); json_string(f, file_activity.c_str()); fputc(',', f);
    fprintf(f, "\"dyld_image_count\":%u,", _dyld_image_count());
    fputs("\"new_images\":", f); write_string_array(f, new_images); fputc(',', f);
    fputs("\"asset_clues\":", f); write_string_array(f, asset_clues); fputc(',', f);
    fputs("\"memory_summary\":", f); write_memory_summary_object(f, memory); fputc(',', f);
    fputs("\"errors\":", f); write_string_array(f, errors);
    fputs("}\n", f);
    fclose(f);
    g_interpose_guard = false;
}

static void *capture_thread_main(void *);
static void start_capture_thread();

static const char *bridge_queue_path() {
    const char *env_path = getenv("CRIMSON_FORGE_BRIDGE_QUEUE");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        snprintf(fallback, sizeof(fallback), "%s", dylib_path());
        dirname_of(fallback);
        strlcat(fallback, "/inventory_remote/bridge_queue.jsonl", sizeof(fallback));
    }
    return fallback;
}

static const char *bridge_ack_path() {
    const char *env_path = getenv("CRIMSON_FORGE_BRIDGE_ACK");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        snprintf(fallback, sizeof(fallback), "%s", dylib_path());
        dirname_of(fallback);
        strlcat(fallback, "/inventory_remote/bridge_ack.jsonl", sizeof(fallback));
    }
    return fallback;
}

static const char *bridge_processed_path() {
    const char *env_path = getenv("CRIMSON_FORGE_BRIDGE_PROCESSED");
    if (env_path != nullptr && env_path[0] == '/') {
        return env_path;
    }
    static char fallback[PATH_MAX];
    if (fallback[0] == '\0') {
        snprintf(fallback, sizeof(fallback), "%s", dylib_path());
        dirname_of(fallback);
        strlcat(fallback, "/inventory_remote/bridge_processed_ids.txt", sizeof(fallback));
    }
    return fallback;
}

static std::string extract_json_string(const std::string &line, const char *key) {
    std::string needle = std::string("\"") + key + "\":\"";
    size_t pos = line.find(needle);
    if (pos == std::string::npos) {
        return "";
    }
    pos += needle.size();
    size_t end = line.find('"', pos);
    if (end == std::string::npos) {
        return "";
    }
    return line.substr(pos, end - pos);
}

static void load_processed_ids(std::set<std::string> &processed) {
    FILE *f = fopen(bridge_processed_path(), "r");
    if (f == nullptr) {
        return;
    }
    char line[128];
    while (fgets(line, sizeof(line), f) != nullptr) {
        std::string item = trim(line);
        if (!item.empty()) {
            processed.insert(item);
        }
    }
    fclose(f);
}

static void mark_processed_id(const std::string &queue_id) {
    FILE *f = fopen(bridge_processed_path(), "a");
    if (f == nullptr) {
        return;
    }
    fprintf(f, "%s\n", queue_id.c_str());
    fclose(f);
}

static void append_bridge_ack(
    const std::string &queue_id,
    const std::string &loadout_id,
    const std::string &command_type,
    const char *status,
    const char *message) {
    FILE *f = fopen(bridge_ack_path(), "a");
    if (f == nullptr) {
        return;
    }
    char ts[64];
    get_timestamp(ts, sizeof(ts));
    g_interpose_guard = true;
    fputc('{', f);
    fputs("\"schema_version\":1,", f);
    fputs("\"timestamp\":", f); json_string(f, ts); fputc(',', f);
    fputs("\"queue_id\":", f); json_string(f, queue_id.c_str()); fputc(',', f);
    fputs("\"loadout_id\":", f); json_string(f, loadout_id.c_str()); fputc(',', f);
    fputs("\"command_type\":", f); json_string(f, command_type.c_str()); fputc(',', f);
    fputs("\"status\":", f); json_string(f, status); fputc(',', f);
    fputs("\"message\":", f); json_string(f, message); fputc(',', f);
    fprintf(f, "\"pid\":%d", getpid());
    fputs("}\n", f);
    fclose(f);
    g_interpose_guard = false;
}

static void process_bridge_queue_line(const std::string &line, std::set<std::string> &processed) {
    if (line.find("\"queue_status\":\"pending\"") == std::string::npos &&
        line.find("\"queue_status\": \"pending\"") == std::string::npos &&
        line.find("\"queue_status\"") != std::string::npos) {
        return;
    }
    std::string queue_id = extract_json_string(line, "id");
    if (queue_id.empty()) {
        return;
    }
    if (processed.find(queue_id) != processed.end()) {
        return;
    }
    std::string loadout_id = extract_json_string(line, "loadout_id");
    std::string command_type = extract_json_string(line, "command_type");
    if (command_type.empty()) {
        command_type = "apply_loadout";
    }
    append_bridge_ack(
        queue_id,
        loadout_id,
        command_type,
        "received_by_hook",
        "CrimsonLooker received loadout command. Game apply not implemented.");
    mark_processed_id(queue_id);
    processed.insert(queue_id);

    char buf[PATH_MAX + 256];
    snprintf(
        buf,
        sizeof(buf),
        "bridge: received queue_id=%s loadout_id=%s command_type=%s status=received_by_hook\n",
        queue_id.c_str(),
        loadout_id.c_str(),
        command_type.c_str());
    append_line(buf);
}

static void *bridge_thread_main(void *) {
    std::set<std::string> processed;
    load_processed_ids(processed);
    long queue_offset = 0;

    char buf[512];
    snprintf(buf, sizeof(buf), "bridge: queue=%s ack=%s\n", bridge_queue_path(), bridge_ack_path());
    append_line(buf);

    while (true) {
        FILE *f = fopen(bridge_queue_path(), "r");
        if (f != nullptr) {
            if (fseek(f, queue_offset, SEEK_SET) != 0) {
                queue_offset = 0;
                fseek(f, 0, SEEK_SET);
            }
            char line[65536];
            while (fgets(line, sizeof(line), f) != nullptr) {
                queue_offset = ftell(f);
                std::string item = trim(line);
                if (!item.empty()) {
                    process_bridge_queue_line(item, processed);
                }
            }
            fclose(f);
        }
        usleep(500000);
    }
    return nullptr;
}

static void start_bridge_thread() {
    pthread_t thread{};
    if (pthread_create(&thread, nullptr, bridge_thread_main, nullptr) == 0) {
        pthread_detach(thread);
    } else {
        append_line("CrimsonLooker bridge thread failed to start\n");
    }
}

static void *capture_thread_main(void *) {
    std::set<std::string> seen_images;
    bool active = false;
    std::string active_file;
    CaptureControl active_control;
    time_t last_sample = 0;

    while (true) {
        CaptureControl control = read_capture_control();
        if (control.capture && !active) {
            active = true;
            active_control = control;
            mkdir_p(active_control.output_dir.c_str());
            active_file = active_control.output_dir + "/capture.jsonl";
            std::string file_activity = active_control.output_dir + "/filetrace.jsonl";
            set_capture_file_activity_state(true, active_control.session_id.c_str(), file_activity.c_str());
            seen_images.clear();
            for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
                const char *name = _dyld_get_image_name(i);
                if (name != nullptr) {
                    seen_images.insert(name);
                }
            }
            std::vector<std::string> errors;
            std::vector<std::string> clues = gather_asset_clues(errors);
            append_capture_event(active_file, "capture_started", active_control, {}, clues, errors);
            last_sample = time(nullptr);
        } else if (!control.capture && active) {
            append_capture_event(active_file, "capture_stopped", active_control, {}, {}, {});
            set_capture_file_activity_state(false, nullptr, nullptr);
            active = false;
            active_file.clear();
        } else if (control.capture && active) {
            active_control = control;
            time_t now = time(nullptr);
            if (now - last_sample >= 1) {
                std::vector<std::string> new_images;
                for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
                    const char *name = _dyld_get_image_name(i);
                    if (name != nullptr && seen_images.insert(name).second) {
                        new_images.push_back(name);
                    }
                }
                std::vector<std::string> asset_clues;
                for (const std::string &image : new_images) {
                    if (contains_keyword(image)) {
                        add_unique(asset_clues, std::string("dyld:") + image, kMaxCaptureClues);
                    }
                }
                append_capture_event(active_file, "sample", active_control, new_images, asset_clues, {});
                last_sample = now;
            }
        }
        usleep(500000);
    }
    return nullptr;
}

static void start_capture_thread() {
    pthread_t thread{};
    if (pthread_create(&thread, nullptr, capture_thread_main, nullptr) == 0) {
        pthread_detach(thread);
    } else {
        append_line("CrimsonLooker capture thread failed to start\n");
    }
}

static void write_report(const char *timestamp) {
    char exe_path[PATH_MAX];
    char exe_err[128] = "";
    get_executable_path(exe_path, sizeof(exe_path), exe_err, sizeof(exe_err));

    char cwd[PATH_MAX];
    char cwd_err[128] = "";
    if (getcwd(cwd, sizeof(cwd)) == nullptr) {
        snprintf(cwd, sizeof(cwd), "");
        snprintf(cwd_err, sizeof(cwd_err), "getcwd failed");
    }

    const NXArchInfo *arch = NXGetLocalArchInfo();
    const char *arch_name = arch && arch->name ? arch->name : "unknown";
    uint32_t image_count = _dyld_image_count();

    int main_image_index = -1;
    int looker_image_index = -1;
    const char *looker_path = dylib_path();
    for (uint32_t i = 0; i < image_count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (main_image_index < 0 && paths_equal(name, exe_path)) {
            main_image_index = static_cast<int>(i);
        }
        if (looker_image_index < 0 && paths_equal(name, looker_path)) {
            looker_image_index = static_cast<int>(i);
        }
    }

    FILE *f = fopen(report_path(), "w");
    if (f == nullptr) {
        append_line("CrimsonLooker report write failed\n");
        return;
    }

    fputs("{", f);
    fputs("\"schema_version\":1,", f);
    fputs("\"timestamp\":", f); json_string(f, timestamp); fputc(',', f);
    fprintf(f, "\"pid\":%d,", getpid());
    fputs("\"process_path\":", f); json_string(f, exe_path); fputc(',', f);
    fputs("\"current_working_directory\":", f); json_string(f, cwd); fputc(',', f);
    fputs("\"executable_architecture\":", f); json_string(f, arch_name); fputc(',', f);
    fputs("\"main_executable_image\":{", f);
    fprintf(f, "\"index\":%d,\"path\":", main_image_index);
    json_string(f, main_image_index >= 0 ? _dyld_get_image_name(static_cast<uint32_t>(main_image_index)) : exe_path);
    fputs("},", f);
    fputs("\"crimsonlooker_image\":{", f);
    fprintf(f, "\"index\":%d,\"path\":", looker_image_index);
    json_string(f, looker_path);
    fputs("},", f);
    fprintf(f, "\"dyld_image_count\":%u,", image_count);

    fputs("\"environment_flags\":{", f);
    fputs("\"DYLD_INSERT_LIBRARIES\":", f); json_string(f, getenv("DYLD_INSERT_LIBRARIES")); fputc(',', f);
    fputs("\"CRIMSONLOOKER_LOG_PATH\":", f); json_string(f, getenv("CRIMSONLOOKER_LOG_PATH")); fputc(',', f);
    fputs("\"CRIMSONLOOKER_REPORT_PATH\":", f); json_string(f, getenv("CRIMSONLOOKER_REPORT_PATH")); fputc(',', f);
    fputs("\"CRIMSONLOOKER_CONTROL_PATH\":", f); json_string(f, getenv("CRIMSONLOOKER_CONTROL_PATH")); fputc(',', f);
    fputs("\"CRIMSONLOOKER_CAPTURE_DIR\":", f); json_string(f, getenv("CRIMSONLOOKER_CAPTURE_DIR")); fputc(',', f);
    fputs("\"PWD\":", f); json_string(f, getenv("PWD"));
    fputs("},", f);

    fputs("\"loaded_images\":[", f);
    for (uint32_t i = 0; i < image_count; ++i) {
        const char *name = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (i > 0) {
            fputc(',', f);
        }
        fprintf(f, "{\"index\":%u,\"path\":", i);
        json_string(f, name);
        fprintf(f, ",\"vmaddr_slide\":\"0x%lx\"}", static_cast<long>(slide));
    }
    fputs("],", f);

    MemorySummary memory = write_memory_map(f);
    fputs(",\"errors\":[", f);
    bool wrote_error = false;
    if (exe_err[0] != '\0') {
        json_string(f, exe_err);
        wrote_error = true;
    }
    if (cwd_err[0] != '\0') {
        if (wrote_error) fputc(',', f);
        json_string(f, cwd_err);
        wrote_error = true;
    }
    if (memory.error[0] != '\0') {
        if (wrote_error) fputc(',', f);
        json_string(f, memory.error);
    }
    fputs("]}", f);
    fclose(f);
}

__attribute__((constructor)) static void crimsonlooker_on_load(void) {
    char ts[64];
    get_timestamp(ts, sizeof(ts));

    char buf[1024];
    snprintf(buf, sizeof(buf), "[%s] CrimsonLooker loaded pid=%d\n", ts, getpid());
    append_line(buf);

    snprintf(buf, sizeof(buf), "  report: %s\n", report_path());
    append_line(buf);

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        if (name == nullptr) {
            snprintf(buf, sizeof(buf), "  image[%u]: <null> slide=0x%lx\n", i, static_cast<long>(slide));
        } else {
            snprintf(buf, sizeof(buf), "  image[%u]: %s slide=0x%lx\n", i, name, static_cast<long>(slide));
        }
        append_line(buf);
    }

    write_report(ts);
    start_bridge_thread();
    start_axiom_patch_thread();
    start_capture_thread();
    start_capture_research_thread();
}
