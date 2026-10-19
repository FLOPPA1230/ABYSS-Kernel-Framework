#include "abyss.h"
#include <dirent.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <ctype.h>

#define FUZZ_MAX_CHILDREN 16
#define FUZZ_MAX_DRIVERS ABYSS_MAX_DRIVERS
#define FUZZ_MAX_IOCTLS ABYSS_MAX_IOCTLS
#define FUZZ_DEFAULT_ITER 1000
#define FUZZ_DEFAULT_TIMEOUT_MS 2000

static const char *known_driver_paths[] = {
    "/dev/dri/card0", "/dev/dri/renderD128", "/dev/kfd",
    "/dev/nvidia0", "/dev/nvidiactl", "/dev/vfio/vfio",
    "/dev/kvm", "/dev/vhost-net", "/dev/vhost-vsock",
    "/dev/net/tun", "/dev/loop-control", "/dev/fuse",
    "/dev/uhid", "/dev/uinput", "/dev/input/event0",
    "/dev/input/mice", "/dev/rfkill", "/dev/video0",
    "/dev/snd/controlC0", "/dev/snd/pcmC0D0p",
    "/dev/tty0", "/dev/ptmx", "/dev/random", "/dev/urandom",
    "/dev/i2c-0", "/dev/i2c-1", "/dev/spidev0.0",
    "/dev/mtd0", "/dev/mem", "/dev/port",
    "/dev/cpu/0/msr", "/dev/cpu/0/cpuid",
    NULL
};

static uint32_t crc_table[256];
static int crc_table_ready = 0;

static void crc_init_table(void) {
    if (crc_table_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
    crc_table_ready = 1;
}

static uint32_t fuzz_crc32(const uint8_t *data, size_t len) {
    crc_init_table();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c = crc_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFFu;
}

static int is_character_device(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return 0;
    return S_ISCHR(st.st_mode);
}

int abyss_fuzz_scan_drivers(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    abyss_driver_t *drivers = calloc(FUZZ_MAX_DRIVERS, sizeof(abyss_driver_t));
    if (!drivers) return ABYSS_ERR_MEM;
    uint32_t count = 0;
    for (int i = 0; known_driver_paths[i] && count < FUZZ_MAX_DRIVERS; i++) {
        const char *path = known_driver_paths[i];
        if (!is_character_device(path)) continue;
        abyss_driver_t *d = &drivers[count];
        const char *base = strrchr(path, '/');
        snprintf(d->name, sizeof(d->name), "%s", base ? base + 1 : path);
        snprintf(d->path, sizeof(d->path), "%s", path);
        int fd = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
            if (fd < 0) continue;
        }
        close(fd);
        d->ioctl_count = 0;
        d->vendor = 0;
        d->device = 0;
        d->crash_count = 0;
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
                  "driver found: %s -> %s", d->name, d->path);
        count++;
    }
    ctx->module_data[ABYSS_MODULE_FUZZ] = drivers;
    if (ctx->shm) ctx->shm->stats.total_drivers = count;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ, "total drivers: %u", count);
    return count > 0 ? ABYSS_OK : ABYSS_ERR_FUZZ;
}

static uint32_t probe_ioctl_ids(int fd, uint32_t *ids, uint32_t max) {
    uint32_t found = 0;
    static const uint32_t common_cmds[] = {
        0x00000000, 0x00000001, 0x00000002, 0x00000003,
        0x80000000, 0x80000001, 0x80000002,
        0xC0000000, 0xC0000001, 0xC0000002,
        0x40000000, 0x40000001, 0x40000002,
        0x10000000, 0x10000001, 0x20000000,
        0x5400, 0x5401, 0x5402, 0x5403, 0x5404, 0x540B,
        0x5410, 0x5411, 0x5412, 0x5413, 0x5414, 0x5415,
        0x5416, 0x5417, 0x5418, 0x5419, 0x541A, 0x541B,
        0x5600, 0x5601, 0x5602, 0x5603, 0x5604, 0x5605,
        0x8901, 0x8902, 0x8903, 0x8904, 0x8905, 0x8906,
        0x8907, 0x8908, 0x8909, 0x890A, 0x890B, 0x890C,
        0x890D, 0x890E, 0x890F, 0x8910, 0x8911, 0x8912,
        0x8913, 0x8914, 0x8915, 0x8916, 0x8917, 0x8918,
    };
    for (size_t i = 0; i < sizeof(common_cmds)/sizeof(common_cmds[0]) && found < max; i++) {
        uint8_t buf[64] = {0};
        errno = 0;
        int r = ioctl(fd, (unsigned long)common_cmds[i], buf);
        if (r != -1 || errno == EFAULT || errno == EPERM || errno == EACCES) {
            ids[found++] = common_cmds[i];
        }
    }
    return found;
}

int abyss_fuzz_scan_ioctls(abyss_context_t *ctx, abyss_driver_t *d) {
    if (!ctx || !d) return ABYSS_ERR;
    if (d->ioctl_count > 0) return ABYSS_OK;
    int fd = open(d->path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return ABYSS_ERR_IO;
    uint32_t ids[FUZZ_MAX_IOCTLS];
    uint32_t n = probe_ioctl_ids(fd, ids, FUZZ_MAX_IOCTLS);
    close(fd);
    if (n == 0) {
        abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_FUZZ,
                  "%s: no ioctls responded", d->name);
        return ABYSS_ERR_FUZZ;
    }
    memcpy(d->ioctl_ids, ids, n * sizeof(uint32_t));
    d->ioctl_count = n;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
              "%s: %u ioctl candidates", d->name, n);
    return ABYSS_OK;
}

int abyss_fuzz_mutate(abyss_context_t *ctx, uint8_t *buf, size_t size, uint32_t seed) {
    if (!ctx || !buf || size == 0) return ABYSS_ERR;
    uint32_t s = seed ? seed : 1;
    uint32_t ops = 1 + (s % 4);
    for (uint32_t i = 0; i < ops; i++) {
        s = s * 1103515245u + 12345u;
        uint32_t kind = (s >> 16) % 4;
        s = s * 1103515245u + 12345u;
        size_t pos = s % size;
        s = s * 1103515245u + 12345u;
        switch (kind) {
            case 0:
                buf[pos] ^= (uint8_t)(s >> 24);
                break;
            case 1:
                buf[pos] = (uint8_t)(s >> 24);
                break;
            case 2:
                if (pos + 1 < size) buf[pos] = buf[pos + 1];
                break;
            case 3:
                if (pos + 4 < size) {
                    uint32_t v = s;
                    memcpy(buf + pos, &v, 4);
                }
                break;
        }
    }
    return ABYSS_OK;
}

static void install_sandbox(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
    rl.rlim_cur = 256 * 1024;
    rl.rlim_max = 256 * 1024;
    setrlimit(RLIMIT_AS, &rl);
    rl.rlim_cur = 4 * 1024 * 1024;
    rl.rlim_max = 4 * 1024 * 1024;
    setrlimit(RLIMIT_FSIZE, &rl);
    rl.rlim_cur = 1;
    rl.rlim_max = 1;
    setrlimit(RLIMIT_CPU, &rl);
    rl.rlim_cur = 64;
    rl.rlim_max = 64;
    setrlimit(RLIMIT_NOFILE, &rl);
    signal(SIGPIPE, SIG_IGN);
}

int abyss_fuzz_execute(abyss_context_t *ctx, abyss_driver_t *d,
                       uint32_t ioctl_id, const uint8_t *buf, size_t size) {
    if (!ctx || !d || !buf) return ABYSS_ERR;
    pid_t pid = fork();
    if (pid < 0) return ABYSS_ERR;
    if (pid == 0) {
        install_sandbox();
        int fd = open(d->path, O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) _exit(2);
        uint8_t tmp[4096];
        size_t n = size < sizeof(tmp) ? size : sizeof(tmp);
        memcpy(tmp, buf, n);
        ioctl(fd, (unsigned long)ioctl_id, tmp);
        close(fd);
        _exit(0);
    }
    int status = 0;
    uint32_t timeout = ctx->config.fuzz_timeout_ms ? ctx->config.fuzz_timeout_ms : FUZZ_DEFAULT_TIMEOUT_MS;
    uint32_t elapsed = 0;
    while (elapsed < timeout) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            return abyss_fuzz_detect_crash(ctx, pid, status) == ABYSS_OK
                   ? ABYSS_OK : ABYSS_ERR_FUZZ;
        }
        if (r < 0) return ABYSS_ERR;
        usleep(10000);
        elapsed += 10;
    }
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_FUZZ,
              "%s ioctl 0x%x: timeout", d->name, ioctl_id);
    return ABYSS_ERR_FUZZ;
}

int abyss_fuzz_detect_crash(abyss_context_t *ctx, pid_t child, int status) {
    if (!ctx) return ABYSS_ERR;
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        if (sig == SIGKILL) return ABYSS_ERR;
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
                  "child %d killed by signal %d (%s)", child, sig, strsignal(sig));
        return ABYSS_OK;
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) return ABYSS_ERR;
        if (code == 2) return ABYSS_ERR;
        return ABYSS_OK;
    }
    return ABYSS_ERR;
}

int abyss_fuzz_report_crash(abyss_context_t *ctx, abyss_driver_t *d,
                            uint32_t ioctl_id, uint32_t severity) {
    if (!ctx || !d) return ABYSS_ERR;
    abyss_finding_t f;
    memset(&f, 0, sizeof(f));
    static uint32_t next_id = 1;
    f.id = next_id++;
    snprintf(f.name, sizeof(f.name), "ioctl-crash-%s", d->name);
    f.state = ABYSS_MODULE_FUZZ;
    f.severity = severity;
    f.timestamp = abyss_time_ms();
    snprintf(f.detail, sizeof(f.detail),
             "driver=%s ioctl=0x%x path=%s", d->name, ioctl_id, d->path);
    abyss_shm_push_finding(ctx, &f);
    if (ctx->shm) __atomic_fetch_add(&ctx->shm->stats.total_crashes, 1, __ATOMIC_RELAXED);
    d->crash_count++;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
              "crash reported: %s ioctl=0x%x", d->name, ioctl_id);
    return ABYSS_OK;
}

int abyss_fuzz_run(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    abyss_driver_t *drivers = (abyss_driver_t *)ctx->module_data[ABYSS_MODULE_FUZZ];
    if (!drivers) {
        if (abyss_fuzz_scan_drivers(ctx) != ABYSS_OK) return ABYSS_ERR_FUZZ;
        drivers = (abyss_driver_t *)ctx->module_data[ABYSS_MODULE_FUZZ];
    }
    uint32_t iterations = ctx->config.fuzz_iterations ? ctx->config.fuzz_iterations : FUZZ_DEFAULT_ITER;
    uint32_t total_crashes = 0;
    for (uint32_t i = 0; i < FUZZ_MAX_DRIVERS; i++) {
        abyss_driver_t *d = &drivers[i];
        if (!d->path[0]) continue;
        if (abyss_fuzz_scan_ioctls(ctx, d) != ABYSS_OK) continue;
        uint32_t local_crashes = 0;
        for (uint32_t j = 0; j < d->ioctl_count; j++) {
            for (uint32_t k = 0; k < iterations; k++) {
                uint8_t buf[512];
                memset(buf, 0, sizeof(buf));
                size_t sz = 64 + (k % 448);
                uint32_t seed = (uint32_t)(abyss_time_us() ^ (i << 16) ^ (j << 8) ^ k);
                abyss_fuzz_mutate(ctx, buf, sz, seed);
                int r = abyss_fuzz_execute(ctx, d, d->ioctl_ids[j], buf, sz);
                if (r == ABYSS_OK) {
                    abyss_fuzz_report_crash(ctx, d, d->ioctl_ids[j],
                                            ABYSS_SEVERITY_HIGH);
                    local_crashes++;
                    if (local_crashes > 8) break;
                }
            }
            if (local_crashes > 8) break;
        }
        total_crashes += local_crashes;
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
                  "%s: %u ioctls, %u crashes", d->name, d->ioctl_count, local_crashes);
    }
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
              "fuzz done: %u total crashes", total_crashes);
    return ABYSS_OK;
}

int abyss_fuzz_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    ctx->module_data[ABYSS_MODULE_FUZZ] = NULL;
    if (!ctx->config.fuzz_iterations) ctx->config.fuzz_iterations = FUZZ_DEFAULT_ITER;
    if (!ctx->config.fuzz_timeout_ms) ctx->config.fuzz_timeout_ms = FUZZ_DEFAULT_TIMEOUT_MS;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ,
              "fuzz module init: iter=%u timeout=%ums",
              ctx->config.fuzz_iterations, ctx->config.fuzz_timeout_ms);
    return ABYSS_OK;
}

int abyss_fuzz_stop(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    abyss_driver_t *drivers = (abyss_driver_t *)ctx->module_data[ABYSS_MODULE_FUZZ];
    if (drivers) {
        free(drivers);
        ctx->module_data[ABYSS_MODULE_FUZZ] = NULL;
    }
    return ABYSS_OK;
}

void abyss_fuzz_free(abyss_context_t *ctx) {
    abyss_fuzz_stop(ctx);
}