#include "abyss.h"
#include <stdarg.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

abyss_context_t *g_abyss = NULL;

int abyss_shm_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    size_t size = sizeof(abyss_shm_t) + sizeof(abyss_log_t);
    char path[ABYSS_PATH_MAX];
    snprintf(path, sizeof(path), "/dev/shm/%s", ctx->config.shm_name);
    ctx->shm_fd = open(path, O_RDWR | O_CREAT, 0600);
    if (ctx->shm_fd < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_IPC, "shm open failed: %s", strerror(errno));
        return ABYSS_ERR_IPC;
    }
    if (ftruncate(ctx->shm_fd, size) < 0) {
        close(ctx->shm_fd);
        return ABYSS_ERR_IPC;
    }
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, ctx->shm_fd, 0);
    if (mem == MAP_FAILED) {
        close(ctx->shm_fd);
        return ABYSS_ERR_IPC;
    }
    ctx->shm = (abyss_shm_t *)mem;
    ctx->log = (abyss_log_t *)((uint8_t *)mem + sizeof(abyss_shm_t));
    memset(ctx->shm, 0, sizeof(abyss_shm_t));
    memset(ctx->log, 0, sizeof(abyss_log_t));
    ctx->shm->magic = 0xABAD0BEE;
    ctx->shm->version = 1;
    ctx->shm->state = ABYSS_STATE_IDLE;
    ctx->log->magic = 0xABAD1066;
    ctx->log->capacity = 4096;
    ctx->shm->stats.start_time = time(NULL);
    for (uint32_t i = 0; i < ABYSS_MODULE_MAX; i++) {
        ctx->shm->heartbeat[i] = abyss_time_ms();
    }
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_IPC, "shm initialized: %zu bytes at %p", size, (void*)ctx->shm);
    return ABYSS_OK;
}

void abyss_shm_free(abyss_context_t *ctx) {
    if (!ctx || !ctx->shm) return;
    size_t size = sizeof(abyss_shm_t) + sizeof(abyss_log_t);
    munmap(ctx->shm, size);
    if (ctx->shm_fd >= 0) close(ctx->shm_fd);
    ctx->shm = NULL;
    ctx->log = NULL;
}

int abyss_shm_push_event(abyss_context_t *ctx, const void *event, size_t size) {
    if (!ctx || !ctx->shm || !event) return ABYSS_ERR;
    if (size > sizeof(abyss_msr_event_t)) return ABYSS_ERR;
    uint32_t head = __atomic_load_n(&ctx->shm->event_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&ctx->shm->event_tail, __ATOMIC_RELAXED);
    uint32_t next = (head + 1) % 2048;
    if (next == tail) {
        abyss_log(ctx, ABYSS_LOG_WARN, ABYSS_MODULE_IPC, "event ring full, drop");
        return ABYSS_ERR;
    }
    memcpy(&ctx->shm->msr_events[head], event, size);
    __atomic_store_n(&ctx->shm->event_head, next, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ctx->shm->stats.total_events, 1, __ATOMIC_RELAXED);
    return ABYSS_OK;
}

int abyss_shm_push_finding(abyss_context_t *ctx, const abyss_finding_t *f) {
    if (!ctx || !ctx->shm || !f) return ABYSS_ERR;
    uint32_t head = __atomic_load_n(&ctx->shm->finding_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&ctx->shm->finding_tail, __ATOMIC_RELAXED);
    uint32_t next = (head + 1) % 2048;
    if (next == tail) {
        abyss_log(ctx, ABYSS_LOG_WARN, ABYSS_MODULE_IPC, "finding ring full, drop");
        return ABYSS_ERR;
    }
    memcpy(&ctx->shm->findings[head], f, sizeof(abyss_finding_t));
    __atomic_store_n(&ctx->shm->finding_head, next, __ATOMIC_RELEASE);
    __atomic_fetch_add(&ctx->shm->stats.total_findings, 1, __ATOMIC_RELAXED);
    return ABYSS_OK;
}

int abyss_shm_pop_finding(abyss_context_t *ctx, abyss_finding_t *f) {
    if (!ctx || !ctx->shm || !f) return ABYSS_ERR;
    uint32_t head = __atomic_load_n(&ctx->shm->finding_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&ctx->shm->finding_tail, __ATOMIC_RELAXED);
    if (head == tail) return ABYSS_ERR;
    memcpy(f, &ctx->shm->findings[tail], sizeof(abyss_finding_t));
    __atomic_store_n(&ctx->shm->finding_tail, (tail + 1) % 2048, __ATOMIC_RELEASE);
    return ABYSS_OK;
}

int abyss_shm_update_stats(abyss_context_t *ctx) {
    if (!ctx || !ctx->shm) return ABYSS_ERR;
    __atomic_fetch_add(&ctx->shm->stats.total_crashes, 0, __ATOMIC_RELAXED);
    ctx->shm->stats.end_time = time(NULL);
    ctx->shm->heartbeat[ABYSS_MODULE_IPC] = abyss_time_ms();
    return ABYSS_OK;
}

static int make_unix_socket(const char *name, int server) {
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/abyss_%s.sock", name);
    if (server) {
        unlink(addr.sun_path);
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
        chmod(addr.sun_path, 0600);
    }
    return fd;
}

int abyss_channel_open(abyss_context_t *ctx, uint32_t module) {
    if (!ctx || module >= ABYSS_MODULE_MAX) return ABYSS_ERR;
    char name[ABYSS_NAME_MAX];
    snprintf(name, sizeof(name), "mod%u", module);
    int fd = make_unix_socket(name, 1);
    if (fd < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_IPC, "channel open failed for mod%u: %s", module, strerror(errno));
        return ABYSS_ERR_IPC;
    }
    ctx->module_data[module] = (void *)(intptr_t)fd;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_IPC, "channel opened for mod%u fd=%d", module, fd);
    return ABYSS_OK;
}

int abyss_channel_send(abyss_context_t *ctx, uint32_t module, const void *msg, size_t size) {
    if (!ctx || !msg || module >= ABYSS_MODULE_MAX) return ABYSS_ERR;
    int fd = (int)(intptr_t)ctx->module_data[module];
    if (fd < 0) return ABYSS_ERR;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/abyss_mod%u.sock", module);
    ssize_t n = sendto(fd, msg, size, 0, (struct sockaddr*)&addr, sizeof(addr));
    if (n < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_IPC, "send to mod%u failed: %s", module, strerror(errno));
        return ABYSS_ERR_IPC;
    }
    return ABYSS_OK;
}

int abyss_channel_recv(abyss_context_t *ctx, uint32_t module, void *msg, size_t size) {
    if (!ctx || !msg || module >= ABYSS_MODULE_MAX) return ABYSS_ERR;
    int fd = (int)(intptr_t)ctx->module_data[module];
    if (fd < 0) return ABYSS_ERR;
    ssize_t n = recv(fd, msg, size, MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return ABYSS_ERR;
        return ABYSS_ERR_IPC;
    }
    return (int)n;
}

int abyss_log_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    if (!ctx->log) {
        if (abyss_shm_init(ctx) < 0) return ABYSS_ERR_IPC;
    }
    ctx->log->write_idx = 0;
    ctx->log->read_idx = 0;
    return ABYSS_OK;
}

void abyss_log_free(abyss_context_t *ctx) {
    if (!ctx) return;
    abyss_log_flush(ctx);
}

const char *abyss_log_level_str(uint32_t level) {
    switch (level) {
        case ABYSS_LOG_DEBUG: return "DEBUG";
        case ABYSS_LOG_INFO:  return "INFO";
        case ABYSS_LOG_WARN:  return "WARN";
        case ABYSS_LOG_ERROR: return "ERROR";
        case ABYSS_LOG_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

void abyss_log(abyss_context_t *ctx, uint32_t level, uint32_t module, const char *fmt, ...) {
    if (!ctx || !ctx->log || !fmt) return;
    if (level < ABYSS_LOG_INFO && !ctx->config.verbose) return;
    uint32_t idx = __atomic_fetch_add(&ctx->log->write_idx, 1, __ATOMIC_RELAXED) % ctx->log->capacity;
    abyss_log_entry_t *e = &ctx->log->entries[idx];
    e->level = level;
    e->module = module;
    e->timestamp = abyss_time_ms();
    e->pid = getpid();
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->message, sizeof(e->message), fmt, ap);
    va_end(ap);
    if (!ctx->config.no_color && isatty(STDERR_FILENO)) {
        const char *color = "";
        switch (level) {
            case ABYSS_LOG_DEBUG: color = "\033[36m"; break;
            case ABYSS_LOG_INFO:  color = "\033[32m"; break;
            case ABYSS_LOG_WARN:  color = "\033[33m"; break;
            case ABYSS_LOG_ERROR: color = "\033[31m"; break;
            case ABYSS_LOG_FATAL: color = "\033[35m"; break;
        }
        fprintf(stderr, "%s[%s] [mod%u] %s\033[0m\n", color, abyss_log_level_str(level), module, e->message);
    } else {
        fprintf(stderr, "[%s] [mod%u] %s\n", abyss_log_level_str(level), module, e->message);
    }
    if (level >= ABYSS_LOG_FATAL) {
        abyss_log_flush(ctx);
        abort();
    }
}

int abyss_log_flush(abyss_context_t *ctx) {
    if (!ctx || !ctx->log || !ctx->config.log_path[0]) return ABYSS_OK;
    FILE *f = fopen(ctx->config.log_path, "a");
    if (!f) return ABYSS_ERR_IO;
    uint32_t write_idx = __atomic_load_n(&ctx->log->write_idx, __ATOMIC_ACQUIRE);
    uint32_t read_idx = ctx->log->read_idx;
    while (read_idx != write_idx) {
        abyss_log_entry_t *e = &ctx->log->entries[read_idx % ctx->log->capacity];
        fprintf(f, "%llu [%s] [mod%u] [pid=%u] %s\n",
                (unsigned long long)e->timestamp,
                abyss_log_level_str(e->level),
                e->module, e->pid, e->message);
        read_idx++;
    }
    ctx->log->read_idx = write_idx;
    fclose(f);
    return ABYSS_OK;
}