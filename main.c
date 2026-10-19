#include "abyss.h"
#include <getopt.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>

static void print_banner(void) {
    fprintf(stderr,
        "\033[31m"
        "    ___    ____  __  __ _____ _____\n"
        "   /   |  / __ )/ / / // ___// ___/\n"
        "  / /| | / __  / /_/ /\\__ \\\\__ \\\n"
        " / ___ |/ /_/ / __  /___/ /___/ /\n"
        "/_/  |_/_____/_/ /_//____//____/\n"
        "\033[0m"
        "     abyss v%s -- hellfire toolkit\n"
        "     \"The gates of hell are open.\"\n\n",
        ABYSS_VERSION);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -h, --help              show this help\n"
        "  -v, --verbose           verbose logging\n"
        "  -c, --config FILE       load config file\n"
        "  -o, --output DIR        output directory (default ./abyss_report)\n"
        "  -f, --format FMT        report format: json,html (default json,html)\n"
        "  -l, --log FILE          log file path\n"
        "  -n, --no-color          disable colored output\n"
        "  -d, --daemon            run in background\n"
        "      --hyper             enable hypervisor module\n"
        "      --acpi              enable acpi module\n"
        "      --fuzz              enable fuzzer module\n"
        "      --all               enable all modules\n"
        "      --iter N            fuzz iterations per ioctl (default 1000)\n"
        "      --timeout MS        fuzz child timeout ms (default 2000)\n"
        "      --mutations N       acpi mutations per table (default 4)\n"
        "      --shm NAME          shared memory name (default abyss_shm)\n",
        prog);
}

uint64_t abyss_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

uint64_t abyss_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
}

uint32_t abyss_rand_seed(void) {
    return (uint32_t)(abyss_time_us() ^ (uint64_t)getpid());
}

uint32_t abyss_rand_next(uint32_t *state) {
    if (!state) return 0;
    *state = *state * 1103515245u + 12345u;
    return *state;
}

uint32_t abyss_crc32(const void *data, size_t len) {
    if (!data) return 0;
    const uint8_t *p = (const uint8_t *)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        c ^= p[i];
        for (int j = 0; j < 8; j++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
    }
    return c ^ 0xFFFFFFFFu;
}

int abyss_file_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int abyss_dir_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

int abyss_mkdir_p(const char *path) {
    if (!path || !*path) return ABYSS_ERR;
    char tmp[ABYSS_PATH_MAX * 2];
    size_t len = strlen(path);
    if (len >= sizeof(tmp)) return ABYSS_ERR;
    memcpy(tmp, path, len + 1);
    if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return ABYSS_ERR;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return ABYSS_ERR;
    return ABYSS_OK;
}

ssize_t abyss_read_file(const char *path, void *buf, size_t size) {
    if (!path || !buf || size == 0) return ABYSS_ERR;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return ABYSS_ERR_IO;
    size_t total = 0;
    while (total < size) {
        ssize_t n = read(fd, (uint8_t *)buf + total, size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return ABYSS_ERR_IO;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    close(fd);
    return (ssize_t)total;
}

ssize_t abyss_write_file(const char *path, const void *buf, size_t size) {
    if (!path || !buf) return ABYSS_ERR;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return ABYSS_ERR_IO;
    size_t total = 0;
    while (total < size) {
        ssize_t n = write(fd, (const uint8_t *)buf + total, size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return ABYSS_ERR_IO;
        }
        total += (size_t)n;
    }
    close(fd);
    return (ssize_t)total;
}

static int parse_format(const char *s) {
    if (!s) return ABYSS_ERR;
    int ok = 0;
    if (strstr(s, "json")) ok |= 1;
    if (strstr(s, "html")) ok |= 2;
    return ok ? ok : ABYSS_ERR;
}

int abyss_parse_args(abyss_context_t *ctx, int argc, char **argv) {
    if (!ctx) return ABYSS_ERR;
    static struct option long_opts[] = {
        {"help",      no_argument,       0, 'h'},
        {"verbose",   no_argument,       0, 'v'},
        {"config",    required_argument, 0, 'c'},
        {"output",    required_argument, 0, 'o'},
        {"format",    required_argument, 0, 'f'},
        {"log",       required_argument, 0, 'l'},
        {"no-color",  no_argument,       0, 'n'},
        {"daemon",    no_argument,       0, 'd'},
        {"hyper",     no_argument,       0, 1000},
        {"acpi",      no_argument,       0, 1001},
        {"fuzz",      no_argument,       0, 1002},
        {"all",       no_argument,       0, 1003},
        {"iter",      required_argument, 0, 1004},
        {"timeout",   required_argument, 0, 1005},
        {"mutations", required_argument, 0, 1006},
        {"shm",       required_argument, 0, 1007},
        {0, 0, 0, 0}
    };
    int c;
    while ((c = getopt_long(argc, argv, "hvc:o:f:l:nd", long_opts, NULL)) != -1) {
        switch (c) {
            case 'h': print_usage(argv[0]); exit(0);
            case 'v': ctx->config.verbose = 1; break;
            case 'c': abyss_load_config(ctx, optarg); break;
            case 'o':
                snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "%s", optarg);
                break;
            case 'f':
                if (parse_format(optarg) < 0) {
                    fprintf(stderr, "invalid format: %s\n", optarg);
                    return ABYSS_ERR;
                }
                snprintf(ctx->config.report_format, sizeof(ctx->config.report_format), "%s", optarg);
                break;
            case 'l':
                snprintf(ctx->config.log_path, sizeof(ctx->config.log_path), "%s", optarg);
                break;
            case 'n': ctx->config.no_color = 1; break;
            case 'd': ctx->config.daemon = 1; break;
            case 1000: ctx->config.hyper_enabled = 1; break;
            case 1001: ctx->config.acpi_enabled = 1; break;
            case 1002: ctx->config.fuzz_enabled = 1; break;
            case 1003:
                ctx->config.hyper_enabled = 1;
                ctx->config.acpi_enabled = 1;
                ctx->config.fuzz_enabled = 1;
                ctx->config.report_enabled = 1;
                break;
            case 1004: ctx->config.fuzz_iterations = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 1005: ctx->config.fuzz_timeout_ms = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 1006: ctx->config.acpi_mutations = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 1007:
                snprintf(ctx->config.shm_name, sizeof(ctx->config.shm_name), "%s", optarg);
                break;
            default:
                print_usage(argv[0]);
                return ABYSS_ERR;
        }
    }
    return ABYSS_OK;
}

int abyss_load_config(abyss_context_t *ctx, const char *path) {
    if (!ctx || !path) return ABYSS_ERR;
    FILE *f = fopen(path, "r");
    if (!f) return ABYSS_ERR_IO;
    char line[ABYSS_PATH_MAX * 2];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#' || *p == '\0') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p;
        char *val = eq + 1;
        while (*key && isspace((unsigned char)key[strlen(key)-1])) key[strlen(key)-1] = '\0';
        while (*val && isspace((unsigned char)*val)) val++;
        char *end = val + strlen(val);
        while (end > val && isspace((unsigned char)end[-1])) *--end = '\0';
        if (strcmp(key, "output_dir") == 0)
            snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "%s", val);
        else if (strcmp(key, "report_format") == 0)
            snprintf(ctx->config.report_format, sizeof(ctx->config.report_format), "%s", val);
        else if (strcmp(key, "log_path") == 0)
            snprintf(ctx->config.log_path, sizeof(ctx->config.log_path), "%s", val);
        else if (strcmp(key, "shm_name") == 0)
            snprintf(ctx->config.shm_name, sizeof(ctx->config.shm_name), "%s", val);
        else if (strcmp(key, "fuzz_iterations") == 0)
            ctx->config.fuzz_iterations = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "fuzz_timeout_ms") == 0)
            ctx->config.fuzz_timeout_ms = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "acpi_mutations") == 0)
            ctx->config.acpi_mutations = (uint32_t)strtoul(val, NULL, 10);
        else if (strcmp(key, "verbose") == 0)
            ctx->config.verbose = atoi(val);
        else if (strcmp(key, "hyper") == 0)
            ctx->config.hyper_enabled = atoi(val);
        else if (strcmp(key, "acpi") == 0)
            ctx->config.acpi_enabled = atoi(val);
        else if (strcmp(key, "fuzz") == 0)
            ctx->config.fuzz_enabled = atoi(val);
        else if (strcmp(key, "report") == 0)
            ctx->config.report_enabled = atoi(val);
    }
    fclose(f);
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_IPC, "config loaded: %s", path);
    return ABYSS_OK;
}

int abyss_save_config(abyss_context_t *ctx, const char *path) {
    if (!ctx || !path) return ABYSS_ERR;
    FILE *f = fopen(path, "w");
    if (!f) return ABYSS_ERR_IO;
    fprintf(f, "output_dir=%s\n", ctx->config.output_dir);
    fprintf(f, "report_format=%s\n", ctx->config.report_format);
    fprintf(f, "log_path=%s\n", ctx->config.log_path);
    fprintf(f, "shm_name=%s\n", ctx->config.shm_name);
    fprintf(f, "fuzz_iterations=%u\n", ctx->config.fuzz_iterations);
    fprintf(f, "fuzz_timeout_ms=%u\n", ctx->config.fuzz_timeout_ms);
    fprintf(f, "acpi_mutations=%u\n", ctx->config.acpi_mutations);
    fprintf(f, "verbose=%d\n", ctx->config.verbose);
    fprintf(f, "hyper=%d\n", ctx->config.hyper_enabled);
    fprintf(f, "acpi=%d\n", ctx->config.acpi_enabled);
    fprintf(f, "fuzz=%d\n", ctx->config.fuzz_enabled);
    fprintf(f, "report=%d\n", ctx->config.report_enabled);
    fclose(f);
    return ABYSS_OK;
}

static void fill_defaults(abyss_context_t *ctx) {
    memset(&ctx->config, 0, sizeof(ctx->config));
    snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "./abyss_report");
    snprintf(ctx->config.report_format, sizeof(ctx->config.report_format), "json,html");
    snprintf(ctx->config.shm_name, sizeof(ctx->config.shm_name), "abyss_shm");
    ctx->config.fuzz_iterations = 1000;
    ctx->config.fuzz_timeout_ms = 2000;
    ctx->config.acpi_mutations = 4;
    ctx->config.report_enabled = 1;
    ctx->config.verbose = 0;
    ctx->config.no_color = 0;
    ctx->config.daemon = 0;
}

static void register_modules(abyss_context_t *ctx) {
    ctx->module_init[ABYSS_MODULE_HYPER]  = abyss_hyper_init;
    ctx->module_run[ABYSS_MODULE_HYPER]   = abyss_hyper_run;
    ctx->module_stop[ABYSS_MODULE_HYPER]  = abyss_hyper_stop;
    ctx->module_free[ABYSS_MODULE_HYPER]  = abyss_hyper_free;
    ctx->module_init[ABYSS_MODULE_ACPI]   = abyss_acpi_init;
    ctx->module_run[ABYSS_MODULE_ACPI]    = abyss_acpi_run;
    ctx->module_stop[ABYSS_MODULE_ACPI]   = abyss_acpi_stop;
    ctx->module_free[ABYSS_MODULE_ACPI]   = abyss_acpi_free;
    ctx->module_init[ABYSS_MODULE_FUZZ]   = abyss_fuzz_init;
    ctx->module_run[ABYSS_MODULE_FUZZ]    = abyss_fuzz_run;
    ctx->module_stop[ABYSS_MODULE_FUZZ]   = abyss_fuzz_stop;
    ctx->module_free[ABYSS_MODULE_FUZZ]   = abyss_fuzz_free;
    ctx->module_init[ABYSS_MODULE_REPORT] = abyss_report_init;
    ctx->module_run[ABYSS_MODULE_REPORT]  = abyss_report_run;
    ctx->module_stop[ABYSS_MODULE_REPORT] = abyss_report_stop;
    ctx->module_free[ABYSS_MODULE_REPORT] = abyss_report_free;
}

int abyss_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    if (ctx->magic == 0xABAD0BEE) return ABYSS_OK;
    g_abyss = ctx;
    if (abyss_shm_init(ctx) != ABYSS_OK) return ABYSS_ERR_IPC;
    if (abyss_log_init(ctx) != ABYSS_OK) {
        abyss_shm_free(ctx);
        return ABYSS_ERR_IPC;
    }
    register_modules(ctx);
    ctx->state = ABYSS_STATE_IDLE;
    ctx->magic = 0xABAD0BEE;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_IPC, "abyss initialized");
    return ABYSS_OK;
}

int abyss_run(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    ctx->state = ABYSS_STATE_RUNNING;
    if (ctx->shm) ctx->shm->state = ABYSS_STATE_RUNNING;
    if (ctx->config.hyper_enabled && ctx->module_run[ABYSS_MODULE_HYPER]) {
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER, "starting hypervisor");
        ctx->module_run[ABYSS_MODULE_HYPER](ctx);
    }
    if (ctx->config.acpi_enabled && ctx->module_run[ABYSS_MODULE_ACPI]) {
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI, "starting acpi engine");
        ctx->module_run[ABYSS_MODULE_ACPI](ctx);
    }
    if (ctx->config.fuzz_enabled && ctx->module_run[ABYSS_MODULE_FUZZ]) {
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_FUZZ, "starting fuzzer");
        ctx->module_run[ABYSS_MODULE_FUZZ](ctx);
    }
    if (ctx->config.report_enabled && ctx->module_run[ABYSS_MODULE_REPORT]) {
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_REPORT, "starting report");
        ctx->module_run[ABYSS_MODULE_REPORT](ctx);
    }
    ctx->state = ABYSS_STATE_STOPPED;
    if (ctx->shm) ctx->shm->state = ABYSS_STATE_STOPPED;
    return ABYSS_OK;
}

int abyss_stop(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    ctx->state = ABYSS_STATE_STOPPED;
    for (int i = ABYSS_MODULE_MAX - 1; i >= 0; i--) {
        if (ctx->module_stop[i]) {
            abyss_log(ctx, ABYSS_LOG_DEBUG, (uint32_t)i, "stopping module");
            ctx->module_stop[i](ctx);
        }
    }
    if (ctx->shm) {
        abyss_shm_update_stats(ctx);
        ctx->shm->state = ABYSS_STATE_STOPPED;
    }
    abyss_log_flush(ctx);
    return ABYSS_OK;
}

void abyss_free(abyss_context_t *ctx) {
    if (!ctx) return;
    for (int i = ABYSS_MODULE_MAX - 1; i >= 0; i--) {
        if (ctx->module_free[i]) ctx->module_free[i](ctx);
    }
    abyss_log_free(ctx);
    abyss_shm_free(ctx);
    ctx->magic = 0;
    g_abyss = NULL;
}

static int daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) return ABYSS_ERR;
    if (pid > 0) _exit(0);
    if (setsid() < 0) return ABYSS_ERR;
    pid = fork();
    if (pid < 0) return ABYSS_ERR;
    if (pid > 0) _exit(0);
    umask(077);
    if (chdir("/") < 0) return ABYSS_ERR;
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
    return ABYSS_OK;
}

int main(int argc, char **argv) {
    abyss_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    fill_defaults(&ctx);
    print_banner();
    if (abyss_parse_args(&ctx, argc, argv) != ABYSS_OK) {
        print_usage(argv[0]);
        return 1;
    }
    if (ctx.config.daemon) {
        if (daemonize() != ABYSS_OK) {
            fprintf(stderr, "daemonize failed: %s\n", strerror(errno));
            return 1;
        }
    }
    if (!abyss_file_exists(argv[0])) {
        /* argv[0] may be relative; ignore */
    }
    if (abyss_init(&ctx) != ABYSS_OK) {
        fprintf(stderr, "abyss_init failed\n");
        return 1;
    }
    abyss_log(&ctx, ABYSS_LOG_INFO, ABYSS_MODULE_IPC,
              "modules: hyper=%d acpi=%d fuzz=%d report=%d",
              ctx.config.hyper_enabled, ctx.config.acpi_enabled,
              ctx.config.fuzz_enabled, ctx.config.report_enabled);
    if (abyss_run(&ctx) != ABYSS_OK) {
        abyss_log(&ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_IPC, "abyss_run failed");
    }
    abyss_stop(&ctx);
    abyss_free(&ctx);
    fprintf(stderr, "\033[35m[abyss] all hells closed. goodbye.\033[0m\n");
    return 0;
}