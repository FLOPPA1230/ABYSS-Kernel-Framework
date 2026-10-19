#include "abyss.h"
#include <dirent.h>
#include <sys/stat.h>
#include <ctype.h>

#define ACPI_SIG_RSDP "RSD PTR "
#define ACPI_SIG_DSDT "DSDT"
#define ACPI_SIG_SSDT "SSDT"
#define ACPI_SIG_FACP "FACP"
#define ACPI_MAX_TABLES 64
#define ACPI_HEADER_LEN 36
#define ACPI_MAX_TABLE_SIZE (16 * 1024 * 1024)

static uint8_t acpi_checksum(const uint8_t *data, uint32_t len) {
    uint8_t sum = 0;
    for (uint32_t i = 0; i < len; i++) sum += data[i];
    return sum;
}

static void safe_strcpy_field(char *dst, size_t dst_size, const uint8_t *src, size_t src_len) {
    if (!dst || dst_size == 0) return;
    memset(dst, 0, dst_size);
    size_t n = src_len < dst_size - 1 ? src_len : dst_size - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static int acpi_read_table_file(const char *path, abyss_acpi_table_t *t) {
    if (!path || !t) return ABYSS_ERR;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return ABYSS_ERR_IO;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return ABYSS_ERR_IO; }
    if (!S_ISREG(st.st_mode)) { close(fd); return ABYSS_ERR_IO; }
    if (st.st_size < ACPI_HEADER_LEN || st.st_size > ACPI_MAX_TABLE_SIZE) {
        close(fd);
        return ABYSS_ERR_IO;
    }
    size_t file_size = (size_t)st.st_size;
    uint8_t *buf = malloc(file_size);
    if (!buf) { close(fd); return ABYSS_ERR_MEM; }
    size_t total = 0;
    while (total < file_size) {
        ssize_t n = read(fd, buf + total, file_size - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buf); close(fd);
            return ABYSS_ERR_IO;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    close(fd);
    if (total < ACPI_HEADER_LEN) { free(buf); return ABYSS_ERR_IO; }
    uint32_t declared_len = 0;
    memcpy(&declared_len, buf + 4, 4);
    if (declared_len < ACPI_HEADER_LEN || declared_len > total) {
        abyss_log(NULL, ABYSS_LOG_WARN, ABYSS_MODULE_ACPI,
                  "table %s declared len %u invalid (file %zu)", path, declared_len, total);
        free(buf);
        return ABYSS_ERR_IO;
    }
    memset(t, 0, sizeof(*t));
    t->data = buf;
    t->length = declared_len;
    memcpy(t->signature, buf, 4);
    t->signature[4] = '\0';
    t->revision = buf[8];
    t->checksum = buf[9];
    safe_strcpy_field(t->oem_id, sizeof(t->oem_id), buf + 10, 6);
    safe_strcpy_field(t->oem_table_id, sizeof(t->oem_table_id), buf + 16, 8);
    memcpy(&t->oem_revision, buf + 24, 4);
    safe_strcpy_field(t->creator_id, sizeof(t->creator_id), buf + 28, 4);
    memcpy(&t->creator_revision, buf + 32, 4);
    t->phys_addr = 0;
    t->mutated = 0;
    uint8_t cks = acpi_checksum(t->data, t->length);
    if (cks != 0) {
        abyss_log(NULL, ABYSS_LOG_WARN, ABYSS_MODULE_ACPI,
                  "table %s checksum invalid (got 0x%02x)", t->signature, cks);
    }
    return ABYSS_OK;
}

int abyss_acpi_load_tables(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    abyss_acpi_table_t *tables = calloc(ACPI_MAX_TABLES, sizeof(abyss_acpi_table_t));
    if (!tables) return ABYSS_ERR_MEM;
    const char *base = "/sys/firmware/acpi/tables";
    DIR *d = opendir(base);
    if (!d) {
        abyss_log(ctx, ABYSS_LOG_WARN, ABYSS_MODULE_ACPI,
                  "cannot open %s (kernel may not expose ACPI tables)", base);
        free(tables);
        return ABYSS_ERR_ACPI;
    }
    struct dirent *de;
    uint32_t count = 0;
    while ((de = readdir(d)) != NULL && count < ACPI_MAX_TABLES) {
        if (de->d_name[0] == '.') continue;
        char path[ABYSS_PATH_MAX * 2];
        int n = snprintf(path, sizeof(path), "%s/%s", base, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) continue;
        if (acpi_read_table_file(path, &tables[count]) == ABYSS_OK) {
            abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI,
                      "loaded %s rev=%u len=%u oem=%s",
                      tables[count].signature, tables[count].revision,
                      tables[count].length, tables[count].oem_id);
            count++;
        }
    }
    closedir(d);
    ctx->module_data[ABYSS_MODULE_ACPI] = tables;
    if (ctx->shm) ctx->shm->stats.total_acpi_tables = count;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI, "total ACPI tables loaded: %u", count);
    return count > 0 ? ABYSS_OK : ABYSS_ERR_ACPI;
}

int abyss_acpi_find_table(abyss_context_t *ctx, const char *sig, abyss_acpi_table_t **out) {
    if (!ctx || !sig || !out) return ABYSS_ERR;
    abyss_acpi_table_t *tables = (abyss_acpi_table_t *)ctx->module_data[ABYSS_MODULE_ACPI];
    if (!tables) return ABYSS_ERR_ACPI;
    for (uint32_t i = 0; i < ACPI_MAX_TABLES; i++) {
        if (tables[i].data && strcmp(tables[i].signature, sig) == 0) {
            *out = &tables[i];
            return ABYSS_OK;
        }
    }
    return ABYSS_ERR_ACPI;
}

static int aml_skip_pkglen(const uint8_t *p, uint32_t len, uint32_t *off) {
    if (!p || !off || *off >= len) return -1;
    uint8_t lead = p[*off];
    uint8_t extra = (uint8_t)(lead >> 6);
    if (extra > 3) return -1;
    if (*off + 1 + extra > len) return -1;
    *off += 1 + extra;
    return 0;
}

static int aml_read_name(const uint8_t *p, uint32_t len, uint32_t *off, char out[5]) {
    if (!p || !off || !out) return -1;
    if (*off + 4 > len) return -1;
    memcpy(out, p + *off, 4);
    out[4] = '\0';
    for (int i = 0; i < 4; i++) {
        if (!isalnum((unsigned char)out[i]) && out[i] != '_') out[i] = '?';
    }
    *off += 4;
    return 0;
}

int abyss_acpi_parse_dsdt(abyss_context_t *ctx, abyss_acpi_table_t *t) {
    if (!ctx || !t || !t->data || t->length < ACPI_HEADER_LEN) return ABYSS_ERR;
    uint32_t off = ACPI_HEADER_LEN;
    uint32_t count = 0;
    while (off < t->length && count < 100000) {
        uint8_t op = t->data[off];
        if (op == 0x5B) {
            if (off + 1 >= t->length) break;
            uint8_t ext = t->data[off + 1];
            off += 2;
            char name[5];
            switch (ext) {
                case 0x80:
                    if (aml_read_name(t->data, t->length, &off, name) != 0) goto done;
                    if (aml_skip_pkglen(t->data, t->length, &off) != 0) goto done;
                    abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_ACPI, "OpRegion: %s", name);
                    break;
                case 0x88:
                    if (aml_read_name(t->data, t->length, &off, name) != 0) goto done;
                    abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_ACPI, "Field: %s", name);
                    break;
                default:
                    break;
            }
            count++;
        } else {
            switch (op) {
                case 0x08: {
                    off++;
                    char name[5];
                    if (aml_read_name(t->data, t->length, &off, name) != 0) goto done;
                    abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_ACPI, "Name: %s", name);
                    break;
                }
                case 0x14: {
                    off++;
                    char name[5];
                    if (aml_read_name(t->data, t->length, &off, name) != 0) goto done;
                    if (aml_skip_pkglen(t->data, t->length, &off) != 0) goto done;
                    abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_ACPI, "Method: %s", name);
                    break;
                }
                case 0x10:
                    off++;
                    if (aml_skip_pkglen(t->data, t->length, &off) != 0) goto done;
                    break;
                case 0x5C:
                    if (off + 4 > t->length) goto done;
                    off += 4;
                    break;
                default:
                    off++;
            }
        }
    }
done:
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI,
              "%s parsed: %u ops (off=%u/%u)", t->signature, count, off, t->length);
    return ABYSS_OK;
}

int abyss_acpi_parse_ssdt(abyss_context_t *ctx, abyss_acpi_table_t *t) {
    return abyss_acpi_parse_dsdt(ctx, t);
}

int abyss_acpi_read_thermal(abyss_context_t *ctx, uint32_t zone, int32_t *temp) {
    if (!ctx || !temp) return ABYSS_ERR;
    char path[ABYSS_PATH_MAX];
    int n = snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%u/temp", zone);
    if (n < 0 || (size_t)n >= sizeof(path)) return ABYSS_ERR;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return ABYSS_ERR_IO;
    char buf[32] = {0};
    ssize_t r = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (r <= 0) return ABYSS_ERR_IO;
    errno = 0;
    long val = strtol(buf, NULL, 10);
    if (errno != 0) return ABYSS_ERR_IO;
    if (val > 100000 || val < -100000) return ABYSS_ERR_IO;
    if (val > 1000 || val < -1000) val /= 1000;
    *temp = (int32_t)val;
    return ABYSS_OK;
}

int abyss_acpi_read_power_state(abyss_context_t *ctx, uint32_t cpu,
                                uint32_t *cstate, uint32_t *pstate) {
    if (!ctx || !cstate || !pstate) return ABYSS_ERR;
    *cstate = 0;
    *pstate = 0;
    char path[ABYSS_PATH_MAX];
    int n = snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/cpu%u/cpuidle/state0/usage", cpu);
    if (n > 0 && (size_t)n < sizeof(path)) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char buf[32] = {0};
            if (read(fd, buf, sizeof(buf) - 1) > 0) *cstate = (uint32_t)strtoul(buf, NULL, 10);
            close(fd);
        }
    }
    n = snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%u/cpufreq/scaling_cur_freq", cpu);
    if (n > 0 && (size_t)n < sizeof(path)) {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char buf[32] = {0};
            if (read(fd, buf, sizeof(buf) - 1) > 0) *pstate = (uint32_t)strtoul(buf, NULL, 10);
            close(fd);
        }
    }
    return ABYSS_OK;
}

int abyss_acpi_mutate(abyss_context_t *ctx, abyss_acpi_table_t *t, uint32_t seed) {
    if (!ctx || !t || !t->data) return ABYSS_ERR;
    if (t->length <= ACPI_HEADER_LEN + 4) return ABYSS_ERR;
    uint32_t s = seed ? seed : 1;
    uint32_t mutations = ctx->config.acpi_mutations ? ctx->config.acpi_mutations : 4;
    uint32_t span = t->length - ACPI_HEADER_LEN;
    for (uint32_t i = 0; i < mutations; i++) {
        s = s * 1103515245u + 12345u;
        uint32_t pos = ACPI_HEADER_LEN + (s % span);
        s = s * 1103515245u + 12345u;
        uint8_t val = (uint8_t)(s >> 24);
        t->data[pos] ^= val;
        abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_ACPI,
                  "mutated %s[%u] ^= 0x%02x", t->signature, pos, val);
    }
    t->data[9] = 0;
    t->data[9] = (uint8_t)(0 - acpi_checksum(t->data, t->length));
    t->mutated++;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI,
              "mutated %s (%u mutations, new checksum 0x%02x)",
              t->signature, mutations, t->data[9]);
    return ABYSS_OK;
}

int abyss_acpi_apply(abyss_context_t *ctx, abyss_acpi_table_t *t) {
    if (!ctx || !t || !t->data) return ABYSS_ERR;
    const char *dir = ctx->config.output_dir[0] ? ctx->config.output_dir : "./abyss_report";
    abyss_mkdir_p(dir);
    char path[ABYSS_PATH_MAX * 2];
    int n = snprintf(path, sizeof(path), "%s/%s.mutated", dir, t->signature);
    if (n < 0 || (size_t)n >= sizeof(path)) return ABYSS_ERR;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_ACPI,
                  "cannot write mutated table: %s", strerror(errno));
        return ABYSS_ERR_IO;
    }
    size_t total = 0;
    while (total < t->length) {
        ssize_t w = write(fd, t->data + total, t->length - total);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return ABYSS_ERR_IO;
        }
        total += (size_t)w;
    }
    close(fd);
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI,
              "mutated %s saved to %s", t->signature, path);
    return ABYSS_OK;
}

int abyss_acpi_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    ctx->module_data[ABYSS_MODULE_ACPI] = NULL;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI, "acpi module initialized");
    return ABYSS_OK;
}

int abyss_acpi_run(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    if (abyss_acpi_load_tables(ctx) != ABYSS_OK) {
        abyss_log(ctx, ABYSS_LOG_WARN, ABYSS_MODULE_ACPI, "no tables loaded, skipping");
        return ABYSS_ERR_ACPI;
    }
    abyss_acpi_table_t *t = NULL;
    if (abyss_acpi_find_table(ctx, ACPI_SIG_DSDT, &t) == ABYSS_OK) {
        abyss_acpi_parse_dsdt(ctx, t);
        abyss_acpi_mutate(ctx, t, (uint32_t)time(NULL));
        abyss_acpi_apply(ctx, t);
    }
    abyss_acpi_table_t *tables = (abyss_acpi_table_t *)ctx->module_data[ABYSS_MODULE_ACPI];
    if (tables) {
        for (uint32_t i = 0; i < ACPI_MAX_TABLES; i++) {
            if (tables[i].data && strcmp(tables[i].signature, ACPI_SIG_SSDT) == 0) {
                abyss_acpi_parse_ssdt(ctx, &tables[i]);
                abyss_acpi_mutate(ctx, &tables[i], (uint32_t)time(NULL) + i + 1);
                abyss_acpi_apply(ctx, &tables[i]);
            }
        }
    }
    int32_t temp = 0;
    if (abyss_acpi_read_thermal(ctx, 0, &temp) == ABYSS_OK) {
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI, "zone0 temp=%dC", temp);
    }
    uint32_t cs = 0, ps = 0;
    if (abyss_acpi_read_power_state(ctx, 0, &cs, &ps) == ABYSS_OK) {
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_ACPI,
                  "cpu0 cstate-usage=%u freq=%ukHz", cs, ps);
    }
    return ABYSS_OK;
}

int abyss_acpi_stop(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    abyss_acpi_table_t *tables = (abyss_acpi_table_t *)ctx->module_data[ABYSS_MODULE_ACPI];
    if (tables) {
        for (uint32_t i = 0; i < ACPI_MAX_TABLES; i++) {
            if (tables[i].data) {
                free(tables[i].data);
                tables[i].data = NULL;
                tables[i].length = 0;
            }
        }
        free(tables);
        ctx->module_data[ABYSS_MODULE_ACPI] = NULL;
    }
    return ABYSS_OK;
}

void abyss_acpi_free(abyss_context_t *ctx) {
    abyss_acpi_stop(ctx);
}