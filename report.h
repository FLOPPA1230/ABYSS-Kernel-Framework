#include "abyss.h"
#include <ctype.h>
#include <dirent.h>
#include <sys/utsname.h>

static const char *severity_str(uint32_t s) {
    switch (s) {
        case ABYSS_SEVERITY_LOW:    return "low";
        case ABYSS_SEVERITY_MEDIUM: return "medium";
        case ABYSS_SEVERITY_HIGH:   return "high";
        case ABYSS_SEVERITY_CRIT:   return "critical";
        default:                    return "none";
    }
}

static const char *module_str(uint32_t m) {
    switch (m) {
        case ABYSS_MODULE_HYPER:  return "hypervisor";
        case ABYSS_MODULE_ACPI:   return "acpi";
        case ABYSS_MODULE_FUZZ:   return "fuzzer";
        case ABYSS_MODULE_IPC:    return "ipc";
        case ABYSS_MODULE_REPORT: return "report";
        default:                  return "unknown";
    }
}

static void json_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 6 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':  out[j++]='\\'; out[j++]='"';  break;
            case '\\': out[j++]='\\'; out[j++]='\\'; break;
            case '\n': out[j++]='\\'; out[j++]='n';  break;
            case '\r': out[j++]='\\'; out[j++]='r';  break;
            case '\t': out[j++]='\\'; out[j++]='t';  break;
            default:
                if (c < 0x20) {
                    j += snprintf(out+j, out_size-j, "\\u%04x", c);
                } else {
                    out[j++] = c;
                }
        }
    }
    out[j] = '\0';
}

static void html_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 8 < out_size; i++) {
        switch (in[i]) {
            case '<': memcpy(out+j, "&lt;", 4); j+=4; break;
            case '>': memcpy(out+j, "&gt;", 4); j+=4; break;
            case '&': memcpy(out+j, "&amp;", 5); j+=5; break;
            case '"': memcpy(out+j, "&quot;", 6); j+=6; break;
            case '\'': memcpy(out+j, "&#39;", 5); j+=5; break;
            default: out[j++] = in[i];
        }
    }
    out[j] = '\0';
}

int abyss_report_collect(abyss_context_t *ctx) {
    if (!ctx || !ctx->shm) return ABYSS_ERR;
    ctx->shm->stats.end_time = time(NULL);
    ctx->shm->stats.total_drivers = 0;
    ctx->shm->stats.total_acpi_tables = 0;
    ctx->shm->stats.total_ioctls = 0;
    if (ctx->module_data[ABYSS_MODULE_FUZZ]) {
        abyss_driver_t *drivers = (abyss_driver_t *)ctx->module_data[ABYSS_MODULE_FUZZ];
        for (uint32_t i = 0; i < ABYSS_MAX_DRIVERS; i++) {
            if (drivers[i].name[0]) {
                ctx->shm->stats.total_drivers++;
                ctx->shm->stats.total_ioctls += drivers[i].ioctl_count;
            }
        }
    }
    return ABYSS_OK;
}

static int write_json_header(FILE *f, abyss_context_t *ctx) {
    struct utsname u;
    uname(&u);
    char host[ABYSS_PATH_MAX] = {0};
    gethostname(host, sizeof(host)-1);
    char out[ABYSS_PATH_MAX];
    json_escape(u.sysname, out, sizeof(out));
    fprintf(f, "{\n");
    fprintf(f, "  \"abyss_version\": \"%s\",\n", ABYSS_VERSION);
    fprintf(f, "  \"generated_at\": %lld,\n", (long long)time(NULL));
    fprintf(f, "  \"system\": {\n");
    fprintf(f, "    \"hostname\": \"%s\",\n", host);
    fprintf(f, "    \"kernel\": \"%s\",\n", out);
    json_escape(u.release, out, sizeof(out));
    fprintf(f, "    \"release\": \"%s\",\n", out);
    json_escape(u.machine, out, sizeof(out));
    fprintf(f, "    \"machine\": \"%s\"\n", out);
    fprintf(f, "  },\n");
    fprintf(f, "  \"stats\": {\n");
    fprintf(f, "    \"events\": %u,\n", ctx->shm->stats.total_events);
    fprintf(f, "    \"findings\": %u,\n", ctx->shm->stats.total_findings);
    fprintf(f, "    \"crashes\": %u,\n", ctx->shm->stats.total_crashes);
    fprintf(f, "    \"drivers\": %u,\n", ctx->shm->stats.total_drivers);
    fprintf(f, "    \"acpi_tables\": %u,\n", ctx->shm->stats.total_acpi_tables);
    fprintf(f, "    \"ioctls\": %u,\n", ctx->shm->stats.total_ioctls);
    fprintf(f, "    \"duration_sec\": %lld\n", (long long)(ctx->shm->stats.end_time - ctx->shm->stats.start_time));
    fprintf(f, "  },\n");
    return ABYSS_OK;
}

int abyss_report_json(abyss_context_t *ctx, const char *path) {
    if (!ctx || !ctx->shm || !path) return ABYSS_ERR;
    FILE *f = fopen(path, "w");
    if (!f) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_REPORT, "cannot open %s: %s", path, strerror(errno));
        return ABYSS_ERR_IO;
    }
    abyss_report_collect(ctx);
    write_json_header(f, ctx);
    fprintf(f, "  \"findings\": [\n");
    uint32_t head = __atomic_load_n(&ctx->shm->finding_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&ctx->shm->finding_tail, __ATOMIC_RELAXED);
    uint32_t idx = tail;
    int first = 1;
    while (idx != head) {
        abyss_finding_t *fi = &ctx->shm->findings[idx % 2048];
        char name[ABYSS_PATH_MAX*2], detail[ABYSS_PATH_MAX*2];
        json_escape(fi->name, name, sizeof(name));
        json_escape(fi->detail, detail, sizeof(detail));
        fprintf(f, "%s    {\n", first ? "" : ",\n");
        fprintf(f, "      \"id\": %u,\n", fi->id);
        fprintf(f, "      \"name\": \"%s\",\n", name);
        fprintf(f, "      \"module\": \"%s\",\n", module_str(fi->state % ABYSS_MODULE_MAX));
        fprintf(f, "      \"severity\": \"%s\",\n", severity_str(fi->severity));
        fprintf(f, "      \"timestamp\": %llu,\n", (unsigned long long)fi->timestamp);
        fprintf(f, "      \"detail\": \"%s\"\n", detail);
        fprintf(f, "    }");
        first = 0;
        idx++;
    }
    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"events\": [\n");
    head = __atomic_load_n(&ctx->shm->event_head, __ATOMIC_ACQUIRE);
    tail = __atomic_load_n(&ctx->shm->event_tail, __ATOMIC_RELAXED);
    idx = tail;
    first = 1;
    while (idx != head) {
        abyss_msr_event_t *e = &ctx->shm->msr_events[idx % 2048];
        char comm[ABYSS_PATH_MAX];
        json_escape(e->comm, comm, sizeof(comm));
        fprintf(f, "%s    {\n", first ? "" : ",\n");
        fprintf(f, "      \"cpu\": %u,\n", e->cpu);
        fprintf(f, "      \"msr\": \"0x%llx\",\n", (unsigned long long)e->msr);
        fprintf(f, "      \"value\": \"0x%llx\",\n", (unsigned long long)e->value);
        fprintf(f, "      \"op\": %u,\n", e->op);
        fprintf(f, "      \"comm\": \"%s\",\n", comm);
        fprintf(f, "      \"ts\": %llu\n", (unsigned long long)e->timestamp);
        fprintf(f, "    }");
        first = 0;
        idx++;
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_REPORT, "JSON report written: %s", path);
    return ABYSS_OK;
}

int abyss_report_html(abyss_context_t *ctx, const char *path) {
    if (!ctx || !ctx->shm || !path) return ABYSS_ERR;
    FILE *f = fopen(path, "w");
    if (!f) return ABYSS_ERR_IO;
    struct utsname u;
    uname(&u);
    char host[ABYSS_PATH_MAX] = {0};
    gethostname(host, sizeof(host)-1);
    char s_host[ABYSS_PATH_MAX*2], s_kernel[ABYSS_PATH_MAX*2], s_release[ABYSS_PATH_MAX*2];
    html_escape(host, s_host, sizeof(s_host));
    html_escape(u.sysname, s_kernel, sizeof(s_kernel));
    html_escape(u.release, s_release, sizeof(s_release));
    fprintf(f, "<!DOCTYPE html>\n<html lang=\"ar\">\n<head>\n");
    fprintf(f, "<meta charset=\"utf-8\">\n");
    fprintf(f, "<title>ABYSS Report</title>\n");
    fprintf(f, "<style>\n");
    fprintf(f, "body{font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:2em}\n");
    fprintf(f, "h1{color:#ff2020;text-shadow:0 0 10px #ff2020}\n");
    fprintf(f, "h2{color:#ff6030;border-bottom:1px solid #ff6030}\n");
    fprintf(f, "table{border-collapse:collapse;width:100%%;margin:1em 0}\n");
    fprintf(f, "th,td{border:1px solid #333;padding:.5em;text-align:left}\n");
    fprintf(f, "th{background:#1a1a1a;color:#ff9020}\n");
    fprintf(f, "tr:hover{background:#151515}\n");
    fprintf(f, ".crit{color:#ff0000;font-weight:bold}\n");
    fprintf(f, ".high{color:#ff5000}\n");
    fprintf(f, ".med{color:#ffa000}\n");
    fprintf(f, ".low{color:#a0ff00}\n");
    fprintf(f, ".stat{display:inline-block;margin:1em;padding:1em;background:#1a1a1a;border:1px solid #ff2020}\n");
    fprintf(f, ".stat .n{font-size:2em;color:#ff2020;display:block}\n");
    fprintf(f, "</style>\n</head>\n<body>\n");
    fprintf(f, "<h1>ABYSS &mdash; Hellfire Report</h1>\n");
    fprintf(f, "<p>Generated: %s</p>\n", ctime(&ctx->shm->stats.end_time));
    fprintf(f, "<p>Host: %s | Kernel: %s %s</p>\n", s_host, s_kernel, s_release);
    fprintf(f, "<h2>Statistics</h2>\n");
    fprintf(f, "<div class=\"stat\"><span class=\"n\">%u</span>events</div>\n", ctx->shm->stats.total_events);
    fprintf(f, "<div class=\"stat\"><span class=\"n\">%u</span>findings</div>\n", ctx->shm->stats.total_findings);
    fprintf(f, "<div class=\"stat\"><span class=\"n\">%u</span>crashes</div>\n", ctx->shm->stats.total_crashes);
    fprintf(f, "<div class=\"stat\"><span class=\"n\">%u</span>drivers</div>\n", ctx->shm->stats.total_drivers);
    fprintf(f, "<div class=\"stat\"><span class=\"n\">%u</span>acpi tables</div>\n", ctx->shm->stats.total_acpi_tables);
    fprintf(f, "<div class=\"stat\"><span class=\"n\">%u</span>ioctls</div>\n", ctx->shm->stats.total_ioctls);
    fprintf(f, "<h2>Findings</h2>\n<table>\n");
    fprintf(f, "<tr><th>ID</th><th>Name</th><th>Module</th><th>Severity</th><th>Detail</th></tr>\n");
    uint32_t head = __atomic_load_n(&ctx->shm->finding_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&ctx->shm->finding_tail, __ATOMIC_RELAXED);
    uint32_t idx = tail;
    while (idx != head) {
        abyss_finding_t *fi = &ctx->shm->findings[idx % 2048];
        char name[ABYSS_PATH_MAX*2], detail[ABYSS_PATH_MAX*2];
        html_escape(fi->name, name, sizeof(name));
        html_escape(fi->detail, detail, sizeof(detail));
        const char *cls = "low";
        switch (fi->severity) {
            case ABYSS_SEVERITY_CRIT: cls="crit"; break;
            case ABYSS_SEVERITY_HIGH: cls="high"; break;
            case ABYSS_SEVERITY_MEDIUM: cls="med"; break;
        }
        fprintf(f, "<tr><td>%u</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td></tr>\n",
                fi->id, name, module_str(fi->state % ABYSS_MODULE_MAX), cls,
                severity_str(fi->severity), detail);
        idx++;
    }
    fprintf(f, "</table>\n</body>\n</html>\n");
    fclose(f);
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_REPORT, "HTML report written: %s", path);
    return ABYSS_OK;
}

int abyss_report_console(abyss_context_t *ctx) {
    if (!ctx || !ctx->shm) return ABYSS_ERR;
    fprintf(stdout, "\n\033[35m=== ABYSS REPORT ===\033[0m\n");
    fprintf(stdout, "events:   %u\n", ctx->shm->stats.total_events);
    fprintf(stdout, "findings: %u\n", ctx->shm->stats.total_findings);
    fprintf(stdout, "crashes:  %u\n", ctx->shm->stats.total_crashes);
    fprintf(stdout, "drivers:  %u\n", ctx->shm->stats.total_drivers);
    fprintf(stdout, "acpi:     %u\n", ctx->shm->stats.total_acpi_tables);
    fprintf(stdout, "ioctls:   %u\n", ctx->shm->stats.total_ioctls);
    uint32_t head = __atomic_load_n(&ctx->shm->finding_head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&ctx->shm->finding_tail, __ATOMIC_RELAXED);
    uint32_t idx = tail;
    while (idx != head) {
        abyss_finding_t *fi = &ctx->shm->findings[idx % 2048];
        fprintf(stdout, "  [%s] %s: %s\n", severity_str(fi->severity), fi->name, fi->detail);
        idx++;
    }
    return ABYSS_OK;
}

int abyss_report_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    if (!ctx->config.output_dir[0]) {
        snprintf(ctx->config.output_dir, sizeof(ctx->config.output_dir), "./abyss_report");
    }
    abyss_mkdir_p(ctx->config.output_dir);
    if (!ctx->config.report_format[0]) {
        snprintf(ctx->config.report_format, sizeof(ctx->config.report_format), "json,html");
    }
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_REPORT, "report init: dir=%s fmt=%s",
              ctx->config.output_dir, ctx->config.report_format);
    return ABYSS_OK;
}

int abyss_report_run(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    char path[ABYSS_PATH_MAX*2];
    if (strstr(ctx->config.report_format, "json")) {
        snprintf(path, sizeof(path), "%s/report.json", ctx->config.output_dir);
        abyss_report_json(ctx, path);
    }
    if (strstr(ctx->config.report_format, "html")) {
        snprintf(path, sizeof(path), "%s/report.html", ctx->config.output_dir);
        abyss_report_html(ctx, path);
    }
    abyss_report_console(ctx);
    return ABYSS_OK;
}

int abyss_report_stop(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    abyss_log_flush(ctx);
    return ABYSS_OK;
}

void abyss_report_free(abyss_context_t *ctx) {
    (void)ctx;
}