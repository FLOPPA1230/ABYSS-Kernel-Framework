#ifndef ABYSS_H
#define ABYSS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/kvm.h>

#define ABYSS_VERSION        "1.0.0"
#define ABYSS_MAX_CPUS       256
#define ABYSS_MAX_DRIVERS    512
#define ABYSS_MAX_IOCTLS     4096
#define ABYSS_MAX_ACPI_TABLES 64
#define ABYSS_SHM_SIZE       (16 * 1024 * 1024)
#define ABYSS_LOG_SIZE       (4 * 1024 * 1024)
#define ABYSS_PATH_MAX       512
#define ABYSS_NAME_MAX       128

#define ABYSS_OK             0
#define ABYSS_ERR           -1
#define ABYSS_ERR_PERM      -2
#define ABYSS_ERR_MEM       -3
#define ABYSS_ERR_IO        -4
#define ABYSS_ERR_KVM       -5
#define ABYSS_ERR_ACPI      -6
#define ABYSS_ERR_FUZZ      -7
#define ABYSS_ERR_IPC       -8
#define ABYSS_ERR_REPORT    -9

#define ABYSS_LOG_DEBUG      0
#define ABYSS_LOG_INFO       1
#define ABYSS_LOG_WARN       2
#define ABYSS_LOG_ERROR      3
#define ABYSS_LOG_FATAL      4

#define ABYSS_STATE_IDLE     0
#define ABYSS_STATE_RUNNING  1
#define ABYSS_STATE_PAUSED   2
#define ABYSS_STATE_STOPPED  3
#define ABYSS_STATE_CRASHED  4

typedef enum {
    ABYSS_MODULE_HYPER  = 0,
    ABYSS_MODULE_ACPI   = 1,
    ABYSS_MODULE_FUZZ   = 2,
    ABYSS_MODULE_IPC    = 3,
    ABYSS_MODULE_REPORT = 4,
    ABYSS_MODULE_MAX    = 5
} abyss_module_t;

typedef enum {
    ABYSS_SEVERITY_NONE   = 0,
    ABYSS_SEVERITY_LOW    = 1,
    ABYSS_SEVERITY_MEDIUM = 2,
    ABYSS_SEVERITY_HIGH   = 3,
    ABYSS_SEVERITY_CRIT   = 4
} abyss_severity_t;

typedef struct {
    uint64_t addr;
    uint64_t size;
    uint32_t flags;
    uint32_t prot;
    char     name[ABYSS_NAME_MAX];
} abyss_region_t;

typedef struct {
    uint32_t id;
    uint32_t cpu;
    uint64_t msr;
    uint64_t value;
    uint32_t op;
    uint32_t pid;
    char     comm[ABYSS_NAME_MAX];
    uint64_t timestamp;
} abyss_msr_event_t;

typedef struct {
    uint32_t id;
    uint32_t bus;
    uint32_t dev;
    uint32_t fn;
    uint32_t offset;
    uint32_t value;
    uint32_t op;
    uint64_t timestamp;
} abyss_pci_event_t;

typedef struct {
    char     name[ABYSS_NAME_MAX];
    char     path[ABYSS_PATH_MAX];
    uint32_t vendor;
    uint32_t device;
    uint32_t ioctl_count;
    uint32_t ioctl_ids[ABYSS_MAX_IOCTLS];
    uint32_t crash_count;
} abyss_driver_t;

typedef struct {
    char     signature[8];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[8];
    char     oem_table_id[8];
    uint32_t oem_revision;
    char     creator_id[8];
    uint32_t creator_revision;
    uint64_t phys_addr;
    uint8_t *data;
    uint32_t mutated;
} abyss_acpi_table_t;

typedef struct {
    char     name[ABYSS_NAME_MAX];
    uint32_t id;
    uint32_t state;
    uint32_t severity;
    uint64_t timestamp;
    char     detail[ABYSS_PATH_MAX];
} abyss_finding_t;

typedef struct {
    uint32_t total_events;
    uint32_t total_findings;
    uint32_t total_crashes;
    uint32_t total_drivers;
    uint32_t total_acpi_tables;
    uint32_t total_ioctls;
    time_t   start_time;
    time_t   end_time;
} abyss_stats_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t state;
    uint32_t module_count;
    uint64_t module_state[ABYSS_MODULE_MAX];
    uint64_t heartbeat[ABYSS_MODULE_MAX];
    uint32_t event_head;
    uint32_t event_tail;
    uint32_t finding_head;
    uint32_t finding_tail;
    abyss_stats_t stats;
    abyss_msr_event_t  msr_events[1024];
    abyss_pci_event_t  pci_events[1024];
    abyss_finding_t    findings[2048];
} abyss_shm_t;

typedef struct {
    uint32_t level;
    uint32_t module;
    uint64_t timestamp;
    uint32_t pid;
    char     message[512];
} abyss_log_entry_t;

typedef struct {
    uint32_t magic;
    uint32_t write_idx;
    uint32_t read_idx;
    uint32_t capacity;
    abyss_log_entry_t entries[4096];
} abyss_log_t;

typedef struct {
    int         verbose;
    int         daemon;
    int         no_color;
    int         hyper_enabled;
    int         acpi_enabled;
    int         fuzz_enabled;
    int         report_enabled;
    uint32_t    cpu_mask;
    uint32_t    fuzz_iterations;
    uint32_t    fuzz_timeout_ms;
    uint32_t    acpi_mutations;
    char        output_dir[ABYSS_PATH_MAX];
    char        report_format[32];
    char        log_path[ABYSS_PATH_MAX];
    char        shm_name[ABYSS_NAME_MAX];
} abyss_config_t;

typedef struct abyss_context {
    abyss_config_t  config;
    abyss_shm_t    *shm;
    abyss_log_t    *log;
    int             shm_fd;
    int             log_fd;
    uint32_t        state;
    uint32_t        magic;
    void           *module_data[ABYSS_MODULE_MAX];
    int           (*module_init[ABYSS_MODULE_MAX])(struct abyss_context *);
    int           (*module_run[ABYSS_MODULE_MAX])(struct abyss_context *);
    int           (*module_stop[ABYSS_MODULE_MAX])(struct abyss_context *);
    void          (*module_free[ABYSS_MODULE_MAX])(struct abyss_context *);
} abyss_context_t;

int  abyss_init(abyss_context_t *ctx);
int  abyss_run(abyss_context_t *ctx);
int  abyss_stop(abyss_context_t *ctx);
void abyss_free(abyss_context_t *ctx);
int  abyss_parse_args(abyss_context_t *ctx, int argc, char **argv);
int  abyss_load_config(abyss_context_t *ctx, const char *path);
int  abyss_save_config(abyss_context_t *ctx, const char *path);

int  abyss_log_init(abyss_context_t *ctx);
void abyss_log_free(abyss_context_t *ctx);
void abyss_log(abyss_context_t *ctx, uint32_t level, uint32_t module, const char *fmt, ...);
const char *abyss_log_level_str(uint32_t level);
int  abyss_log_flush(abyss_context_t *ctx);

int  abyss_shm_init(abyss_context_t *ctx);
void abyss_shm_free(abyss_context_t *ctx);
int  abyss_shm_push_event(abyss_context_t *ctx, const void *event, size_t size);
int  abyss_shm_push_finding(abyss_context_t *ctx, const abyss_finding_t *f);
int  abyss_shm_pop_finding(abyss_context_t *ctx, abyss_finding_t *f);
int  abyss_shm_update_stats(abyss_context_t *ctx);
int  abyss_channel_open(abyss_context_t *ctx, uint32_t module);
int  abyss_channel_send(abyss_context_t *ctx, uint32_t module, const void *msg, size_t size);
int  abyss_channel_recv(abyss_context_t *ctx, uint32_t module, void *msg, size_t size);

int  abyss_hyper_init(abyss_context_t *ctx);
int  abyss_hyper_run(abyss_context_t *ctx);
int  abyss_hyper_stop(abyss_context_t *ctx);
void abyss_hyper_free(abyss_context_t *ctx);
int  abyss_hyper_vmexit_handler(abyss_context_t *ctx, uint32_t exit_reason, void *data);
int  abyss_hyper_intercept_msr(abyss_context_t *ctx, uint64_t msr, int enable);
int  abyss_hyper_intercept_pci(abyss_context_t *ctx, uint32_t bus, uint32_t dev, uint32_t fn);
int  abyss_hyper_snapshot(abyss_context_t *ctx, abyss_region_t *out, uint32_t max);

int  abyss_acpi_init(abyss_context_t *ctx);
int  abyss_acpi_run(abyss_context_t *ctx);
int  abyss_acpi_stop(abyss_context_t *ctx);
void abyss_acpi_free(abyss_context_t *ctx);
int  abyss_acpi_load_tables(abyss_context_t *ctx);
int  abyss_acpi_parse_dsdt(abyss_context_t *ctx, abyss_acpi_table_t *t);
int  abyss_acpi_parse_ssdt(abyss_context_t *ctx, abyss_acpi_table_t *t);
int  abyss_acpi_mutate(abyss_context_t *ctx, abyss_acpi_table_t *t, uint32_t seed);
int  abyss_acpi_apply(abyss_context_t *ctx, abyss_acpi_table_t *t);
int  abyss_acpi_find_table(abyss_context_t *ctx, const char *sig, abyss_acpi_table_t **out);
int  abyss_acpi_read_power_state(abyss_context_t *ctx, uint32_t cpu, uint32_t *cstate, uint32_t *pstate);
int  abyss_acpi_read_thermal(abyss_context_t *ctx, uint32_t zone, int32_t *temp);

int  abyss_fuzz_init(abyss_context_t *ctx);
int  abyss_fuzz_run(abyss_context_t *ctx);
int  abyss_fuzz_stop(abyss_context_t *ctx);
void abyss_fuzz_free(abyss_context_t *ctx);
int  abyss_fuzz_scan_drivers(abyss_context_t *ctx);
int  abyss_fuzz_scan_ioctls(abyss_context_t *ctx, abyss_driver_t *d);
int  abyss_fuzz_mutate(abyss_context_t *ctx, uint8_t *buf, size_t size, uint32_t seed);
int  abyss_fuzz_execute(abyss_context_t *ctx, abyss_driver_t *d, uint32_t ioctl_id, const uint8_t *buf, size_t size);
int  abyss_fuzz_detect_crash(abyss_context_t *ctx, pid_t child, int status);
int  abyss_fuzz_report_crash(abyss_context_t *ctx, abyss_driver_t *d, uint32_t ioctl_id, uint32_t severity);

int  abyss_report_init(abyss_context_t *ctx);
int  abyss_report_run(abyss_context_t *ctx);
int  abyss_report_stop(abyss_context_t *ctx);
void abyss_report_free(abyss_context_t *ctx);
int  abyss_report_json(abyss_context_t *ctx, const char *path);
int  abyss_report_html(abyss_context_t *ctx, const char *path);
int  abyss_report_console(abyss_context_t *ctx);
int  abyss_report_collect(abyss_context_t *ctx);

uint64_t abyss_time_ms(void);
uint64_t abyss_time_us(void);
uint32_t abyss_rand_seed(void);
uint32_t abyss_rand_next(uint32_t *state);
uint32_t abyss_crc32(const void *data, size_t len);
int  abyss_file_exists(const char *path);
int  abyss_dir_exists(const char *path);
int  abyss_mkdir_p(const char *path);
ssize_t abyss_read_file(const char *path, void *buf, size_t size);
ssize_t abyss_write_file(const char *path, const void *buf, size_t size);

extern abyss_context_t *g_abyss;

#endif