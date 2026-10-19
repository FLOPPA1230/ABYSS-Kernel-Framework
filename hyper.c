#include "abyss.h"
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sched.h>

#define HYPER_MAX_VCPUS 4
#define HYPER_MAX_MSRS  64
#define HYPER_VM_MEM    (16 * 1024 * 1024)

typedef struct {
    uint32_t msr;
    uint32_t enabled;
    uint64_t last_value;
    uint64_t hit_count;
} hyper_msr_watch_t;

typedef struct {
    uint32_t bus;
    uint32_t dev;
    uint32_t fn;
    uint32_t enabled;
    uint64_t hit_count;
} hyper_pci_watch_t;

typedef struct {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd[HYPER_MAX_VCPUS];
    uint32_t vcpu_count;
    uint8_t *guest_mem;
    size_t guest_mem_size;
    hyper_msr_watch_t msr_watch[HYPER_MAX_MSRS];
    uint32_t msr_count;
    hyper_pci_watch_t pci_watch[HYPER_MAX_MSRS];
    uint32_t pci_count;
    uint64_t total_exits;
    uint64_t exits_by_reason[64];
    volatile int running;
    pthread_t thread;
} hyper_state_t;

static const char *vmexit_reason_str(uint32_t reason) {
    switch (reason) {
        case KVM_EXIT_UNKNOWN:          return "UNKNOWN";
        case KVM_EXIT_EXCEPTION:        return "EXCEPTION";
        case KVM_EXIT_IO:               return "IO";
        case KVM_EXIT_HYPERCALL:        return "HYPERCALL";
        case KVM_EXIT_DEBUG:            return "DEBUG";
        case KVM_EXIT_HLT:              return "HLT";
        case KVM_EXIT_MMIO:             return "MMIO";
        case KVM_EXIT_IRQ_WINDOW_OPEN:  return "IRQ_WINDOW_OPEN";
        case KVM_EXIT_SHUTDOWN:         return "SHUTDOWN";
        case KVM_EXIT_FAIL_ENTRY:       return "FAIL_ENTRY";
        case KVM_EXIT_INTR:             return "INTR";
        case KVM_EXIT_SET_TPR:          return "SET_TPR";
        case KVM_EXIT_TPR_ACCESS:       return "TPR_ACCESS";
        case KVM_EXIT_S390_SIEIC:       return "S390_SIEIC";
        case KVM_EXIT_S390_RESET:       return "S390_RESET";
        case KVM_EXIT_DCR:              return "DCR";
        case KVM_EXIT_NMI:              return "NMI";
        case KVM_EXIT_INTERNAL_ERROR:   return "INTERNAL_ERROR";
        case KVM_EXIT_OSI:              return "OSI";
        case KVM_EXIT_PAPR_HCALL:       return "PAPR_HCALL";
        case KVM_EXIT_S390_UCONTROL:    return "S390_UCONTROL";
        case KVM_EXIT_WATCHDOG:         return "WATCHDOG";
        case KVM_EXIT_S390_TSCH:        return "S390_TSCH";
        case KVM_EXIT_EPR:              return "EPR";
        case KVM_EXIT_SYSTEM_EVENT:     return "SYSTEM_EVENT";
        case KVM_EXIT_S390_STSI:        return "S390_STSI";
        case KVM_EXIT_IOAPIC_EOI:       return "IOAPIC_EOI";
        case KVM_EXIT_HYPERV:           return "HYPERV";
        default:                        return "OTHER";
    }
}

static int hyper_msr_index(hyper_state_t *h, uint32_t msr) {
    for (uint32_t i = 0; i < h->msr_count; i++) {
        if (h->msr_watch[i].msr == msr) return (int)i;
    }
    return -1;
}

static void hyper_push_msr_event(abyss_context_t *ctx, uint32_t cpu,
                                 uint64_t msr, uint64_t val, uint32_t op) {
    if (!ctx || !ctx->shm) return;
    abyss_msr_event_t ev;
    memset(&ev, 0, sizeof(ev));
    static uint32_t next_id = 1;
    ev.id = __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);
    ev.cpu = cpu;
    ev.msr = msr;
    ev.value = val;
    ev.op = op;
    ev.pid = getpid();
    snprintf(ev.comm, sizeof(ev.comm), "kvm-vcpu%u", cpu);
    ev.timestamp = abyss_time_ms();
    abyss_shm_push_event(ctx, &ev, sizeof(ev));
}

int abyss_hyper_intercept_msr(abyss_context_t *ctx, uint64_t msr, int enable) {
    if (!ctx) return ABYSS_ERR;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return ABYSS_ERR_KVM;
    int idx = hyper_msr_index(h, (uint32_t)msr);
    if (enable) {
        if (idx >= 0) {
            h->msr_watch[idx].enabled = 1;
            return ABYSS_OK;
        }
        if (h->msr_count >= HYPER_MAX_MSRS) return ABYSS_ERR;
        h->msr_watch[h->msr_count].msr = (uint32_t)msr;
        h->msr_watch[h->msr_count].enabled = 1;
        h->msr_watch[h->msr_count].last_value = 0;
        h->msr_watch[h->msr_count].hit_count = 0;
        h->msr_count++;
        abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER,
                  "MSR watch added: 0x%llx", (unsigned long long)msr);
    } else {
        if (idx >= 0) h->msr_watch[idx].enabled = 0;
    }
    return ABYSS_OK;
}

int abyss_hyper_intercept_pci(abyss_context_t *ctx, uint32_t bus,
                              uint32_t dev, uint32_t fn) {
    if (!ctx) return ABYSS_ERR;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return ABYSS_ERR_KVM;
    if (h->pci_count >= HYPER_MAX_MSRS) return ABYSS_ERR;
    h->pci_watch[h->pci_count].bus = bus;
    h->pci_watch[h->pci_count].dev = dev;
    h->pci_watch[h->pci_count].fn = fn;
    h->pci_watch[h->pci_count].enabled = 1;
    h->pci_watch[h->pci_count].hit_count = 0;
    h->pci_count++;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER,
              "PCI watch added: %02x:%02x.%u", bus, dev, fn);
    return ABYSS_OK;
}

static void hyper_handle_io(abyss_context_t *ctx, hyper_state_t *h,
                            struct kvm_run *run, uint32_t vcpu) {
    uint16_t port = run->io.port;
    uint32_t size = run->io.size;
    uint32_t count = run->io.count;
    if (run->io.direction == KVM_EXIT_IO_IN) {
        memset((uint8_t *)run + run->io.data_offset, 0xFF, (size_t)size * count);
        abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_HYPER,
                  "vcpu%u IN port=0x%x size=%u count=%u", vcpu, port, size, count);
    } else {
        abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_HYPER,
                  "vcpu%u OUT port=0x%x size=%u count=%u", vcpu, port, size, count);
    }
}

static void hyper_handle_mmio(abyss_context_t *ctx, hyper_state_t *h,
                              struct kvm_run *run, uint32_t vcpu) {
    uint64_t addr = run->mmio.phys_addr;
    uint32_t len = run->mmio.len;
    if (run->mmio.is_write) {
        abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_HYPER,
                  "vcpu%u MMIO WR addr=0x%llx len=%u", vcpu,
                  (unsigned long long)addr, len);
    } else {
        memset(run->mmio.data, 0xFF, len);
        abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_HYPER,
                  "vcpu%u MMIO RD addr=0x%llx len=%u", vcpu,
                  (unsigned long long)addr, len);
    }
}

int abyss_hyper_vmexit_handler(abyss_context_t *ctx, uint32_t exit_reason, void *data) {
    if (!ctx || !data) return ABYSS_ERR;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return ABYSS_ERR_KVM;
    struct kvm_run *run = (struct kvm_run *)data;
    uint32_t vcpu = 0;
    h->total_exits++;
    if (exit_reason < 64) h->exits_by_reason[exit_reason]++;
    switch (exit_reason) {
        case KVM_EXIT_IO:
            hyper_handle_io(ctx, h, run, vcpu);
            break;
        case KVM_EXIT_MMIO:
            hyper_handle_mmio(ctx, h, run, vcpu);
            break;
        case KVM_EXIT_SHUTDOWN:
            abyss_log(ctx, ABYSS_LOG_WARN, ABYSS_MODULE_HYPER,
                      "vcpu%u SHUTDOWN", vcpu);
            h->running = 0;
            break;
        case KVM_EXIT_FAIL_ENTRY:
            abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                      "vcpu%u FAIL_ENTRY hardware_entry_failure_reason=0x%llx", vcpu,
                      (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
            h->running = 0;
            break;
        case KVM_EXIT_INTERNAL_ERROR:
            abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                      "vcpu%u INTERNAL_ERROR suberror=0x%x", vcpu,
                      run->internal.suberror);
            h->running = 0;
            break;
        case KVM_EXIT_HLT:
            abyss_log(ctx, ABYSS_LOG_DEBUG, ABYSS_MODULE_HYPER, "vcpu%u HLT", vcpu);
            break;
        default:
            break;
    }
    return ABYSS_OK;
}

static void *hyper_loop(void *arg) {
    abyss_context_t *ctx = (abyss_context_t *)arg;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return NULL;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER, "hypervisor loop started");
    while (h->running && ctx->state == ABYSS_STATE_RUNNING) {
        int r = ioctl(h->vcpu_fd[0], KVM_RUN, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                      "KVM_RUN failed: %s", strerror(errno));
            break;
        }
        uint32_t reason = h->guest_mem ? 0 : 0;
        struct kvm_run *run = (struct kvm_run *)mmap(NULL, 4096,
                                                     PROT_READ | PROT_WRITE,
                                                     MAP_SHARED, h->vcpu_fd[0], 0);
        if (run == MAP_FAILED) break;
        reason = run->exit_reason;
        abyss_hyper_vmexit_handler(ctx, reason, run);
        munmap(run, 4096);
        if (ctx->shm) __atomic_fetch_add(&ctx->shm->stats.total_events, 1, __ATOMIC_RELAXED);
    }
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER, "hypervisor loop stopped");
    return NULL;
}

int abyss_hyper_init(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    hyper_state_t *h = calloc(1, sizeof(hyper_state_t));
    if (!h) return ABYSS_ERR_MEM;
    h->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (h->kvm_fd < 0) {
        abyss_log(ctx, ABYSS_LOG_WARN, ABYSS_MODULE_HYPER,
                  "/dev/kvm unavailable: %s", strerror(errno));
        free(h);
        return ABYSS_ERR_KVM;
    }
    int api = ioctl(h->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api != KVM_API_VERSION) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                  "KVM API mismatch: %d != %d", api, KVM_API_VERSION);
        close(h->kvm_fd);
        free(h);
        return ABYSS_ERR_KVM;
    }
    h->vm_fd = ioctl(h->kvm_fd, KVM_CREATE_VM, 0);
    if (h->vm_fd < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                  "KVM_CREATE_VM failed: %s", strerror(errno));
        close(h->kvm_fd);
        free(h);
        return ABYSS_ERR_KVM;
    }
    h->guest_mem_size = HYPER_VM_MEM;
    h->guest_mem = mmap(NULL, h->guest_mem_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (h->guest_mem == MAP_FAILED) {
        close(h->vm_fd); close(h->kvm_fd); free(h);
        return ABYSS_ERR_MEM;
    }
    memset(h->guest_mem, 0, h->guest_mem_size);
    struct kvm_userspace_memory_region region;
    memset(&region, 0, sizeof(region));
    region.slot = 0;
    region.guest_phys_addr = 0;
    region.memory_size = h->guest_mem_size;
    region.userspace_addr = (uint64_t)(uintptr_t)h->guest_mem;
    if (ioctl(h->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                  "KVM_SET_USER_MEMORY_REGION failed: %s", strerror(errno));
        munmap(h->guest_mem, h->guest_mem_size);
        close(h->vm_fd); close(h->kvm_fd); free(h);
        return ABYSS_ERR_KVM;
    }
    h->vcpu_fd[0] = ioctl(h->vm_fd, KVM_CREATE_VCPU, 0);
    if (h->vcpu_fd[0] < 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                  "KVM_CREATE_VCPU failed: %s", strerror(errno));
        munmap(h->guest_mem, h->guest_mem_size);
        close(h->vm_fd); close(h->kvm_fd); free(h);
        return ABYSS_ERR_KVM;
    }
    h->vcpu_count = 1;
    h->running = 0;
    h->total_exits = 0;
    ctx->module_data[ABYSS_MODULE_HYPER] = h;
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER,
              "hypervisor initialized: kvm=%d vm=%d vcpu=%d mem=%zu",
              h->kvm_fd, h->vm_fd, h->vcpu_fd[0], h->guest_mem_size);
    return ABYSS_OK;
}

int abyss_hyper_run(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) {
        if (abyss_hyper_init(ctx) != ABYSS_OK) return ABYSS_ERR_KVM;
        h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    }
    abyss_hyper_intercept_msr(ctx, 0x1A0, 1);
    abyss_hyper_intercept_msr(ctx, 0x199, 1);
    abyss_hyper_intercept_msr(ctx, 0x1B, 1);
    abyss_hyper_intercept_msr(ctx, 0x10, 1);
    abyss_hyper_intercept_pci(ctx, 0, 0, 0);
    h->running = 1;
    if (pthread_create(&h->thread, NULL, hyper_loop, ctx) != 0) {
        abyss_log(ctx, ABYSS_LOG_ERROR, ABYSS_MODULE_HYPER,
                  "pthread_create failed: %s", strerror(errno));
        h->running = 0;
        return ABYSS_ERR;
    }
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER, "hypervisor running");
    return ABYSS_OK;
}

int abyss_hyper_stop(abyss_context_t *ctx) {
    if (!ctx) return ABYSS_ERR;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return ABYSS_OK;
    h->running = 0;
    if (h->thread) {
        pthread_join(h->thread, NULL);
        h->thread = 0;
    }
    abyss_log(ctx, ABYSS_LOG_INFO, ABYSS_MODULE_HYPER,
              "hypervisor stopped: total_exits=%llu", (unsigned long long)h->total_exits);
    return ABYSS_OK;
}

void abyss_hyper_free(abyss_context_t *ctx) {
    if (!ctx) return;
    abyss_hyper_stop(ctx);
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return;
    if (h->vcpu_fd[0] >= 0) close(h->vcpu_fd[0]);
    if (h->vm_fd >= 0) close(h->vm_fd);
    if (h->kvm_fd >= 0) close(h->kvm_fd);
    if (h->guest_mem && h->guest_mem != MAP_FAILED) munmap(h->guest_mem, h->guest_mem_size);
    free(h);
    ctx->module_data[ABYSS_MODULE_HYPER] = NULL;
}

int abyss_hyper_snapshot(abyss_context_t *ctx, abyss_region_t *out, uint32_t max) {
    if (!ctx || !out) return ABYSS_ERR;
    hyper_state_t *h = (hyper_state_t *)ctx->module_data[ABYSS_MODULE_HYPER];
    if (!h) return ABYSS_ERR_KVM;
    uint32_t n = 0;
    if (n < max) {
        out[n].addr = 0;
        out[n].size = h->guest_mem_size;
        out[n].flags = 0;
        out[n].prot = PROT_READ | PROT_WRITE;
        snprintf(out[n].name, sizeof(out[n].name), "guest-mem");
        n++;
    }
    for (uint32_t i = 0; i < h->msr_count && n < max; i++) {
        out[n].addr = h->msr_watch[i].msr;
        out[n].size = sizeof(uint64_t);
        out[n].flags = h->msr_watch[i].enabled;
        out[n].prot = 0;
        snprintf(out[n].name, sizeof(out[n].name), "msr-0x%x", h->msr_watch[i].msr);
        n++;
    }
    return (int)n;
}