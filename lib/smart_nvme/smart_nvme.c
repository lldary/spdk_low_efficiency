#include <spdk/smart_nvme.h>
#include <spdk/nvme.h> // Include the header defining struct spdk_nvme_ctrlr
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <x86gprintrin.h>
#include <spdk/log.h>
#include <rte_log.h>
#include <spdk/spdk_plus_log.h>
#include <spdk/nvme_zns.h>
#include "queue_wrapper.h"           // Include the queue wrapper header
#include "thread_affinity_control.h" // Include the thread affinity control header
#include "cJSON.h"

#ifdef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#undef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#define NS_PER_S 1000000000
#define US_PER_S 1000000
#define CORE_NUMBER 0XFF

#define SPDK_PLUS_MAX_QUEUE_NUM 12

#ifndef __NR_uintr_register_handler
#define __NR_uintr_wait_msix_interrupt 470
#define __NR_uintr_register_handler 471
#define __NR_uintr_unregister_handler 472
#define __NR_uintr_create_fd 473
#define __NR_uintr_register_sender 474
#define __NR_uintr_unregister_sender 475
#define __NR_uintr_wait 476
#endif

#define UINTR_WAIT_EXPERIMENTAL_FLAG 0x1

#define uintr_wait_msix_interrupt(ptr, flags) syscall(__NR_uintr_wait_msix_interrupt, ptr, flags)
#define uintr_register_handler(handler, flags) syscall(__NR_uintr_register_handler, handler, flags)
#define uintr_unregister_handler(flags) syscall(__NR_uintr_unregister_handler, flags)
#define uintr_create_fd(vector, flags) syscall(__NR_uintr_create_fd, vector, flags)
#define uintr_register_sender(fd, flags) syscall(__NR_uintr_register_sender, fd, flags)
#define uintr_unregister_sender(ipi_idx, flags) syscall(__NR_uintr_unregister_sender, ipi_idx, flags)
#define uintr_wait(usec, flags) syscall(__NR_uintr_wait, usec, flags)

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN3(a, b, c) (MIN(MIN((a), (b)), (c)))

#define PORT 11451         // 端口号
#define BACKLOG 10         // 最大连接队列长度
#define EPOLL_SIZE BACKLOG // 定义EPOLL_SIZE为10
#define SPDK_PLUS_BUF_SIZE 4096

enum nvme_io_mode
{
    SPDK_PLUS_READ,
    SPDK_PLUS_WRITE,
    SPDK_PLUS_FLUSH,
};

enum spdk_plus_nvme_control_cmd
{
    SPDK_PLUS_CLEAR_STAT,
};

// TODO: 用户中断调频怎么加进去
// TODO: 硬盘功耗控制
// TODO: 后备写还没有做
// TODO: 回写也也没有做
// TODO: 中断聚合等操作如何利用

struct io_task
{
    enum spdk_plus_monitor_io_size io_size;   /* 统计口径IO大小 */
    enum nvme_io_mode io_mode;                /* 读写模式 */
    uint64_t notify_mode;                     /* 通知模式，注意，中断轮询算作轮询 */
    struct spdk_plus_smart_nvme *nvme_device; /* NVMe设备 */
    spdk_nvme_cmd_cb cb_fn;                   /* 回调函数 */
    struct timespec start_time;               /* 开始时间 */
    void *cb_arg;
};

struct spdk_plus_nvme_thread
{
    uint64_t rsp;
    uint64_t rip;
    uint64_t stack_space[0x10000];
    int64_t flags; /* 记录用户中断标志，帮助恢复 */
};

struct nvme_metadata
{
    struct spdk_nvme_ctrlr *ctrlr;
    struct spdk_plus_nvme_qpair qpair;                 // 后备队列
    struct spdk_plus_smart_nvme_statistics statistics; // 统计信息
    uint64_t cite_number;
    struct spdk_plus_smart_nvme *nvme_qpair[SPDK_PLUS_MAX_QUEUE_NUM]; // NVMe队列对
    TAILQ_ENTRY(nvme_metadata)
    link;
};

struct power_state_cql
{
    uint32_t power_state : 5;
    uint32_t workhint : 3;
    uint32_t reserved : 24;
};

#define local_irq_save(flags) \
    do                        \
    {                         \
        flags = _testui();    \
        _clui();              \
    } while (0)
#define local_irq_restore(flags) \
    do                           \
    {                            \
        if (flags)               \
            _stui();             \
    } while (0)

static void spdk_plus_vlog(enum spdk_log_level level, const char *file, const int line, const char *func,
                           const char *format, va_list ap);
void spdk_plus_switch_thread(struct spdk_plus_nvme_thread *from, struct spdk_plus_nvme_thread *to);

/* 全局变量定义 */
static struct spdk_plus_smart_schedule_module_opts g_smart_schedule_module_opts = {
    .status = SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM,
    .notify_mode = {
        .poll = 1,
        .interrupt = 1,
        .uintr = 1,
        .int_poll = 1,
        .uintr_poll = 1,
    },
    .read_alpha = 0.5,
    .write_alpha = 0.5,
    .enable_back_ssd = true,
};

static struct spdk_log_opts g_log_opts = {
    .log = spdk_plus_vlog,
    .open = NULL,
    .close = NULL,
    .user_ctx = NULL,
    .size = sizeof(struct spdk_log_opts),
};

static const char *const spdk_level_names[] = {
    [SPDK_LOG_ERROR] = "ERROR",
    [SPDK_LOG_WARN] = "WARNING",
    [SPDK_LOG_NOTICE] = "NOTICE",
    [SPDK_LOG_INFO] = "INFO",
    [SPDK_LOG_DEBUG] = "DEBUG",
};

pthread_t g_control_thread; /* 控制线程 */

/* 用于用户中断切换框架 */
struct spdk_plus_nvme_thread *g_curr_thread[CORE_NUMBER]; /* 当前线程 */
struct spdk_plus_nvme_thread *g_work_thread[CORE_NUMBER]; /* IO线程结构 */
struct spdk_plus_nvme_thread *g_idle_thread[CORE_NUMBER]; /* 节能线程结构 */
uint64_t g_cpuid_uipi_map[CORE_NUMBER];                   /* CPU ID到用户中断的映射 */
bool g_io_completion_notify[CORE_NUMBER];                 /* IO完成通知 */
TAILQ_HEAD(, spdk_plus_smart_nvme)
g_qpair_list = TAILQ_HEAD_INITIALIZER(g_qpair_list);
TAILQ_HEAD(, nvme_metadata)
g_nvme_metadata_list = TAILQ_HEAD_INITIALIZER(g_nvme_metadata_list);
pthread_mutex_t meta_mutex;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER; // TODO: 这个要解决
pthread_rwlock_t meta_rwlock = PTHREAD_RWLOCK_INITIALIZER;
uint32_t lba_size = 0;
bool g_spdk_plus_exit = false;
struct spdk_plus_smart_nvme g_back_device; /* 备选 NVMe设备 */
static uint32_t nvme_ctrlr_keep_alive_timeout_in_ms = 10000;
static uint32_t tmp_core = 0;

void __attribute__((interrupt)) __attribute__((target("general-regs-only", "inline-all-stringops")))
uintr_get_handler(struct __uintr_frame *ui_frame,
                  unsigned long long vector)
{
    local_irq_save(g_curr_thread[vector]->flags);
    _senduipi(g_cpuid_uipi_map[vector]);
    if (g_curr_thread[vector] == g_idle_thread[vector])
    {
        spdk_plus_switch_thread(g_idle_thread[vector], g_work_thread[vector]);
        g_curr_thread[vector] = g_idle_thread[vector];
    }
    else
    {
        g_io_completion_notify[vector] = true;
    }
}

static void
get_timestamp_prefix(char *buf, int buf_size)
{
    struct tm *info;
    char date[24];
    struct timespec ts;
    long usec;

    clock_gettime(CLOCK_REALTIME, &ts);
    info = localtime(&ts.tv_sec);
    usec = ts.tv_nsec / 1000;
    if (info == NULL)
    {
        snprintf(buf, buf_size, "[%s.%06ld] ", "unknown date", usec);
        return;
    }

    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", info);
    snprintf(buf, buf_size, "[%s.%06ld] ", date, usec);
}

static void spdk_plus_vlog(enum spdk_log_level level, const char *file, const int line, const char *func,
                           const char *format, va_list ap)
{
    va_list ap_copy;
    int rc;
    char *buf, _buf[SPDK_PLUS_BUF_SIZE], *ext_buf = NULL;
    char timestamp[64];
    pthread_mutex_lock(&log_mutex);
    FILE *fp = fopen("/home/led/workspace/spdk_log.txt", "a"); // TODO: 路径要改成可以设置
    if (fp == NULL)
    {
        perror("Failed to open log file");
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    buf = _buf;

    va_copy(ap_copy, ap);
    rc = vsnprintf(_buf, sizeof(_buf), format, ap);
    if (rc > SPDK_PLUS_BUF_SIZE)
    {
        /* The output including the terminating was more than MAX_TMPBUF bytes.
         * Try allocating memory large enough to hold the output.
         */
        rc = vasprintf(&ext_buf, format, ap_copy);
        if (rc < 0)
        {
            /* Failed to allocate memory. Allow output to be truncated. */
        }
        else
        {
            buf = ext_buf;
        }
    }
    va_end(ap_copy);

    get_timestamp_prefix(timestamp, sizeof(timestamp));
    fprintf(fp, "%s%s:%4d:%s: *%s*: %s", timestamp, file, line, func, spdk_level_names[level], buf);
    fflush(fp);
    free(ext_buf);
    fclose(fp);
    pthread_mutex_unlock(&log_mutex);
    return;
}

static void spdk_plus_idle_thread_func(void)
{
    uint64_t cpu_id;

    // 使用内联汇编将 %rbx 的值赋给 loop
    asm volatile(
        "mov %%r12, %0" // 将 %rbx 的值移动到 loop（%0）
        : "=r"(cpu_id)  // 输出操作数：将 %rbx 的值存储到 loop
    );

    {
        spdk_plus_switch_thread(g_idle_thread[cpu_id], g_work_thread[cpu_id]);
        g_curr_thread[cpu_id] = g_idle_thread[cpu_id];
    }
    uint64_t delay = 20 * spdk_get_ticks_hz() / NS_PER_S;

begin:
    if (!g_io_completion_notify[cpu_id])
    {
        uint64_t sleep_time = _rdtsc() + delay;
        _tpause(0, sleep_time);
        local_irq_save(g_idle_thread[cpu_id]->flags);
    }
    spdk_plus_switch_thread(g_idle_thread[cpu_id], g_work_thread[cpu_id]); // TODO: 看这个能不能去掉，因为是没有意义的
    g_curr_thread[cpu_id] = g_idle_thread[cpu_id];
    goto begin;
}

static int nvme_get_default_threshold_opts(
    struct spdk_plus_nvme_threshold_opts *opts)
{
    // opts->depth_threshold1 = 8;
    // opts->depth_threshold2 = 16;
    // opts->depth_threshold3 = 32;
    opts->depth_threshold1 = 5 * 1000;
    opts->depth_threshold2 = 10 * 1000;
    opts->depth_threshold3 = 25 * 1000;
    return SPDK_PLUS_SUCCESS;
}

static inline enum spdk_plus_monitor_io_size
nvme_get_statistical_io_size(uint32_t lba_count)
{
    enum spdk_plus_monitor_io_size io_size;
    uint32_t io_size_bytes = lba_count * 4096; /* 4K IO TODO: 这个lba大小需要读取 */
    if (io_size_bytes > 2 * 1024 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M;
    }
    else if (io_size_bytes > 1 * 1024 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_2M;
    }
    else if (io_size_bytes > 512 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_1M;
    }
    else if (io_size_bytes > 256 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_512K;
    }
    else if (io_size_bytes > 128 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_256K;
    }
    else if (io_size_bytes > 64 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_128K;
    }
    else if (io_size_bytes > 32 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_64K;
    }
    else if (io_size_bytes > 16 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_32K;
    }
    else if (io_size_bytes > 8 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_16K;
    }
    else if (io_size_bytes > 4 * 1024)
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_8K;
    }
    else
    {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_4K;
    }
    return io_size;
}

static inline void
nvme_sleep(uint64_t ns)
{
    if (ns == 0)
        return;
    switch (g_smart_schedule_module_opts.status)
    {
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
    {
        // if (ns > g_smart_schedule_module_opts.threshold_ns)
        // {
        uint32_t usec = ns / 1000;
        // usec = MIN(usec, usec - 4);
        // uintr_wait(usec, 0);
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = MAX(ns - 50000, 5 * 1000);
        int ret = clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
        // }
        // else
        // {
        //     uint64_t tsc = _rdtsc() + ns * spdk_get_ticks_hz() / NS_PER_S;
        //     _tpause(0, tsc);
        // }
    }
    break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE:
        SPDK_ERRLOG("Super performance mode, no sleep\n");
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM:
        SPDK_ERRLOG("Custom mode, not support\n");
        break;
    default:
        SPDK_ERRLOG("Unknown schedule module status\n");
    }
}

/* 计算指定的队列的睡眠时间 */
static inline uint64_t
nvme_get_sleep_naonotime_internel(struct spdk_plus_smart_nvme *nvme_device, struct spdk_plus_nvme_qpair qpair, struct timespec curr_time)
{
    if (queue_empty(qpair.queue))
    {
        return UINT64_MAX; /* 如果队列为空，返回最大值 */
    }
    struct nvme_timestamp ts = queue_front(qpair.queue);
    uint64_t curr_latency = (curr_time.tv_sec - ts.ts.tv_sec) * 1000000000 + (curr_time.tv_nsec - ts.ts.tv_nsec);
    uint64_t theoretical_latency = 0;
    if (ts.io_size >= SPDK_PLUS_MONITOR_IO_SIZE_TOTAL_NUM)
    {
        SPDK_ERRLOG("IO size is out of range\n");
        return UINT64_MAX;
    }
    if (ts.io_mode == SPDK_PLUS_READ)
    {
        theoretical_latency = nvme_device->statistics->avg_read_latency[ts.io_size] * g_smart_schedule_module_opts.read_sleep_rate;
    }
    else if (ts.io_mode == SPDK_PLUS_WRITE)
    {
        theoretical_latency = nvme_device->statistics->avg_write_latency[ts.io_size] * g_smart_schedule_module_opts.write_sleep_rate;
    }
    else if (ts.io_mode == SPDK_PLUS_FLUSH)
    {
        theoretical_latency = 0; /* 刷新操作不需要休眠 */
    }
    else
    {
        SPDK_ERRLOG("Unknown IO mode\n");
        return UINT64_MAX;
    }
    return curr_latency <= theoretical_latency ? theoretical_latency - curr_latency : 0;
}

/* 用于中断轮询休眠时间计算 */
static inline uint64_t
nvme_get_sleep_nanotime(struct spdk_plus_smart_nvme *nvme_device)
{
    struct timespec curr_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
    uint64_t sleep_time = MIN3(nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->int_qpair, curr_time),
                               nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->uintr_qpair, curr_time),
                               nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->poll_qpair, curr_time));
    if (sleep_time == UINT64_MAX)
    {
        SPDK_ERRLOG("Sleep time is UINT64_MAX\n");
        return sleep_time;
    }
    if (queue_size(nvme_device->int_qpair.queue) +
            queue_size(nvme_device->uintr_qpair.queue) +
            queue_size(nvme_device->poll_qpair.queue) <
        100)
    {
        uint64_t tsc = curr_time.tv_sec * 1000000000 + curr_time.tv_nsec;
        if (nvme_device->least_wait_timestamp > tsc)
        {
            sleep_time = MAX(sleep_time, (nvme_device->least_wait_timestamp - tsc) / 2);
        }
    }
    // sleep_time = MIN(sleep_time, sleep_time - 3000);
    return sleep_time;
}

static struct spdk_nvme_qpair *
nvme_get_suitable_io_qpair(struct spdk_plus_smart_nvme *nvme_device, struct io_task *task, enum nvme_io_mode io_mode)
{
    struct spdk_plus_nvme_qpair *qpair = NULL;
    switch (g_smart_schedule_module_opts.status)
    {
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
        qpair = &nvme_device->int_qpair;
        task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
    {
        uint32_t total_depth = queue_size(nvme_device->int_qpair.queue) +
                               queue_size(nvme_device->uintr_qpair.queue) +
                               queue_size(nvme_device->poll_qpair.queue);
        if (total_depth < nvme_device->threshold_opts.depth_threshold2)
        {
            qpair = &nvme_device->uintr_qpair;
            task->notify_mode = SPDK_PLUS_UINTR_MODE;
        }
        else
        {
            qpair = &nvme_device->int_qpair;
            task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
        }

        switch (task->io_mode)
        {
        case SPDK_PLUS_READ:
            if (nvme_device->statistics->avg_wait_read_latency[task->io_size] <= nvme_device->threshold_opts.depth_threshold2)
            {
                qpair = &nvme_device->uintr_qpair;
                task->notify_mode = SPDK_PLUS_UINTR_MODE;
            }
            else
            {
                qpair = &nvme_device->int_qpair;
                task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            }
            break;
        case SPDK_PLUS_WRITE:
            if (nvme_device->statistics->avg_wait_write_latency[task->io_size] <= nvme_device->threshold_opts.depth_threshold2)
            {
                qpair = &nvme_device->uintr_qpair;
                task->notify_mode = SPDK_PLUS_UINTR_MODE;
            }
            else
            {
                qpair = &nvme_device->int_qpair;
                task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            }
            break;
        case SPDK_PLUS_FLUSH:
            qpair = &nvme_device->uintr_qpair;
            task->notify_mode = SPDK_PLUS_UINTR_MODE;
            break;
        default:
            ERRLOG("Unknown IO mode\n");
            break;
        }
    }
    break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
    {
        uint32_t total_depth = queue_size(nvme_device->int_qpair.queue) +
                               queue_size(nvme_device->uintr_qpair.queue) +
                               queue_size(nvme_device->poll_qpair.queue);
        if (total_depth < nvme_device->threshold_opts.depth_threshold1)
        {
            qpair = &nvme_device->uintr_qpair;
            task->notify_mode = SPDK_PLUS_UINTR_MODE;
        }
        else if (total_depth < nvme_device->threshold_opts.depth_threshold3)
        {
            qpair = &nvme_device->poll_qpair;
            task->notify_mode = SPDK_PLUS_POLL_MODE;
        }
        else
        {
            qpair = &nvme_device->int_qpair;
            task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
        }

        switch (task->io_mode)
        {
        case SPDK_PLUS_READ:
            if (nvme_device->statistics->avg_wait_read_latency[task->io_size] <= nvme_device->threshold_opts.depth_threshold1)
            {
                qpair = &nvme_device->poll_qpair;
                task->notify_mode = SPDK_PLUS_POLL_MODE;
            }
            else if (nvme_device->statistics->avg_wait_read_latency[task->io_size] <= nvme_device->threshold_opts.depth_threshold2)
            {
                qpair = &nvme_device->uintr_qpair;
                task->notify_mode = SPDK_PLUS_UINTR_MODE;
            }
            else
            {
                qpair = &nvme_device->int_qpair;
                task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            }
            break;
        case SPDK_PLUS_WRITE:
            if (nvme_device->statistics->avg_wait_write_latency[task->io_size] <= nvme_device->threshold_opts.depth_threshold1)
            {
                qpair = &nvme_device->poll_qpair;
                task->notify_mode = SPDK_PLUS_POLL_MODE;
            }
            else if (nvme_device->statistics->avg_wait_write_latency[task->io_size] <= nvme_device->threshold_opts.depth_threshold2)
            {
                qpair = &nvme_device->uintr_qpair;
                task->notify_mode = SPDK_PLUS_UINTR_MODE;
            }
            else
            {
                qpair = &nvme_device->int_qpair;
                task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            }
            break;
        case SPDK_PLUS_FLUSH:
            qpair = &nvme_device->uintr_qpair;
            task->notify_mode = SPDK_PLUS_UINTR_MODE;
            break;
        default:
            ERRLOG("Unknown IO mode\n");
            break;
        }
    }
    break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE:
        qpair = &nvme_device->poll_qpair;
        task->notify_mode = SPDK_PLUS_POLL_MODE;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM:
        SPDK_ERRLOG("Custom mode, not support\n");
        break;
    default:
        SPDK_ERRLOG("Unknown schedule module status\n");
    }
    enqueue(qpair->queue, (struct nvme_timestamp){.ts = task->start_time, .io_size = task->io_size, .io_mode = io_mode});
    if (qpair == NULL)
        ERRLOG("qpair is NULL\n");
    switch (task->io_mode)
    {
    case SPDK_PLUS_READ:
    {
        struct timespec ts = task->start_time;
        uint64_t total_time = ts.tv_sec * 1000000000 + ts.tv_nsec + nvme_device->statistics->avg_read_latency[task->io_size];
        if (total_time > nvme_device->least_wait_timestamp)
        {
            nvme_device->least_wait_timestamp = total_time;
        }
    }
    break;
    case SPDK_PLUS_WRITE:
    {
        struct timespec ts = task->start_time;
        uint64_t total_time = ts.tv_sec * 1000000000 + ts.tv_nsec + nvme_device->statistics->avg_write_latency[task->io_size];
        if (total_time > nvme_device->least_wait_timestamp)
        {
            nvme_device->least_wait_timestamp = total_time;
        }
    }
    break;
    case SPDK_PLUS_FLUSH:
        break;
    }
    return qpair->qpair;
}

static void
nvme_ctrlr_io_qpair_opts_copy(struct spdk_nvme_io_qpair_opts *dst,
                              const struct spdk_nvme_io_qpair_opts *src, size_t opts_size_src)
{
    if (!opts_size_src)
    {
        SPDK_ERRLOG("opts_size_src should not be zero value\n");
        assert(false);
    }

#define FIELD_OK(field) \
    offsetof(struct spdk_nvme_io_qpair_opts, field) + sizeof(src->field) <= opts_size_src

#define SET_FIELD(field)         \
    if (FIELD_OK(field))         \
    {                            \
        dst->field = src->field; \
    }

    SET_FIELD(qprio);
    SET_FIELD(io_queue_size);
    SET_FIELD(io_queue_requests);
    SET_FIELD(delay_cmd_submit);
    SET_FIELD(sq.vaddr);
    SET_FIELD(sq.paddr);
    SET_FIELD(sq.buffer_size);
    SET_FIELD(cq.vaddr);
    SET_FIELD(cq.paddr);
    SET_FIELD(cq.buffer_size);
    SET_FIELD(create_only);
    SET_FIELD(async_mode);
    SET_FIELD(disable_pcie_sgl_merge);
    SET_FIELD(interrupt_mode);

    dst->opts_size = opts_size_src;

    /* You should not remove this statement, but need to update the assert statement
     * if you add a new field, and also add a corresponding SET_FIELD statement */
    SPDK_STATIC_ASSERT(sizeof(struct spdk_nvme_io_qpair_opts) == 80, "Incorrect size");

#undef FIELD_OK
#undef SET_FIELD
}

static void
nvme_prepare_uintr_env(void)
{
    int32_t cpu_id = sched_getcpu();
    int flags;
    if (g_curr_thread[cpu_id] != NULL)
    {
        DEBUGLOG("CPU %u already has initalize user interrupt\n", cpu_id);
        return;
    }
#define UINTR_HANDLER_FLAG_WAITING_RECEIVER 0x1000 // TODO: 这个定义也一直需要吗？
    if (uintr_register_handler(uintr_get_handler, UINTR_HANDLER_FLAG_WAITING_RECEIVER))
    {
        SPDK_ERRLOG("Interrupt handler register error");
        exit(EXIT_FAILURE);
    }
    local_irq_save(flags);
    local_irq_restore(flags);
    g_idle_thread[cpu_id] = calloc(1, sizeof(struct spdk_plus_nvme_thread));
    g_work_thread[cpu_id] = calloc(1, sizeof(struct spdk_plus_nvme_thread));
    if (g_idle_thread[cpu_id] == NULL || g_work_thread[cpu_id] == NULL)
    {
        SPDK_ERRLOG("Failed to allocate memory for thread\n");
        exit(EXIT_FAILURE);
    }
    g_idle_thread[cpu_id]->flags = flags;
    g_work_thread[cpu_id]->flags = flags;
    g_idle_thread[cpu_id]->rsp = (uint64_t)((unsigned char *)(g_idle_thread[cpu_id]->stack_space) + sizeof(g_idle_thread[cpu_id]->stack_space) - 0x40);
    g_idle_thread[cpu_id]->rip = (uint64_t)spdk_plus_idle_thread_func;
    g_idle_thread[cpu_id]->stack_space[0xFFFF] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFFE] = (uint64_t)spdk_plus_idle_thread_func;
    g_idle_thread[cpu_id]->stack_space[0xFFFD] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFFC] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFFB] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFFA] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF9] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF8] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF7] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF6] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF5] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF4] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF3] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF2] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF1] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFF0] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFEF] = cpu_id;
    g_idle_thread[cpu_id]->stack_space[0xFFEE] = cpu_id;
    local_irq_save(flags);
    DEBUGLOG("初始化完成用户框架，开始试运行 core id： %u rip: %p %lx\n", cpu_id, spdk_plus_idle_thread_func, *(uint64_t *)(g_idle_thread[cpu_id]->rsp + 0x30));
    spdk_plus_switch_thread(g_work_thread[cpu_id], g_idle_thread[cpu_id]);
    DEBUGLOG("CPU %d 第一次试运行完成\n", cpu_id);
    g_curr_thread[cpu_id] = g_work_thread[cpu_id];
    spdk_plus_switch_thread(g_work_thread[cpu_id], g_idle_thread[cpu_id]);
    g_curr_thread[cpu_id] = g_work_thread[cpu_id];
    local_irq_save(flags);
    DEBUGLOG("试运行成功\n");
}

void *spdk_plus_get_cb_arg(const void *task)
{
    return ((const struct io_task *)task)->cb_arg;
}

static void
power_mode_get_complete(void *ctx, const struct spdk_nvme_cpl *cql)
{
    if (spdk_nvme_cpl_is_error(cql))
    {
        SPDK_ERRLOG("I/O error: %s\n", spdk_nvme_cpl_get_status_string(&cql->status));
    }
    uint32_t cdw0 = cql->cdw0;
    if (ctx == NULL)
        INFOLOG("before change current power state: %u\n", ((struct power_state_cql *)(&cdw0))->power_state);
    else
        INFOLOG("after change current power state: %u\n", ((struct power_state_cql *)(&cdw0))->power_state);
}

static void
power_mode_update_complete(void *ctx, const struct spdk_nvme_cpl *cpl)
{
    struct spdk_nvme_ctrlr *ctrlr = ctx;
    if (spdk_nvme_cpl_is_error(cpl))
    {
        SPDK_ERRLOG("I/O error: %s\n", spdk_nvme_cpl_get_status_string(&cpl->status));
    }
    INFOLOG("Power mode update complete\n");
    if (spdk_nvme_ctrlr_cmd_get_feature(ctrlr, SPDK_NVME_FEAT_POWER_MANAGEMENT, 0,
                                        NULL, 0, power_mode_get_complete, (void *)1) != 0)
    {
        SPDK_ERRLOG("get power state failed\n");
    }
}

struct spdk_plus_smart_nvme *spdk_plus_nvme_ctrlr_alloc_io_device(struct spdk_nvme_ctrlr *ctrlr,
                                                                  const struct spdk_nvme_io_qpair_opts *user_opts,
                                                                  size_t opts_size, int *rc)
{
    DEBUGLOG("正在创建一个新的队列\n");
    struct spdk_plus_smart_nvme *smart_nvme = NULL;
    struct spdk_nvme_io_qpair_opts opts;

    *rc = SPDK_PLUS_SUCCESS;

    /* 设置线程亲和性 */
    int32_t cpu_id = spdk_plus_get_sutiable_core_id(ctrlr);
    if (cpu_id < 0)
    {
        ERRLOG("Failed to get suitable core id\n");
        SPDK_ERRLOG("Failed to get suitable core id\n");
        *rc = cpu_id;
        goto failed;
    }
    spdk_plus_set_thread_affinity(cpu_id);
    DEBUGLOG("设置线程亲和性成功，cpu_id: %d\n", cpu_id);
    SPDK_ERRLOG("[ DEBUG ]设置线程 %u 亲和性成功，cpu_id: %d\n", syscall(SYS_gettid), cpu_id);

    smart_nvme = calloc(1, sizeof(struct spdk_plus_smart_nvme));
    if (!smart_nvme)
    {
        SPDK_ERRLOG("Failed to allocate memory for smart_nvme\n");
        *rc = SPDK_PLUS_ERR_NO_MEMORY;
        goto failed;
    }
    smart_nvme->ctrlr = ctrlr;
    smart_nvme->cpu_id = cpu_id;
    smart_nvme->fd = eventfd(0, EFD_NONBLOCK);
    if (smart_nvme->fd < 0)
    {
        SPDK_ERRLOG("Failed to create eventfd\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        goto failed;
    }
    nvme_get_default_threshold_opts(&smart_nvme->threshold_opts);
    smart_nvme->ns = spdk_nvme_ctrlr_get_ns(ctrlr, 1); // TODO: 所以这个字段不一定有用
    if (!smart_nvme->ns)
    {
        SPDK_ERRLOG("Failed to get default namespace\n");
        *rc = SPDK_PLUS_ERR_SPDK_API_FAILED;
        goto failed;
    }
    spdk_nvme_ctrlr_get_default_io_qpair_opts(ctrlr, &opts, sizeof(opts));
    if (user_opts)
    {
        nvme_ctrlr_io_qpair_opts_copy(&opts, user_opts, MIN(opts.opts_size, opts_size));
        opts_size = MIN(opts.opts_size, opts_size);
    }
    else
        opts_size = opts.opts_size;
    if (opts.interrupt_mode != 0)
    {
        SPDK_ERRLOG("user should not set interrupt mode\n");
        *rc = SPDK_PLUS_ERR_INVALID;
        goto failed;
    }
    // smart_nvme->poll_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair(ctrlr, &opts, opts_size);
    // if (!smart_nvme->poll_qpair.qpair)
    // {
    //     SPDK_ERRLOG("Failed to allocate poll qpair\n");
    //     *rc = SPDK_PLUS_ERR_SPDK_API_FAILED;
    //     goto failed;
    // }
    smart_nvme->poll_qpair.qpair = NULL;
    smart_nvme->poll_qpair.queue = create_queue();
    if (!smart_nvme->poll_qpair.queue)
    {
        SPDK_ERRLOG("Failed to create poll queue\n");
        *rc = SPDK_PLUS_ERR_SYS_API_FAILED;
        goto failed;
    }
    if (g_smart_schedule_module_opts.enable_back_ssd)
    {
        smart_nvme->back_poll_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair(g_back_device.ctrlr, &opts, opts_size);
        if (!smart_nvme->back_poll_qpair.qpair)
        {
            SPDK_ERRLOG("Failed to allocate back poll qpair\n");
            *rc = SPDK_PLUS_ERR_SPDK_API_FAILED;
            goto failed;
        }
        smart_nvme->back_poll_qpair.queue = create_queue();
        if (!smart_nvme->back_poll_qpair.queue)
        {
            SPDK_ERRLOG("Failed to create back poll queue\n");
            *rc = SPDK_PLUS_ERR_SYS_API_FAILED;
            goto failed;
        }
    }
    else
    {
        smart_nvme->back_poll_qpair.qpair = NULL;
        smart_nvme->back_poll_qpair.queue = NULL;
    }
    opts.interrupt_mode = SPDK_PLUS_INTERRUPT_MODE;
    smart_nvme->int_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair_int(ctrlr, &opts, opts_size, &smart_nvme->int_qpair.fd);
    if (!smart_nvme->int_qpair.qpair)
    {
        SPDK_ERRLOG("Failed to allocate int qpair\n");
        *rc = SPDK_PLUS_ERR_SPDK_PLUS_API_FAILED - 2;
        goto failed;
    }
    DEBUGLOG("int qpair fd: %d\n", smart_nvme->int_qpair.fd);
    if (smart_nvme->int_qpair.fd <= 0)
    {
        SPDK_ERRLOG("Failed to get int qpair fd\n");
        *rc = SPDK_PLUS_ERR_SPDK_PLUS_API_FAILED - 3;
        goto failed;
    }
    int flags = fcntl(smart_nvme->int_qpair.fd, F_GETFL, 0);
    if (flags == -1)
    {
        SPDK_ERRLOG("Failed to get flags\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        goto failed;
    }
    DEBUGLOG("正常获取到flags: %d\n", flags);
    if (fcntl(smart_nvme->int_qpair.fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
    {
        SPDK_ERRLOG("Failed to set flags\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        goto failed;
    }
    DEBUGLOG("正常设置flags: %d\n", flags);
    smart_nvme->int_qpair.queue = create_queue();
    if (!smart_nvme->int_qpair.queue)
    {
        SPDK_ERRLOG("Failed to create int queue\n");
        *rc = SPDK_PLUS_ERR_SYS_API_FAILED;
        goto failed;
    }
    DEBUGLOG("正常创建int queue\n");
    nvme_prepare_uintr_env();
    DEBUGLOG("正常创建uintr env\n");
    opts.interrupt_mode = SPDK_PLUS_UINTR_MODE;
    smart_nvme->uintr_qpair.fd = -1;
    smart_nvme->uintr_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair_int(ctrlr, &opts, opts_size, &smart_nvme->uintr_qpair.fd);
    if (!smart_nvme->uintr_qpair.qpair)
    {
        SPDK_ERRLOG("Failed to allocate uintr qpair\n");
        *rc = SPDK_PLUS_ERR_SPDK_PLUS_API_FAILED - 4;
        goto failed;
    }
    smart_nvme->poll_qpair.qpair = smart_nvme->uintr_qpair.qpair;
    smart_nvme->poll_qpair.fd = false; // 代表轮询队列中断没有屏蔽
    spdk_nvme_ctrlr_control_io_qpair_interrupt(smart_nvme->poll_qpair.qpair, true);
    smart_nvme->poll_qpair.fd = true;
    if (smart_nvme->uintr_qpair.fd < 0)
    {
        SPDK_ERRLOG("Failed to get uintr qpair fd\n");
        *rc = SPDK_PLUS_ERR_SPDK_PLUS_API_FAILED - 5;
        goto failed;
    }
    int uipi_index = uintr_register_sender(smart_nvme->uintr_qpair.fd, 0);
    if (uipi_index < 0)
    {
        ERRLOG("Unable to register sender fd=%d rc=%d\n", smart_nvme->uintr_qpair.fd, uipi_index);
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        goto failed;
    }
    smart_nvme->uintr_qpair.uipi_index = uipi_index;
    g_cpuid_uipi_map[smart_nvme->cpu_id] = uipi_index;
    DEBUGLOG("uipi_index: %d\n", uipi_index);
    DEBUGLOG("用户中断相关寄存器已预先填充\n");
    smart_nvme->uintr_qpair.queue = create_queue();
    DEBUGLOG("相关队列已创建\n");
    if (!smart_nvme->uintr_qpair.queue)
    {
        SPDK_ERRLOG("Failed to create uintr queue\n");
        *rc = SPDK_PLUS_ERR_SYS_API_FAILED;
        goto failed;
    }
    memset(smart_nvme->last_five_read_latency, 0, sizeof(smart_nvme->last_five_read_latency));
    memset(smart_nvme->last_five_write_latency, 0, sizeof(smart_nvme->last_five_write_latency));
    memset(smart_nvme->last_five_read_wait_latency, 0, sizeof(smart_nvme->last_five_read_wait_latency));
    memset(smart_nvme->last_five_write_wait_latency, 0, sizeof(smart_nvme->last_five_write_wait_latency));
    // memset(smart_nvme->statistics->avg_write_latency, 0, sizeof(smart_nvme->statistics->avg_write_latency));
    // memset(smart_nvme->statistics->avg_read_latency, 0, sizeof(smart_nvme->statistics->avg_read_latency));
    // memset(smart_nvme->statistics->avg_wait_read_latency, 0, sizeof(smart_nvme->statistics->avg_wait_read_latency));
    // memset(smart_nvme->statistics->avg_wait_write_latency, 0, sizeof(smart_nvme->statistics->avg_wait_write_latency));
    struct nvme_metadata *nvme_meta = NULL;
    if (pthread_rwlock_wrlock(&meta_rwlock) != 0)
    {
        SPDK_ERRLOG("Failed to lock mutex\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        return NULL;
    }
    DEBUGLOG("数组已清零\n");
    TAILQ_INSERT_TAIL(&g_qpair_list, smart_nvme, link);
    DEBUGLOG("已将该qpair添加到全局队列中管理\n");
    TAILQ_FOREACH(nvme_meta, &g_nvme_metadata_list, link)
    {
        if (nvme_meta->ctrlr == ctrlr)
        {
            nvme_meta->cite_number++;
            smart_nvme->curr_cite_num = 1;
            nvme_meta->nvme_qpair[smart_nvme->cpu_id % SPDK_PLUS_MAX_QUEUE_NUM] = smart_nvme;
            smart_nvme->statistics = &(nvme_meta->statistics);
            if (pthread_rwlock_unlock(&meta_rwlock) != 0)
            {
                SPDK_ERRLOG("Failed to unlock mutex\n");
                *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
                goto failed;
            }
            spdk_plus_unset_thread_affinity();
            return smart_nvme;
        }
    }
    nvme_meta = calloc(1, sizeof(struct nvme_metadata));
    if (!nvme_meta)
    {
        SPDK_ERRLOG("Failed to allocate memory for nvme_meta\n");
        pthread_rwlock_unlock(&meta_rwlock);
        *rc = SPDK_PLUS_ERR_NO_MEMORY;
        goto failed;
    }
    memset(nvme_meta, 0, sizeof(struct nvme_metadata));
    smart_nvme->statistics = &(nvme_meta->statistics);
    nvme_meta->ctrlr = ctrlr;
    // if (spdk_nvme_ctrlr_cmd_set_feature(nvme_meta->ctrlr,
    //                                     SPDK_NVME_FEAT_POWER_MANAGEMENT,
    //                                     2, 0,
    //                                     NULL, 0, power_mode_update_complete, nvme_meta->ctrlr) != 0)
    // {
    //     ERRLOG("set power state failed\n");
    //     *rc = SPDK_PLUS_ERR_SPDK_API_FAILED;
    //     goto failed;
    // }
    opts.interrupt_mode = SPDK_PLUS_INTERRUPT_MODE;
    nvme_meta->qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair_int(ctrlr, &opts, opts_size, &nvme_meta->qpair.fd);
    if (!nvme_meta->qpair.qpair)
    {
        SPDK_ERRLOG("Failed to allocate nvme_meta qpair\n");
        *rc = SPDK_PLUS_ERR_SPDK_PLUS_API_FAILED - 6;
        pthread_rwlock_unlock(&meta_rwlock);
        free(nvme_meta);
        goto failed;
    }
    if (nvme_meta->qpair.fd < 0)
    {
        SPDK_ERRLOG("Failed to get nvme_meta qpair fd\n");
        *rc = SPDK_PLUS_ERR_SPDK_PLUS_API_FAILED - 7;
        pthread_rwlock_unlock(&meta_rwlock);
        free(nvme_meta);
        goto failed;
    }
    flags = fcntl(nvme_meta->qpair.fd, F_GETFL, 0);
    if (flags == -1)
    {
        SPDK_ERRLOG("Failed to get flags\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        pthread_rwlock_unlock(&meta_rwlock);
        free(nvme_meta);
        goto failed;
    }
    if (fcntl(nvme_meta->qpair.fd, F_SETFL, flags & ~O_NONBLOCK) == -1)
    {
        SPDK_ERRLOG("Failed to set flags\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        pthread_rwlock_unlock(&meta_rwlock);
        free(nvme_meta);
        goto failed;
    }
    nvme_meta->qpair.queue = create_queue();
    if (!nvme_meta->qpair.queue)
    {
        SPDK_ERRLOG("Failed to create nvme_meta queue\n");
        *rc = SPDK_PLUS_ERR_SYS_API_FAILED;
        pthread_rwlock_unlock(&meta_rwlock);
        free(nvme_meta);
        goto failed;
    }
    nvme_meta->cite_number = 1;
    smart_nvme->curr_cite_num = 1;
    nvme_meta->nvme_qpair[smart_nvme->cpu_id % SPDK_PLUS_MAX_QUEUE_NUM] = smart_nvme;
    TAILQ_INSERT_TAIL(&g_nvme_metadata_list, nvme_meta, link);
    if (pthread_rwlock_unlock(&meta_rwlock) != 0)
    {
        SPDK_ERRLOG("Failed to unlock mutex\n");
        *rc = SPDK_PLUS_ERR_KERNEL_API_FAILED;
        goto failed;
    }
    SPDK_ERRLOG("[ DEBUG ]nvme_meta->qpair->fd: %d\n", nvme_meta->qpair.fd);
    spdk_plus_unset_thread_affinity();
    return smart_nvme;

failed:
    if (smart_nvme)
    {
        if (smart_nvme->poll_qpair.qpair)
        {
            // spdk_nvme_ctrlr_free_io_qpair(smart_nvme->poll_qpair.qpair);
        }
        if (smart_nvme->int_qpair.qpair)
        {
            spdk_nvme_ctrlr_free_io_qpair(smart_nvme->int_qpair.qpair);
        }
        if (smart_nvme->uintr_qpair.qpair)
        {
            spdk_nvme_ctrlr_free_io_qpair(smart_nvme->uintr_qpair.qpair);
        }
        if (smart_nvme->back_poll_qpair.qpair)
        {
            spdk_nvme_ctrlr_free_io_qpair(smart_nvme->back_poll_qpair.qpair);
        }
        if (smart_nvme->int_qpair.fd > 0)
        {
            close(smart_nvme->int_qpair.fd);
        }
        if (smart_nvme->uintr_qpair.fd > 0)
        {
            if (smart_nvme->uintr_qpair.uipi_index > 0)
            {
                uintr_unregister_sender(smart_nvme->uintr_qpair.uipi_index, 0);
            }
            close(smart_nvme->uintr_qpair.fd);
        }
        if (smart_nvme->fd > 0)
        {
            close(smart_nvme->fd);
        }
        free(smart_nvme);
    }
    return NULL;
}

static void io_complete(void *t, const struct spdk_nvme_cpl *completion)
{
    struct io_task *task = (struct io_task *)t;
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    uint64_t latency = (end_time.tv_sec - task->start_time.tv_sec) * 1000000000 + (end_time.tv_nsec - task->start_time.tv_nsec);
    struct spdk_plus_smart_nvme *nvme_device = task->nvme_device;
    nvme_device->statistics->finish_io_count++;
    uint64_t wait_latency = (end_time.tv_sec - nvme_device->start_wait_timestamp.tv_sec) * 1000000000 + (end_time.tv_nsec - nvme_device->start_wait_timestamp.tv_nsec);
    if (task->io_mode == SPDK_PLUS_READ)
    {
        // nvme_device->last_five_read_latency[task->io_size][nvme_device->read_pos] = latency;
        // nvme_device->last_five_read_wait_latency[task->io_size][nvme_device->read_pos] = wait_latency;
        // nvme_device->read_pos = (nvme_device->read_pos + 1) % 5;
        // latency = (nvme_device->last_five_read_latency[task->io_size][0] +
        //            nvme_device->last_five_read_latency[task->io_size][1] +
        //            nvme_device->last_five_read_latency[task->io_size][2] +
        //            nvme_device->last_five_read_latency[task->io_size][3] +
        //            nvme_device->last_five_read_latency[task->io_size][4]) /
        //           5;
        // wait_latency = (nvme_device->last_five_read_wait_latency[task->io_size][0] +
        //                 nvme_device->last_five_read_wait_latency[task->io_size][1] +
        //                 nvme_device->last_five_read_wait_latency[task->io_size][2] +
        //                 nvme_device->last_five_read_wait_latency[task->io_size][3] +
        //                 nvme_device->last_five_read_wait_latency[task->io_size][4]) /
        //                5;

        nvme_device->statistics->avg_read_latency[task->io_size] = g_smart_schedule_module_opts.read_alpha * latency +
                                                                   (1 - g_smart_schedule_module_opts.read_alpha) * nvme_device->statistics->avg_read_latency[task->io_size]; /* 指数加权移动平均 */
        nvme_device->statistics->avg_wait_read_latency[task->io_size] = g_smart_schedule_module_opts.read_alpha * wait_latency +
                                                                        (1 - g_smart_schedule_module_opts.read_alpha) * nvme_device->statistics->avg_wait_read_latency[task->io_size]; /* 指数加权移动平均 */
        // nvme_device->avg_read_latency[task->io_size] = nvme_device->avg_read_latency[task->io_size] > latency ? latency : nvme_device->avg_read_latency[task->io_size] + 1000;                          /* 指数加权移动平均 */
        // nvme_device->avg_wait_read_latency[task->io_size] = nvme_device->avg_wait_read_latency[task->io_size] > wait_latency ? wait_latency : nvme_device->avg_wait_read_latency[task->io_size] + 1000; /* 指数加权移动平均 */
    }
    else if (task->io_mode == SPDK_PLUS_WRITE)
    {
        // nvme_device->last_five_write_latency[task->io_size][nvme_device->write_pos] = latency;
        // nvme_device->last_five_write_wait_latency[task->io_size][nvme_device->write_pos] = wait_latency;
        // nvme_device->write_pos = (nvme_device->write_pos + 1) % 5;
        // latency = (nvme_device->last_five_write_latency[task->io_size][0] +
        //            nvme_device->last_five_write_latency[task->io_size][1] +
        //            nvme_device->last_five_write_latency[task->io_size][2] +
        //            nvme_device->last_five_write_latency[task->io_size][3] +
        //            nvme_device->last_five_write_latency[task->io_size][4]) /
        //           5;
        // wait_latency = (nvme_device->last_five_write_wait_latency[task->io_size][0] +
        //                 nvme_device->last_five_write_wait_latency[task->io_size][1] +
        //                 nvme_device->last_five_write_wait_latency[task->io_size][2] +
        //                 nvme_device->last_five_write_wait_latency[task->io_size][3] +
        //                 nvme_device->last_five_write_wait_latency[task->io_size][4]) /
        //                5;
        nvme_device->statistics->avg_write_latency[task->io_size] = g_smart_schedule_module_opts.write_alpha * latency +
                                                                    (1 - g_smart_schedule_module_opts.write_alpha) * nvme_device->statistics->avg_write_latency[task->io_size]; /* 指数加权移动平均 */
        nvme_device->statistics->avg_wait_write_latency[task->io_size] = g_smart_schedule_module_opts.write_alpha * wait_latency +
                                                                         (1 - g_smart_schedule_module_opts.write_alpha) * nvme_device->statistics->avg_wait_write_latency[task->io_size]; /* 指数加权移动平均 */
        // nvme_device->avg_write_latency[task->io_size] = nvme_device->avg_write_latency[task->io_size] > latency ? latency : nvme_device->avg_write_latency[task->io_size] + 500;                          /* 指数加权移动平均 */
        // nvme_device->avg_wait_write_latency[task->io_size] = nvme_device->avg_wait_write_latency[task->io_size] > wait_latency ? wait_latency : nvme_device->avg_wait_write_latency[task->io_size] + 500; /* 指数加权移动平均 */
    }
    if (task->notify_mode == SPDK_PLUS_POLL_MODE)
    {
        dequeue(nvme_device->poll_qpair.queue);
    }
    else if (task->notify_mode == SPDK_PLUS_INTERRUPT_MODE)
    {
        dequeue(nvme_device->int_qpair.queue);
    }
    else if (task->notify_mode == SPDK_PLUS_UINTR_MODE)
    {
        dequeue(nvme_device->uintr_qpair.queue);
    }
    else if (task->notify_mode == SPDK_PLUS_INT_POLL_MODE)
    {
        dequeue(nvme_device->poll_qpair.queue);
    }
    else if (task->notify_mode == SPDK_PLUS_UINTR_POLL_MODE)
    {
        dequeue(nvme_device->poll_qpair.queue);
    }
    else
    {
        SPDK_ERRLOG("Unknown notify mode\n");
        free(task);
        return;
    }

    if (task->cb_fn)
    {
        task->cb_fn(task->cb_arg, completion);
    }
    free(task);
    return;
}

static void update_stat(uint32_t lba_count, struct spdk_plus_smart_nvme *nvme_device, enum nvme_io_mode io_mode)
{
    uint64_t value = 0;
    if (read(nvme_device->fd, &value, sizeof(value)) != sizeof(value))
    {
        if (errno != EAGAIN)
        {
            SPDK_ERRLOG("Failed to read from eventfd\n");
        }
        else
        {
            switch (io_mode)
            {
            case SPDK_PLUS_READ:
                nvme_device->statistics->io_read_btypes += lba_count * lba_size;
                break;
            case SPDK_PLUS_WRITE:
                nvme_device->statistics->io_write_btypes += lba_count * lba_size;
                break;
            case SPDK_PLUS_FLUSH:
                break;
            default:
                SPDK_ERRLOG("Unknown IO mode\n");
            }
            return;
        }
    }
    else
    {
        switch (io_mode)
        {
        case SPDK_PLUS_READ:
            nvme_device->statistics->io_read_btypes = lba_count * lba_size;
            break;
        case SPDK_PLUS_WRITE:
            nvme_device->statistics->io_write_btypes = lba_count * lba_size;
            break;
        case SPDK_PLUS_FLUSH:
            break;
        default:
            SPDK_ERRLOG("Unknown IO mode\n");
        }
    }
}

static inline void update_uipi_stat(struct spdk_plus_smart_nvme *nvme_device)
{
    // if (g_cpuid_uipi_map[nvme_device->cpu_id] == 0)
    // {
    //     g_cpuid_uipi_map[nvme_device->cpu_id] = nvme_device->uintr_qpair.uipi_index;
    // }
    if (queue_size(nvme_device->poll_qpair.queue) > 0 && nvme_device->poll_qpair.fd == false)
    {
        int rc = spdk_nvme_ctrlr_control_io_qpair_interrupt(nvme_device->poll_qpair.qpair, true);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to disable interrupt for qpair\n");
            return NULL;
        }
        nvme_device->poll_qpair.fd = true;
    }
    else if (queue_size(nvme_device->poll_qpair.queue) == 0 && nvme_device->poll_qpair.fd == true)
    {
        int rc = spdk_nvme_ctrlr_control_io_qpair_interrupt(nvme_device->poll_qpair.qpair, false);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to enable interrupt for qpair\n");
            return NULL;
        }
        nvme_device->poll_qpair.fd = false;
    }
    return;
}

int spdk_plus_nvme_ns_cmd_read(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device, void *buffer,
                               uint64_t lba,
                               uint32_t lba_count, spdk_nvme_cmd_cb cb_fn, void *cb_arg,
                               uint32_t io_flags)
{
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    update_uipi_stat(nvme_device);

    task = calloc(1, sizeof(struct io_task));
    if (!task)
    {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_READ;
    task->io_size = nvme_get_statistical_io_size(lba_count);
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->cb_arg = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_READ);
    if (!qpair)
    {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }

    rc = spdk_nvme_ns_cmd_read(ns, qpair, buffer, lba, lba_count,
                               io_complete, (void *)task, io_flags);
    return rc;

failed:
    if (task)
    {
        free(task);
    }
    return rc;
}

int spdk_plus_nvme_ns_cmd_readv(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
                                uint64_t lba, uint32_t lba_count,
                                spdk_nvme_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
                                spdk_nvme_req_reset_sgl_cb reset_sgl_fn,
                                spdk_nvme_req_next_sge_cb next_sge_fn)
{
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    update_uipi_stat(nvme_device);

    task = calloc(1, sizeof(struct io_task));
    if (!task)
    {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_READ;
    task->io_size = nvme_get_statistical_io_size(lba_count);
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->cb_arg = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_READ);
    if (!qpair)
    {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }

    rc = spdk_nvme_ns_cmd_readv(ns, qpair, lba, lba_count,
                                io_complete, task, io_flags,
                                reset_sgl_fn, next_sge_fn);
    update_stat(lba_count, nvme_device, SPDK_PLUS_READ);
    return rc;

failed:
    if (task)
    {
        free(task);
    }
    return rc;
}

int spdk_plus_nvme_ns_cmd_write(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
                                void *buffer, uint64_t lba,
                                uint32_t lba_count, spdk_nvme_cmd_cb cb_fn, void *cb_arg,
                                uint32_t io_flags)
{
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    update_uipi_stat(nvme_device);

    task = calloc(1, sizeof(struct io_task));
    if (!task)
    {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_WRITE;
    task->io_size = nvme_get_statistical_io_size(lba_count);
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->cb_arg = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_WRITE);
    if (!qpair)
    {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }

    rc = spdk_nvme_ns_cmd_write(ns, qpair, buffer, lba, lba_count,
                                io_complete, (void *)task, io_flags);
    if (rc < 0)
        ERRLOG("spdk_nvme_ns_cmd_writev failed rc = %d\n", rc);
    update_stat(lba_count, nvme_device, SPDK_PLUS_WRITE);
    return rc;

failed:
    if (task)
    {
        free(task);
    }
    return rc;
}

int spdk_plus_nvme_ns_cmd_writev(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
                                 uint64_t lba, uint32_t lba_count,
                                 spdk_nvme_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
                                 spdk_nvme_req_reset_sgl_cb reset_sgl_fn,
                                 spdk_nvme_req_next_sge_cb next_sge_fn)
{
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    update_uipi_stat(nvme_device);

    task = calloc(1, sizeof(struct io_task));
    if (!task)
    {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_WRITE;
    task->io_size = nvme_get_statistical_io_size(lba_count);
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->cb_arg = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_WRITE);
    if (!qpair)
    {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }

    rc = spdk_nvme_ns_cmd_writev(ns, qpair, lba, lba_count,
                                 io_complete, (void *)task, io_flags,
                                 reset_sgl_fn, next_sge_fn);
    if (rc < 0)
        ERRLOG("spdk_nvme_ns_cmd_writev failed rc = %d\n", rc);
    update_stat(lba_count, nvme_device, SPDK_PLUS_WRITE);
    return rc;

failed:
    if (task)
    {
        free(task);
    }
    return rc;
}

static int32_t nvme_process_completions_poll(struct spdk_plus_smart_nvme *nvme_device,
                                             uint32_t max_completions)
{
    int32_t rc = 0;
    int32_t tmp_rc = 0;
    bool no_limited = max_completions == 0;
    if (!queue_empty(nvme_device->poll_qpair.queue))
    { // 轮询所在的qpair有未完成命令
        tmp_rc = spdk_nvme_qpair_process_completions(nvme_device->poll_qpair.qpair, max_completions);
        if (tmp_rc < 0)
        {
            return tmp_rc;
        }
        rc += tmp_rc;
        max_completions = no_limited ? 0 : max_completions - tmp_rc;
        tmp_rc = 0;
        if (!no_limited && max_completions == 0)
        {
            return rc;
        }
    }
    if (!queue_empty(nvme_device->int_qpair.queue))
    { // 内核中断所在的qpair有未完成命令
        tmp_rc = spdk_nvme_qpair_process_completions(nvme_device->int_qpair.qpair, max_completions);
        if (tmp_rc < 0)
        {
            return tmp_rc;
        }
        rc += tmp_rc;
        max_completions = no_limited ? 0 : max_completions - tmp_rc;
        tmp_rc = 0;
        if (!no_limited && max_completions == 0)
        {
            return rc;
        }
    }
    if (!queue_empty(nvme_device->uintr_qpair.queue))
    { // 用户中断所在的qpair有未完成命令
        tmp_rc = spdk_nvme_qpair_process_completions(nvme_device->uintr_qpair.qpair, max_completions);
        if (tmp_rc < 0)
        {
            return tmp_rc;
        }
        rc += tmp_rc;
    }
    return rc;
}

int32_t spdk_plus_nvme_process_completions(struct spdk_plus_smart_nvme *nvme_device,
                                           uint32_t max_completions)
{
    int32_t rc = 0;

    // update_uipi_stat(nvme_device);

    clock_gettime(CLOCK_MONOTONIC_RAW, &nvme_device->start_wait_timestamp);

    if (!queue_empty(nvme_device->poll_qpair.queue))
    { // 轮询所在的qpair有未完成命令
        switch (g_smart_schedule_module_opts.status)
        {
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE: /* 和轮询模式形态一致 */
        {
            return nvme_process_completions_poll(nvme_device, max_completions);
        }
        break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
        {
            int32_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
            if (tmp_rc != 0)
            {
                return tmp_rc;
            }
            uint64_t sleep_time = nvme_get_sleep_nanotime(nvme_device);
            nvme_sleep(sleep_time);
            while (1)
            {
                int32_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                if (tmp_rc != 0)
                {
                    return tmp_rc;
                }
                // _tpause(0, _rdtsc() + 100);
                usleep(5);
            }
            return 0;
        }
        break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM:
        {
            SPDK_ERRLOG("Custom mode, not support\n");
            return SPDK_PLUS_ERR_NOT_SUPPORTED;
        }
        break;
        default:
            SPDK_ERRLOG("Unknown schedule module status\n");
            return SPDK_PLUS_ERR_INVALID;
        }
    }
    if (!queue_empty(nvme_device->uintr_qpair.queue))
    { // 用户中断所在的qpair有未完成命令
        if (queue_empty(nvme_device->int_qpair.queue))
        { // 内核中断所在的qpair没有未完成命令
            /* 所以直接按照用户中断部署的结构来部署即可 */
            if (sched_getcpu() != nvme_device->cpu_id)
            {
                SPDK_ERRLOG("CPU ID is not match\n");
                return SPDK_PLUS_ERR;
            }
            spdk_plus_switch_thread(g_work_thread[nvme_device->cpu_id], g_work_thread[nvme_device->cpu_id]);
            _senduipi(nvme_device->uintr_qpair.uipi_index);
        again:
            do
            {
                g_io_completion_notify[nvme_device->cpu_id] = false;
                local_irq_restore(g_curr_thread[nvme_device->cpu_id]->flags);
                int32_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                if (tmp_rc < 0)
                {
                    local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                    return tmp_rc;
                }
                rc += tmp_rc;
                if (tmp_rc > 0)
                { // 达到最小数目
                    local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                    return rc;
                }
            } while (g_io_completion_notify[nvme_device->cpu_id]);
            /* 看来还需要等待 */
            spdk_plus_switch_thread(g_work_thread[nvme_device->cpu_id], g_idle_thread[nvme_device->cpu_id]);
            g_curr_thread[nvme_device->cpu_id] = g_work_thread[nvme_device->cpu_id];
            goto again;
        }
        else
        {
            struct timespec curr_time;
            clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
            uint64_t uintr_arrival_time = nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->uintr_qpair, curr_time);
            uint64_t int_arrival_time = nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->int_qpair, curr_time);
            if (uintr_arrival_time == UINT64_MAX || int_arrival_time == UINT64_MAX)
            {
                SPDK_ERRLOG("Sleep time is UINT64_MAX\n");
                return SPDK_PLUS_ERR;
            }
            if (uintr_arrival_time <= int_arrival_time)
            {
                /* 用户中断的时间戳小于等于内核中断的时间戳 */
                if (sched_getcpu() != nvme_device->cpu_id)
                {
                    SPDK_ERRLOG("CPU ID is not match\n");
                    return SPDK_PLUS_ERR;
                }
                spdk_plus_switch_thread(g_work_thread[nvme_device->cpu_id], g_work_thread[nvme_device->cpu_id]);
            next:
                do
                {
                    g_io_completion_notify[nvme_device->cpu_id] = false;
                    local_irq_restore(g_curr_thread[nvme_device->cpu_id]->flags);
                    int32_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                    if (tmp_rc < 0)
                    {
                        local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                        return tmp_rc;
                    }
                    rc += tmp_rc;
                    if (tmp_rc > 0)
                    { // 达到最小数目
                        local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                        return rc;
                    }
                } while (g_io_completion_notify[nvme_device->cpu_id]);
                /* 看来还需要等待 */
                spdk_plus_switch_thread(g_work_thread[nvme_device->cpu_id], g_idle_thread[nvme_device->cpu_id]);
                g_curr_thread[nvme_device->cpu_id] = g_work_thread[nvme_device->cpu_id];
                goto next;
            }
            else
            {
                /* 用户中断的时间戳大于内核中断的时间戳 */
                while (1)
                {
                    uint64_t value = 0;
                    if (read(nvme_device->int_qpair.fd, &value, sizeof(value)) != sizeof(value))
                    {
                        SPDK_ERRLOG("Failed to read from int qpair fd\n");
                        return SPDK_PLUS_ERR;
                    }
                    int32_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                    if (tmp_rc < 0)
                    {
                        return tmp_rc;
                    }
                    rc += tmp_rc;
                    if (tmp_rc > 0)
                    {
                        return rc;
                    }
                }
            }
        }
    }
    if (!queue_empty(nvme_device->int_qpair.queue))
    { // 内核中断所在的qpair有未完成命令
        while (1)
        {
            uint64_t value = 0;
            if (read(nvme_device->int_qpair.fd, &value, sizeof(value)) != sizeof(value))
            {
                SPDK_ERRLOG("Failed to read from int qpair fd\n");
                return SPDK_PLUS_ERR;
            }
            int32_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
            if (tmp_rc < 0)
            {
                return tmp_rc;
            }
            rc += tmp_rc;
            if (tmp_rc > 0)
            {
                return rc;
            }
        }
    }
    // WARNLOG("All qpair are empty\n");
    return 0;
}

int spdk_plus_nvme_ns_cmd_flush(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
                                spdk_nvme_cmd_cb cb_fn, void *cb_arg)
{
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    update_uipi_stat(nvme_device);

    task = calloc(1, sizeof(struct io_task));
    if (!task)
    {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_FLUSH;
    task->io_size = SPDK_PLUS_MONITOR_FLUSH;
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->cb_arg = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_FLUSH);
    if (!qpair)
    {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    rc = spdk_nvme_ns_cmd_flush(ns, qpair, io_complete, task);
    if (rc != 0)
    {
        SPDK_ERRLOG("Failed to send flush command\n");
        goto failed;
    }
    return rc;

failed:
    if (task)
    {
        free(task);
    }
    return rc;
}

static int
spdk_plus_get_default_opts(enum spdk_plus_smart_schedule_module_status status,
                           struct spdk_plus_smart_schedule_module_opts *opts)
{
    opts->status = status;
    switch (status)
    {
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
        opts->read_sleep_rate = 0.99;
        opts->write_sleep_rate = 0.99;
        opts->read_alpha = 0.5;
        opts->write_alpha = 0.5;
        opts->threshold_ns = 50000; /* 50us */
        opts->enable_back_ssd = true;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
        opts->read_sleep_rate = 0.9;
        opts->write_sleep_rate = 0.9;
        opts->read_alpha = 0.5;
        opts->write_alpha = 0.5;
        opts->threshold_ns = 50000; /* 50us */
        opts->enable_back_ssd = true;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
        opts->read_sleep_rate = 0.8;
        opts->write_sleep_rate = 0.8;
        opts->read_alpha = 0.5;
        opts->write_alpha = 0.5;
        opts->threshold_ns = 50000; /* 50us */
        opts->enable_back_ssd = false;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
        opts->read_sleep_rate = 0.7;
        opts->write_sleep_rate = 0.7;
        opts->read_alpha = 0.5;
        opts->write_alpha = 0.5;
        opts->threshold_ns = 50000; /* 50us */
        opts->enable_back_ssd = false;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE:
        opts->read_sleep_rate = 0.2;
        opts->write_sleep_rate = 0.2;
        opts->read_alpha = 0.5;
        opts->write_alpha = 0.5;
        opts->threshold_ns = 50000; /* 50us */
        opts->enable_back_ssd = false;
        break;
    case SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM:
        SPDK_ERRLOG("Custom mode, not support\n");
        return SPDK_PLUS_ERR_NOT_SUPPORTED;
    default:
        SPDK_ERRLOG("Unknown schedule module status\n");
        return SPDK_PLUS_ERR_INVALID;
    }
    return SPDK_PLUS_SUCCESS;
}

static void
spdk_plus_print_statistical_data(int client_id)
{
    struct spdk_plus_smart_nvme *smart_nvme = NULL;
    char buffer[SPDK_PLUS_BUF_SIZE] = {0};
    cJSON *array = cJSON_CreateArray();
    if (array == NULL)
    {
        SPDK_ERRLOG("Failed to create JSON array\n");
        return;
    }
    pthread_rwlock_rdlock(&meta_rwlock);
    TAILQ_FOREACH(smart_nvme, &g_qpair_list, link)
    {
        if (smart_nvme->ctrlr == NULL)
        {
            SPDK_ERRLOG("Controller is NULL\n");
            continue;
        }
        cJSON *object = cJSON_CreateObject();
        if (object == NULL)
        {
            SPDK_ERRLOG("Failed to create JSON object\n");
            cJSON_Delete(array);
            return;
        }
        cJSON_AddStringToObject(object, "Device", spdk_nvme_ctrlr_get_transport_id(smart_nvme->ctrlr)->traddr);
        cJSON_AddNumberToObject(object, "Current Poll Depth", smart_nvme->poll_io_depth);
        cJSON_AddNumberToObject(object, "Current Uintr Depth", smart_nvme->uintr_io_depth);
        cJSON_AddNumberToObject(object, "Current Int Depth", smart_nvme->int_io_depth);
        cJSON_AddNumberToObject(object, "finish IO Count", smart_nvme->statistics->finish_io_count);
        cJSON *read_latency = cJSON_CreateObject();
        if (read_latency == NULL)
        {
            SPDK_ERRLOG("Failed to create JSON object\n");
            cJSON_Delete(object);
            cJSON_Delete(array);
            return;
        }
        cJSON_AddNumberToObject(read_latency, "4k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_4K]);
        cJSON_AddNumberToObject(read_latency, "8k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_8K]);
        cJSON_AddNumberToObject(read_latency, "16k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_16K]);
        cJSON_AddNumberToObject(read_latency, "32k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_32K]);
        cJSON_AddNumberToObject(read_latency, "64k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_64K]);
        cJSON_AddNumberToObject(read_latency, "128k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_128K]);
        cJSON_AddNumberToObject(read_latency, "256k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_256K]);
        cJSON_AddNumberToObject(read_latency, "512k", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_512K]);
        cJSON_AddNumberToObject(read_latency, "1M", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_1M]);
        cJSON_AddNumberToObject(read_latency, "2M", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_2M]);
        cJSON_AddNumberToObject(read_latency, "Over 2M", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M]);
        cJSON_AddNumberToObject(read_latency, "flush", smart_nvme->statistics->avg_read_latency[SPDK_PLUS_MONITOR_FLUSH]);
        cJSON_AddItemToObject(object, "Read Latency", read_latency);
        cJSON *write_latency = cJSON_CreateObject();
        if (write_latency == NULL)
        {
            SPDK_ERRLOG("Failed to create JSON object\n");
            cJSON_Delete(read_latency);
            cJSON_Delete(object);
            cJSON_Delete(array);
            return;
        }
        cJSON_AddNumberToObject(write_latency, "4k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_4K]);
        cJSON_AddNumberToObject(write_latency, "8k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_8K]);
        cJSON_AddNumberToObject(write_latency, "16k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_16K]);
        cJSON_AddNumberToObject(write_latency, "32k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_32K]);
        cJSON_AddNumberToObject(write_latency, "64k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_64K]);
        cJSON_AddNumberToObject(write_latency, "128k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_128K]);
        cJSON_AddNumberToObject(write_latency, "256k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_256K]);
        cJSON_AddNumberToObject(write_latency, "512k", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_512K]);
        cJSON_AddNumberToObject(write_latency, "1M", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_1M]);
        cJSON_AddNumberToObject(write_latency, "2M", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_2M]);
        cJSON_AddNumberToObject(write_latency, "Over 2M", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M]);
        cJSON_AddNumberToObject(write_latency, "flush", smart_nvme->statistics->avg_write_latency[SPDK_PLUS_MONITOR_FLUSH]);
        cJSON_AddItemToObject(object, "Write Latency", write_latency);
        cJSON *read_wait_latency = cJSON_CreateObject();
        if (read_wait_latency == NULL)
        {
            SPDK_ERRLOG("Failed to create JSON object\n");
            cJSON_Delete(read_latency);
            cJSON_Delete(write_latency);
            cJSON_Delete(object);
            cJSON_Delete(array);
            return;
        }
        cJSON_AddNumberToObject(read_wait_latency, "4k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_4K]);
        cJSON_AddNumberToObject(read_wait_latency, "8k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_8K]);
        cJSON_AddNumberToObject(read_wait_latency, "16k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_16K]);
        cJSON_AddNumberToObject(read_wait_latency, "32k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_32K]);
        cJSON_AddNumberToObject(read_wait_latency, "64k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_64K]);
        cJSON_AddNumberToObject(read_wait_latency, "128k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_128K]);
        cJSON_AddNumberToObject(read_wait_latency, "256k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_256K]);
        cJSON_AddNumberToObject(read_wait_latency, "512k", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_512K]);
        cJSON_AddNumberToObject(read_wait_latency, "1M", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_1M]);
        cJSON_AddNumberToObject(read_wait_latency, "2M", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_2M]);
        cJSON_AddNumberToObject(read_wait_latency, "Over 2M", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M]);
        cJSON_AddNumberToObject(read_wait_latency, "flush", smart_nvme->statistics->avg_wait_read_latency[SPDK_PLUS_MONITOR_FLUSH]);
        cJSON_AddItemToObject(object, "Read Wait Latency", read_wait_latency);
        cJSON *write_wait_latency = cJSON_CreateObject();
        if (write_wait_latency == NULL)
        {
            SPDK_ERRLOG("Failed to create JSON object\n");
            cJSON_Delete(read_wait_latency);
            cJSON_Delete(read_latency);
            cJSON_Delete(write_latency);
            cJSON_Delete(object);
            cJSON_Delete(array);
            return;
        }
        cJSON_AddNumberToObject(write_wait_latency, "4k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_4K]);
        cJSON_AddNumberToObject(write_wait_latency, "8k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_8K]);
        cJSON_AddNumberToObject(write_wait_latency, "16k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_16K]);
        cJSON_AddNumberToObject(write_wait_latency, "32k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_32K]);
        cJSON_AddNumberToObject(write_wait_latency, "64k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_64K]);
        cJSON_AddNumberToObject(write_wait_latency, "128k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_128K]);
        cJSON_AddNumberToObject(write_wait_latency, "256k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_256K]);
        cJSON_AddNumberToObject(write_wait_latency, "512k", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_512K]);
        cJSON_AddNumberToObject(write_wait_latency, "1M", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_1M]);
        cJSON_AddNumberToObject(write_wait_latency, "2M", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_2M]);
        cJSON_AddNumberToObject(write_wait_latency, "Over 2M", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M]);
        cJSON_AddNumberToObject(write_wait_latency, "flush", smart_nvme->statistics->avg_wait_write_latency[SPDK_PLUS_MONITOR_FLUSH]);
        cJSON_AddItemToObject(object, "Write Wait Latency", write_wait_latency);
        cJSON_AddItemToArray(array, object);
    }
    pthread_rwlock_unlock(&meta_rwlock);
    char *json_string = cJSON_Print(array);
    if (json_string == NULL)
    {
        SPDK_ERRLOG("Failed to print JSON string\n");
        cJSON_Delete(array);
        return;
    }
    int16_t pos = 0;
    int16_t len = strlen(json_string);
    int16_t send_len = 0;
    while (pos < len)
    {
        send_len = send(client_id, json_string + pos, len - pos, 0);
        if (send_len <= 0)
        {
            SPDK_ERRLOG("Failed to send data to client\n");
            break;
        }
        pos += send_len;
    }
    send(client_id, "\n", 1, 0);
    if (send_len <= 0)
    {
        SPDK_ERRLOG("Failed to send newline to client\n");
    }
    free(json_string);
    cJSON_Delete(array);
    return;
}

static void *
spdk_plus_get_remote_control_function(void *arg)
{
    int client_fd = *((int *)arg);
    free(arg);
    char buffer[SPDK_PLUS_BUF_SIZE] = {0};
    if (1)
    {
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0)
        {
            if (bytes_read == 0)
            {
                SPDK_ERRLOG("Client disconnected\n");
            }
            else
            {
                SPDK_ERRLOG("Error reading from client\n");
            }
            close(client_fd);
            return NULL;
        }
        // printf("Received from client: %s\n", buffer);
        // TODO: 处理接收到的数据
        if (strcmp(buffer, "dump") == 0)
        {
            spdk_plus_print_statistical_data(client_fd);
        }
        else
        {
            SPDK_ERRLOG("Unknown command: %s\n", buffer);
        }
    }

    close(client_fd);
    return NULL;
}

static void
spdk_plus_change_ssd_strategy(void)
{
    // TODO: 策略调整

    pthread_rwlock_rdlock(&meta_rwlock);
    /* 通知所有qpair清零统计数据 */
    struct spdk_plus_smart_nvme *smart_nvme = NULL;
    TAILQ_FOREACH(smart_nvme, &g_qpair_list, link)
    {
        if (smart_nvme->ctrlr == NULL)
        {
            SPDK_ERRLOG("Controller is NULL\n");
            continue;
        }
        // uint64_t cmd = SPDK_PLUS_CLEAR_STAT;
        // int rc = write(smart_nvme->fd, &cmd, sizeof(cmd));
        // if (rc != sizeof(cmd))
        // {
        //     SPDK_ERRLOG("Failed to write to eventfd\n");
        // }
    }
    pthread_rwlock_unlock(&meta_rwlock);
}

static void
spdk_plus_update_statistical_data(void)
{
    pthread_rwlock_rdlock(&meta_rwlock);
    /* 更新统计数据 */
    struct spdk_plus_smart_nvme *smart_nvme = NULL;
    TAILQ_FOREACH(smart_nvme, &g_qpair_list, link)
    {
        if (smart_nvme->ctrlr == NULL)
        {
            SPDK_ERRLOG("Controller is NULL\n");
            continue;
        }
        smart_nvme->statistics->finish_io_count = 0;
        smart_nvme->poll_io_depth = (smart_nvme->poll_io_depth + queue_size(smart_nvme->poll_qpair.queue)) / 2;
        smart_nvme->uintr_io_depth = (smart_nvme->uintr_io_depth + queue_size(smart_nvme->uintr_qpair.queue)) / 2;
        smart_nvme->int_io_depth = (smart_nvme->int_io_depth + queue_size(smart_nvme->int_qpair.queue)) / 2;
    }
    pthread_rwlock_unlock(&meta_rwlock);
    return;
}

static void *
spdk_plus_control_thread(void *arg)
{
    if (arg != NULL)
    {
        ERRLOG("Control thread is not NULL\n");
        return NULL;
    }
    /* 创建网络监听符 */
    int32_t server_fd, new_socket;
    struct sockaddr_in address;
    int32_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        ERRLOG("socket failed\n");
        return NULL;
    }
// 随机生成端口号
retry:
    uint16_t port = rand() % (10000) + 20000;
    // 设置地址结构
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // 监听所有网络接口
    address.sin_port = htons(port);
    // 绑定套接字到地址
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        ERRLOG("bind failed port: %u err: %s\n", port, strerror(errno));
        if (errno == EADDRINUSE)
            goto retry;
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    // 开始监听
    if (listen(server_fd, BACKLOG) < 0)
    {
        ERRLOG("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    pid_t tid = syscall(SYS_gettid);
    INFOLOG("Thread %u Listening on port %d\n", tid, port);
    SPDK_ERRLOG("Thread %u Listening on port %d\n", tid, port);
    /* 创建100us循环的触发一次的描述符 */
    struct itimerspec ts;
    int32_t timer_fd = timerfd_create(CLOCK_MONOTONIC_RAW, TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0)
    {
        ERRLOG("Failed to create timer fd: %s\n", strerror(errno));
        close(server_fd);
        return NULL;
    }
    // 设置定时器参数
    memset(&ts, 0, sizeof(ts));
    ts.it_interval.tv_sec = 0;       // 间隔秒数
    ts.it_interval.tv_nsec = 100000; // 间隔纳秒数（100微秒）
    ts.it_value.tv_sec = 5;          // 初始延迟秒数
    ts.it_value.tv_nsec = 500000;    // 初始延迟纳秒数（500微秒）
    // 设置定时器
    if (timerfd_settime(timer_fd, 0, &ts, NULL) == -1)
    {
        ERRLOG("timerfd_settime");
        close(timer_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    /* 统一监听 */
    int32_t epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        ERRLOG("Failed to create epoll fd\n");
        close(timer_fd);
        close(server_fd);
        return NULL;
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1)
    {
        ERRLOG("epoll_ctl failed");
        close(server_fd);
        close(timer_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }
    ev.data.fd = timer_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev) == -1)
    {
        ERRLOG("epoll_ctl failed");
        close(server_fd);
        close(timer_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }

    struct epoll_event events[EPOLL_SIZE];

    INFOLOG("Control thread started\n");

    // 等待事件
    while (!g_spdk_plus_exit)
    {
        int32_t nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, -1);
        if (nfds == -1)
        {
            SPDK_ERRLOG("epoll_wait failed\n");
            break;
        }

        for (int i = 0; i < nfds; i++)
        {
            if (events[i].data.fd == server_fd)
            {
                // 处理TCP连接请求
                new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                if (new_socket < 0)
                {
                    SPDK_ERRLOG("accept failed\n");
                    continue;
                }
                printf("Connection accepted from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
                int *pclient = malloc(sizeof(int));
                if (pclient == NULL)
                {
                    SPDK_ERRLOG("Failed to allocate memory for client fd\n");
                    close(new_socket);
                    continue;
                }
                *pclient = new_socket;
                pthread_t thread_id;
                if (pthread_create(&thread_id, NULL, spdk_plus_get_remote_control_function, pclient) != 0)
                {
                    SPDK_ERRLOG("Failed to create thread\n");
                    close(new_socket);
                    free(pclient);
                    continue;
                }
                pthread_detach(thread_id); // 分离线程
            }
            else if (events[i].data.fd == timer_fd)
            {
                // 处理定时器事件
                uint64_t expirations;
                if (read(timer_fd, &expirations, sizeof(expirations)) != sizeof(expirations))
                {
                    SPDK_ERRLOG("Failed to read from timer fd\n");
                    continue;
                }
                spdk_plus_update_statistical_data();
                // spdk_plus_change_ssd_strategy();
                // spdk_plus_print_statistical_data();
                // DEBUGLOG("Timer expired %llu times\n", (unsigned long long)expirations);
            }
        }
    }

    INFOLOG("Exiting control thread\n");
    SPDK_ERRLOG("Exiting control thread\n");
    // 清理资源
    close(server_fd);
    close(timer_fd);
    close(epoll_fd);
    return NULL;
}

static bool probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid, struct spdk_nvme_ctrlr_opts *opts)
{
    struct spdk_nvme_transport_id *target_trid = (struct spdk_nvme_transport_id *)(cb_ctx);
    bool do_attach = false;

    if (trid->trtype == SPDK_NVME_TRANSPORT_PCIE)
    {
        do_attach = spdk_nvme_transport_id_compare(target_trid, trid) == 0;
        if (!do_attach)
        {
            SPDK_ERRLOG("trid mismatch: %s != %s\n",
                        spdk_nvme_transport_id_trtype_str(target_trid->trtype),
                        spdk_nvme_transport_id_trtype_str(trid->trtype));
        }
    }
    else
    {
        // for non-pcie devices, should always match the specified trid
        assert(!spdk_nvme_transport_id_compare(target_trid, trid));
        do_attach = true;
    }

    if (do_attach)
    {
        // dout(0) << __func__ << " found device at: "
        //     << "trtype=" << spdk_nvme_transport_id_trtype_str(trid->trtype) << ", "
        //     << "traddr=" << trid->traddr << dendl;

        opts->io_queue_size = UINT16_MAX;
        opts->io_queue_requests = UINT16_MAX;
        opts->keep_alive_timeout_ms = nvme_ctrlr_keep_alive_timeout_in_ms;
    }

    return do_attach;
}

static void attach_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
                      struct spdk_nvme_ctrlr *ctrlr, const struct spdk_nvme_ctrlr_opts *opts)
{
    g_back_device.ctrlr = ctrlr;
    g_back_device.ns = spdk_nvme_ctrlr_get_ns(ctrlr, 1);
    if (!g_back_device.ns)
    {
        SPDK_ERRLOG("Failed to get default namespace\n");
        return;
    }
    g_back_device.fd = eventfd(0, EFD_NONBLOCK);
    if (g_back_device.fd < 0)
    {
        SPDK_ERRLOG("Failed to create eventfd\n");
        return;
    }
}

static void dpdk_log_open_ext(const char *file_path)
{
    FILE *fp = fopen(file_path, "a+");
    if (fp == NULL)
    {
        ERRLOG("Failed to open log file");
        return;
    }
    rte_openlog_stream(fp);
    rte_log_set_global_level(RTE_LOG_DEBUG);
    return;
}

int spdk_plus_env_init(enum spdk_plus_smart_schedule_module_status status,
                       struct spdk_plus_smart_schedule_module_opts *opts, const char *dev_name)
{
    if (opts != NULL)
    {
        return SPDK_PLUS_ERR_NOT_SUPPORTED;
    }
    unsigned int seed = (unsigned int)time(NULL) ^ getpid();
    srand(seed);
    /* 日志初始化 */
    spdk_log_open_ext(&g_log_opts);
    dpdk_log_open_ext("/home/led/workspace/dpdk_plus_log.log");
    // 初始化互斥锁
    if (pthread_mutex_init(&meta_mutex, NULL) != 0)
    {
        perror("pthread_mutex_init failed");
        return EXIT_FAILURE;
    }
    int rc;
    rc = spdk_plus_get_default_opts(status, &g_smart_schedule_module_opts);
    if (rc != SPDK_PLUS_SUCCESS)
    {
        SPDK_ERRLOG("Failed to get default opts\n");
        return rc;
    }
    /* 创建控制线程 */
    // if (pthread_create(&g_control_thread, NULL, spdk_plus_control_thread, NULL) != 0)
    // {
    //     SPDK_ERRLOG("Failed to create control thread\n");
    //     return SPDK_PLUS_ERR;
    // }
    // if (pthread_detach(g_control_thread) != 0)
    // {
    //     SPDK_ERRLOG("Failed to detach control thread\n");
    //     return SPDK_PLUS_ERR;
    // }

    if (dev_name == NULL) // 如果没有传入设备名，则不启用后备SSD
        g_smart_schedule_module_opts.enable_back_ssd = false;

    if (g_smart_schedule_module_opts.enable_back_ssd)
    {
        /* 设置后备ssd */
        if (dev_name == NULL)
        {
            ERRLOG("dev_name is NULL but back_ssd is enable\n");
            return SPDK_PLUS_ERR_INVALID;
        }
        char filename[SPDK_PLUS_BUF_SIZE] = {0};
        strncpy(filename, dev_name, sizeof(filename) - 1);
        struct spdk_nvme_transport_id trid;
        trid.trtype = SPDK_NVME_TRANSPORT_PCIE;
        char *p = strstr(filename, " ns=");
        char *trid_info = NULL;
        if (p != NULL)
        {
            trid_info = strndup(filename, p - filename);
        }
        else
        {
            trid_info = strndup(filename, strlen(filename));
        }

        if (!trid_info)
        {
            SPDK_ERRLOG("Failed to allocate space for trid_info\n");
            return SPDK_PLUS_ERR;
        }

        rc = spdk_nvme_transport_id_parse(&trid, trid_info);
        if (rc < 0)
        {
            SPDK_ERRLOG("Failed to parse given str: %s\n", trid_info);
            free(trid_info);
            return SPDK_PLUS_ERR;
        }
        free(trid_info);

        if (trid.trtype == SPDK_NVME_TRANSPORT_PCIE)
        {
            struct spdk_pci_addr pci_addr;
            if (spdk_pci_addr_parse(&pci_addr, trid.traddr) < 0)
            {
                SPDK_ERRLOG("Invalid traddr=%s\n", trid.traddr);
                return SPDK_PLUS_ERR_INVALID;
            }
            spdk_pci_addr_fmt(trid.traddr, sizeof(trid.traddr), &pci_addr);
        }
        else
        {
            SPDK_ERRLOG("Invalid transport type not supported\n");
            return SPDK_PLUS_ERR_NOT_SUPPORTED;
        }

        if (spdk_nvme_probe(&trid, &trid, probe_cb, attach_cb, NULL) != 0)
        {
            SPDK_ERRLOG("spdk_nvme_probe() failed\n");
            return SPDK_PLUS_ERR;
        }
        INFOLOG("spdk plus env init success, trid: %s\n", trid.traddr);
    }
    else
    {
        INFOLOG("spdk plus env init success, back ssd is off\n");
    }
    return SPDK_PLUS_SUCCESS;
}

int spdk_plus_nvme_zns_reset_zone(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
                                  uint64_t slba, bool select_all,
                                  spdk_nvme_cmd_cb cb_fn, void *cb_arg)
{
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;
    task = calloc(1, sizeof(struct io_task));
    if (!task)
    {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_FLUSH;
    task->io_size = SPDK_PLUS_MONITOR_FLUSH;
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->cb_arg = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_FLUSH);
    if (!qpair)
    {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    rc = spdk_nvme_zns_reset_zone(ns, qpair, slba, select_all,
                                  io_complete, task);
    if (rc != 0)
    {
        SPDK_ERRLOG("Failed to send flush command\n");
        goto failed;
    }
    return rc;

failed:
    if (task)
    {
        free(task);
    }
    return rc;
}

int spdk_plus_nvme_ctrlr_free_io_qpair(struct spdk_plus_smart_nvme *nvme_device)
{
    int rc = 0;
    int cpu_id = nvme_device->cpu_id;
    if (nvme_device == NULL)
    {
        SPDK_ERRLOG("nvme_device is NULL\n");
        return SPDK_PLUS_ERR_INVALID;
    }
    if (pthread_rwlock_wrlock(&meta_rwlock) < 0)
    {
        SPDK_ERRLOG("Failed to lock mutex\n");
        return SPDK_PLUS_ERR;
    }
    if (nvme_device->poll_qpair.qpair)
    {
        // rc = spdk_nvme_ctrlr_free_io_qpair(nvme_device->poll_qpair.qpair);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to free poll qpair\n");
            goto failed;
        }
        destroy_queue(nvme_device->poll_qpair.queue);
    }
    if (nvme_device->int_qpair.qpair)
    {
        rc = spdk_nvme_ctrlr_free_io_qpair(nvme_device->int_qpair.qpair);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to free int qpair\n");
            goto failed;
        }
        destroy_queue(nvme_device->int_qpair.queue);
    }
    if (nvme_device->uintr_qpair.qpair)
    {
        rc = spdk_nvme_ctrlr_free_io_qpair(nvme_device->uintr_qpair.qpair);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to free uintr qpair\n");
            goto failed;
        }
        destroy_queue(nvme_device->uintr_qpair.queue);
        uintr_unregister_sender(nvme_device->uintr_qpair.uipi_index, 0);
        if (g_cpuid_uipi_map[nvme_device->cpu_id] == nvme_device->uintr_qpair.uipi_index)
        {
            g_cpuid_uipi_map[nvme_device->cpu_id] = 0;
        }
    }
    if (nvme_device->back_poll_qpair.qpair)
    {
        rc = spdk_nvme_ctrlr_free_io_qpair(nvme_device->back_poll_qpair.qpair);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to free back poll qpair\n");
            goto failed;
        }
        destroy_queue(nvme_device->back_poll_qpair.queue);
    }
    if (nvme_device->fd > 0)
    {
        rc = close(nvme_device->fd);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to close fd\n");
            goto failed;
        }
    }
    if (nvme_device->int_qpair.fd > 0)
    {
        rc = close(nvme_device->int_qpair.fd);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to close int qpair fd\n");
            goto failed;
        }
    }
    if (nvme_device->uintr_qpair.fd > 0)
    {
        rc = close(nvme_device->uintr_qpair.fd);
        if (rc != 0)
        {
            SPDK_ERRLOG("Failed to close uintr qpair fd\n");
            goto failed;
        }
    }

failed:
    struct spdk_plus_smart_nvme *smart_nvme = NULL;
    TAILQ_FOREACH(smart_nvme, &g_qpair_list, link)
    {
        if (smart_nvme == nvme_device)
        {
            TAILQ_REMOVE(&g_qpair_list, smart_nvme, link);
            break;
        }
    }
    struct nvme_metadata *meta = NULL;
    TAILQ_FOREACH(meta, &g_nvme_metadata_list, link)
    {
        if (meta->ctrlr == nvme_device->ctrlr)
        {
            meta->cite_number--;
            meta->nvme_qpair[cpu_id % SPDK_PLUS_MAX_QUEUE_NUM] = NULL;
            if (meta->cite_number == 0)
            {
                TAILQ_REMOVE(&g_nvme_metadata_list, meta, link);
                spdk_nvme_ctrlr_free_io_qpair(meta->qpair.qpair);
                close(meta->qpair.fd);
                destroy_queue(meta->qpair.queue);
                free(meta);
            }
            break;
        }
    }
    pthread_rwlock_unlock(&meta_rwlock);
    DEBUGLOG("Free nvme device %p rc = %d\n", nvme_device, rc);
    SPDK_ERRLOG("Free nvme device %p rc = %d thread id = %lu\n", nvme_device, rc, pthread_self());
    return rc;
}

int spdk_plus_env_fini(void)
{
    INFOLOG("SPDK Plus environment finalizing...\n");
    int rc = 0;
    /* 等待所有队列全部释放 */
    bool is_all_free = true;
    do
    {
        usleep(1000);
        struct spdk_plus_smart_nvme *smart_nvme = NULL;
        if (pthread_rwlock_rdlock(&meta_rwlock) < 0)
        {
            SPDK_ERRLOG("Failed to lock mutex\n");
            return SPDK_PLUS_ERR;
        }
        TAILQ_FOREACH(smart_nvme, &g_qpair_list, link)
        {
            if (smart_nvme != NULL)
            {
                is_all_free = false;
                DEBUGLOG("SPDK Plus env is not free, still has %p\n", smart_nvme);
                break;
            }
        }
        pthread_rwlock_unlock(&meta_rwlock);
    } while (!is_all_free);
    INFOLOG("SPDK Plus env is free, now we will process the backend ssd source\n");
    g_spdk_plus_exit = true;
    if (g_back_device.ctrlr)
    {
        spdk_nvme_detach(g_back_device.ctrlr);
        g_back_device.ctrlr = NULL;
    }
    if (g_back_device.ns)
    {
        g_back_device.ns = NULL;
    }
    if (g_back_device.fd > 0)
    {
        close(g_back_device.fd);
        g_back_device.fd = -1;
    }
    pthread_mutex_destroy(&meta_mutex);
    if (g_control_thread)
    {
        pthread_join(g_control_thread, NULL);
        g_control_thread = 0;
    }
    INFOLOG("SPDK Plus environment finalized\n");
    return rc;
}
