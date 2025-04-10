#include <spdk/smart_nvme.h>
#include <spdk/nvme.h> // Include the header defining struct spdk_nvme_ctrlr
#include <bits/time.h>
#include "queue_wrapper.hpp" // Include the queue wrapper header

#ifndef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#define NS_PER_S 1000000000
#define US_PER_S 1000000
#define CORE_NUMBER 0XFF

#ifndef __NR_uintr_register_handler
#define __NR_uintr_wait_msix_interrupt 470
#define __NR_uintr_register_handler	471
#define __NR_uintr_unregister_handler	472
#define __NR_uintr_create_fd		473
#define __NR_uintr_register_sender	474
#define __NR_uintr_unregister_sender	475
#define __NR_uintr_wait			476
#endif

#define UINTR_WAIT_EXPERIMENTAL_FLAG 0x1

#define uintr_wait_msix_interrupt(ptr, flags)   syscall(__NR_uintr_wait_msix_interrupt, ptr, flags)
#define uintr_register_handler(handler, flags)	syscall(__NR_uintr_register_handler, handler, flags)
#define uintr_unregister_handler(flags)		syscall(__NR_uintr_unregister_handler, flags)
#define uintr_create_fd(vector, flags)		syscall(__NR_uintr_create_fd, vector, flags)
#define uintr_register_sender(fd, flags)	syscall(__NR_uintr_register_sender, fd, flags)
#define uintr_unregister_sender(ipi_idx, flags)	syscall(__NR_uintr_unregister_sender, ipi_idx, flags)
#define uintr_wait(usec, flags)			syscall(__NR_uintr_wait, usec, flags)

enum nvme_io_mode {
    SPDK_PLUS_READ,
    SPDK_PLUS_WRITE,
    SPDK_PLUS_FLUSH,
};

// TODO: 用户中断调频怎么加进去

struct io_task {
    enum spdk_plus_monitor_io_size io_size; /* 统计口径IO大小 */
    enum nvme_io_mode io_mode; /* 读写模式 */
    uint64_t notify_mode; /* 通知模式，注意，中断轮询算作轮询 */
    struct spdk_plus_smart_nvme *nvme_device; /* NVMe设备 */
    spdk_nvme_cmd_cb cb_fn; /* 回调函数 */
    struct timespec start_time;
    void *t;
};

struct nvme_thread {
	uint64_t stack_space[0x10000];
	uint64_t rsp;
	uint64_t rip;
    int flags; /* 记录用户中断标志，帮助恢复 */
};


#define local_irq_save(flags) \
    do {                      \
        flags = _testui();    \
        _clui();              \
    } while (0)
#define local_irq_restore(flags) \
    do {                         \
        if (flags)               \
            _stui();             \
    } while (0)


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
};


/* 用于用户中断切换框架 */
struct nvme_thread *g_curr_thread[CORE_NUMBER] = {0}; /* 当前线程 */
struct nvme_thread g_work_thread[CORE_NUMBER]; /* IO线程结构 */
struct nvme_thread g_idle_thread[CORE_NUMBER]; /* 节能线程结构 */
uint64_t g_cpuid_uipi_map[CORE_NUMBER]; /* CPU ID到用户中断的映射 */
bool g_io_completion_notify[CORE_NUMBER]; /* IO完成通知 */


static void switch_thread(struct nvme_thread *from, struct nvme_thread *to);

void __attribute__((interrupt))__attribute__((target("general-regs-only", "inline-all-stringops")))
uintr_get_handler(struct __uintr_frame *ui_frame,
	      unsigned long long vector)
{
	int flags;
	local_irq_save(flags);
	_senduipi(g_cpuid_uipi_map[vector]);
	if(g_curr_thread[vector] == g_idle_thread + vector) {
		switch_thread(g_idle_thread + vector, g_work_thread + vector);	
		g_curr_thread[vector] = g_idle_thread + vector;
	} else {
		g_io_completion_notify[vector] = true;
	}
}

static void switch_thread(struct user_thread *from, struct user_thread *to) {
	asm volatile(
				"push %%rbx\n\t"
				"push %%rbp\n\t"
				"push %%r12\n\t"
				"push %%r13\n\t"
				"push %%r14\n\t"
				"push %%r15\n\t"
				"mov %%rsp , %0\n\t"
				"mov %1 , %%rsp\n\t"
				"pop %%r15\n\t"
				"pop %%r14\n\t"
				"pop %%r13\n\t"
				"pop %%r12\n\t"
				"pop %%rbp\n\t"
				"pop %%rbx\n\t"
				: "=m"(from->rsp)  // 正确存储 from->rsp
				: "m"(to->rsp) // 正确加载 to->rsp 和 to->rip
				);
	asm volatile ("ret");
}

static void idle_thread_func(void) {
	int loop = 0;
	uint64_t cpu_id;

    // 使用内联汇编将 %rbx 的值赋给 loop
    asm volatile(
        "mov %%rbx, %0"  // 将 %rbx 的值移动到 loop（%0）
        : "=r"(cpu_id)      // 输出操作数：将 %rbx 的值存储到 loop
    );

	{
		local_irq_save(g_idle_thread[cpu_id].flags);
		switch_thread(g_idle_thread + cpu_id, g_work_thread + cpu_id);
		g_curr_thread[cpu_id] = g_idle_thread + cpu_id;
		local_irq_restore(g_idle_thread[cpu_id].flags);
	}
	uint64_t delay = 20 * spdk_get_ticks_hz() / NS_PER_S;
	
begin:
	if(!g_io_completion_notify[cpu_id]) {
        g_curr_thread[cpu_id] = g_idle_thread + cpu_id;
        uint64_t sleep_time = _rdtsc() + delay;
	    _tpause(0, sleep_time);
    }
	local_irq_save(g_idle_thread[cpu_id].flags);
	switch_thread(g_idle_thread + cpu_id, g_work_thread + cpu_id); // TODO: 看这个能不能去掉，因为是没有意义的
	goto begin;
}


static inline enum spdk_plus_monitor_io_size
nvme_get_statistical_io_size(uint32_t lba_count){
    enum spdk_plus_monitor_io_size io_size;
    uint32_t io_size_bytes = lba_count * 4096; /* 4K IO TODO: 这个lba大小需要读取 */
    if(io_size_bytes > 2 * 1024 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M;
    } else if(io_size_bytes > 1 * 1024 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_2M;
    } else if(io_size_bytes > 512 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_1M;
    } else if(io_size_bytes > 256 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_512K;
    } else if(io_size_bytes > 128 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_256K;
    } else if(io_size_bytes > 64 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_128K;
    } else if(io_size_bytes > 32 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_64K;
    } else if(io_size_bytes > 16 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_32K;
    } else if(io_size_bytes > 8 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_16K;
    } else if(io_size_bytes > 4 * 1024){
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_8K;
    } else {
        io_size = SPDK_PLUS_MONITOR_IO_SIZE_4K;
    }
    return io_size;
}

static inline void
nvme_sleep(uint64_t ns) {
    if(ns == 0)
        return;
    switch(g_smart_schedule_module_opts.status) {
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
            {
                if(ns > g_smart_schedule_module_opts.threshold_ns) {
                    uint32_t usec = ns / 1000;
                    usec = MIN(usec, usec - 4);
                    uintr_wait(usec, 0);
                } else {
                    uint64_t tsc = _rdtsc() + ns * spdk_get_ticks_hz() / NS_PER_S;
                    _tpause(0, tsc);
                }
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
nvme_get_sleep_naonotime_internel(struct spdk_plus_smart_nvme *nvme_device, struct spdk_plus_nvme_qpair qpair) {
    if(queue_empty(qpair.queue)) {
        return UINT64_MAX; /* 如果队列为空，返回最大值 */
    }
    struct nvme_timestamp ts = queue_front(qpair.queue);
    uint64_t curr_latency = (curr_time.tv_sec - ts.ts.tv_sec) * 1000000000 + (curr_time.tv_nsec - ts.ts.tv_nsec);
    uint64_t theoretical_latency = 0;
    if(ts.io_size >= SPDK_PLUS_MONITOR_IO_SIZE_TOTAL_NUM) {
        SPDK_ERRLOG("IO size is out of range\n");
        return UINT64_MAX;
    }
    if(ts.io_mode == SPDK_PLUS_READ) {
        theoretical_latency = nvme_device->avg_read_latency[ts.io_size] * g_smart_schedule_module_opts.read_sleep_rate;
    } else if (ts.io_mode == SPDK_PLUS_WRITE) {
        theoretical_latency = nvme_device->avg_write_latency[ts.io_size] * g_smart_schedule_module_opts.write_sleep_rate;
    } else if (ts.io_mode == SPDK_PLUS_FLUSH) {
        theoretical_latency = 0; /* 刷新操作不需要休眠 */
    } else {
        SPDK_ERRLOG("Unknown IO mode\n");
        return UINT64_MAX;
    }
    return curr_latency <= theoretical_latency ? theoretical_latency - curr_latency : 0;
}

/* 用于中断轮询休眠时间计算 */
static inline uint64_t
nvme_get_sleep_nanotime(struct spdk_plus_smart_nvme *nvme_device) {
    struct timespec curr_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &curr_time);
    uint64_t sleep_time = MIN(nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->int_qpair),
                      nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->uintr_qpair), 
                      nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->poll_qpair));
    if (sleep_time == UINT64_MAX) {
        SPDK_ERRLOG("Sleep time is UINT64_MAX\n");
    }
    return sleep_time;
}

static struct spdk_nvme_qpair*
nvme_get_suitable_io_qpair(struct spdk_plus_smart_nvme *nvme_device, struct io_task* task, enum nvme_io_mode io_mode) {
    struct spdk_plus_nvme_qpair *qpair = NULL;
    switch(g_smart_schedule_module_opts.status) {
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
            qpair = nvme_device->int_qpair;
            task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE: {
            uint32_t total_depth = queue_size(nvme_device->int_qpair.queue) +
                                   queue_size(nvme_device->uintr_qpair.queue) +
                                   queue_size(nvme_device->poll_qpair.queue);
            if(total_depth < nvme_device->threshold_opts.depth_threshold2) {
                qpair = nvme_device->uintr_qpair;
                task->notify_mode = SPDK_PLUS_UINTR_MODE;
            } else {
                qpair = nvme_device->int_qpair;
                task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            }
        } break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
        {
            uint32_t total_depth = queue_size(nvme_device->int_qpair.queue) +
                                   queue_size(nvme_device->uintr_qpair.queue) +
                                   queue_size(nvme_device->poll_qpair.queue);
            if(total_depth < nvme_device->threshold_opts.depth_threshold1) {
                qpair = nvme_device->uintr_qpair;
                task->notify_mode = SPDK_PLUS_UINTR_MODE;
            } else if(total_depth < nvme_device->threshold_opts.depth_threshold3) {
                qpair = nvme_device->poll_qpair;
                task->notify_mode = SPDK_PLUS_POLLING_MODE;
            } else {
                qpair = nvme_device->int_qpair;
                task->notify_mode = SPDK_PLUS_INTERRUPT_MODE;
            }
        } break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE:
            qpair = nvme_device->poll_qpair;
            task->notify_mode = SPDK_PLUS_POLLING_MODE;
            break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM:
            SPDK_ERRLOG("Custom mode, not support\n");
            break;
        default:
            SPDK_ERRLOG("Unknown schedule module status\n");
    }
    enqueue(qpair->queue, (struct nvme_timestamp){.ts = task->curr_time, .io_size = task->io_size, .io_mode = io_mode});
    return qpair;
}

static void
nvme_ctrlr_io_qpair_opts_copy(struct spdk_nvme_io_qpair_opts *dst,
			      const struct spdk_nvme_io_qpair_opts *src, size_t opts_size_src)
{
	if (!opts_size_src) {
		SPDK_ERRLOG("opts_size_src should not be zero value\n");
		assert(false);
	}

#define FIELD_OK(field) \
        offsetof(struct spdk_nvme_io_qpair_opts, field) + sizeof(src->field) <= opts_size_src

#define SET_FIELD(field) \
        if (FIELD_OK(field)) { \
                dst->field = src->field; \
        } \

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
nvme_prepare_uintr_env() {
    int cpu_id = sched_getcpu();
    int flags;
    if(g_curr_thread[cpu_id] != NULL) {
        SPDK_ERRLOG("[ DEBUG ] Thread is already initialized\n");
        return;
    }
    #define UINTR_HANDLER_FLAG_WAITING_RECEIVER	0x1000 // TODO: 这个定义也一直需要吗？
    if (uintr_register_handler(uintr_get_handler, UINTR_HANDLER_FLAG_WAITING_RECEIVER)) {
        SPDK_ERRLOG("Interrupt handler register error");
        exit(EXIT_FAILURE);
    }
    local_irq_save(flags);
    g_idle_thread[cpu_id].flags = flags;
    g_work_thread[cpu_id].flags = flags;
    g_idle_thread[cpu_id].rsp = (uint64_t)((unsigned char*)(g_idle_thread[cpu_id].stack_space) + sizeof(g_idle_thread[cpu_id].stack_space) - 0x38);
    g_idle_thread[cpu_id].rip = (uint64_t)idle_thread_func;
    g_idle_thread[cpu_id].stack_space[0xFFFF] = idle_thread_func;
    g_idle_thread[cpu_id].stack_space[0xFFFE] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFFD] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFFC] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFFB] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFFA] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF9] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF8] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF7] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF6] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF5] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF4] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF3] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF2] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF1] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFF0] = cpu_id;
    g_idle_thread[cpu_id].stack_space[0xFFEF] = cpu_id;
    switch_thread(g_work_thread + cpu_id, g_idle_thread + cpu_id);
    g_curr_thread[cpu_id] = g_work_thread + cpu_id;
    switch_thread(g_work_thread + cpu_id, g_idle_thread + cpu_id);
    g_curr_thread[cpu_id] = g_work_thread + cpu_id;
}


struct spdk_plus_smart_nvme *spdk_plus_nvme_ctrlr_alloc_io_device(struct spdk_nvme_ctrlr *ctrlr,
    const struct spdk_nvme_io_qpair_opts *user_opts,
    size_t opts_size){
    struct spdk_plus_smart_nvme *smart_nvme = NULL;
    struct spdk_nvme_io_qpair_opts opts;

    if (ctrlr->opts.enable_interrupts) {
        SPDK_ERRLOG("Interrupts are enabled, cannot allocate I/O device\n");
        goto failed;
    }

    smart_nvme = calloc(1, sizeof(struct spdk_plus_smart_nvme));
    if (!smart_nvme) {
        SPDK_ERRLOG("Failed to allocate memory for smart_nvme\n");
        goto failed;
    }
    smart_nvme->ctrlr = ctrlr;
    smart_nvme->cpu_id = sched_getcpu();
    smart_nvme->ns = spdk_nvme_ctrlr_get_default_ns(ctrlr);
    if (!smart_nvme->ns) {
        SPDK_ERRLOG("Failed to get default namespace\n");
        goto failed;
    }
    spdk_nvme_ctrlr_get_default_io_qpair_opts(ctrlr, &opts, sizeof(opts));
    nvme_ctrlr_io_qpair_opts_copy(&opts, user_opts, spdk_min(opts.opts_size, opts_size));
    if(opts.interrupt_mode != 0){
        SPDK_ERRLOG("user should not set interrupt mode\n");
        goto failed;
    }
    smart_nvme->poll_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair(ctrlr, user_opts, opts_size);
    if (!smart_nvme->poll_qpair.qpair) {
        SPDK_ERRLOG("Failed to allocate poll qpair\n");
        goto failed;
    }
    opts.interrupt_mode = SPDK_PLUS_INTERRUPT_MODE;
    smart_nvme->int_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair_int(ctrlr, user_opts, opts_size, &smart_nvme->int_qpair.fd);
    if (!smart_nvme->int_qpair.qpair) {
        SPDK_ERRLOG("Failed to allocate int qpair\n");
        goto failed;
    }
    if(smart_nvme->int_qpair.fd < 0) {
        SPDK_ERRLOG("Failed to get int qpair fd\n");
        goto failed;
    }
    int flags = fcntl(smart_nvme->int_qpair.fd, F_GETFL, 0);
    if (flags == -1) {
        SPDK_ERRLOG("Failed to get flags\n");
        goto failed;
    }
    if (fcntl(smart_nvme->int_qpair.fd, F_SETFL, flags & ~O_NONBLOCK) == -1) {
        SPDK_ERRLOG("Failed to set flags\n");
        goto failed;
    }
    nvme_prepare_uintr_env();
    opts.interrupt_mode = SPDK_PLUS_UINTR_MODE;
    smart_nvme->uintr_qpair.qpair = spdk_nvme_ctrlr_alloc_io_qpair_int(ctrlr, user_opts, opts_size, &smart_nvme->uintr_qpair.fd);
    if (!smart_nvme->uintr_qpair.qpair) {
        SPDK_ERRLOG("Failed to allocate uintr qpair\n");
        goto failed;
    }
    if(smart_nvme->uintr_qpair.fd < 0) {
        SPDK_ERRLOG("Failed to get uintr qpair fd\n");
        goto failed;
    }
    int uipi_index = uintr_register_sender(efd, 0);
    if(uipi_index < 0) {
        SPDK_ERRLOG("Unable to register sender\n");
        goto qpair_failed;
    }
    g_cpuid_uipi_map[smart_nvme->cpu_id] = uipi_index;
    SPDK_ERRLOG("[ DEBUG ]uipi_index: %d\n", uipi_index);
    _senduipi(uipi_index);
    memset(smart_nvme->avg_write_latency, 0, sizeof(smart_nvme->avg_write_latency));
    memset(smart_nvme->avg_read_latency, 0, sizeof(smart_nvme->avg_read_latency));
    return smart_nvme;

failed:
    if (smart_nvme) {
        free(smart_nvme);
    }
    return NULL;
}

static void io_complete(void *t, const struct spdk_nvme_cpl *completion) {
    struct io_task *task = (struct io_task *)t;
    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
    uint64_t latency = (end_time.tv_sec - task->start_time.tv_sec) * 1000000000 + (end_time.tv_nsec - task->start_time.tv_nsec);
    struct spdk_plus_smart_nvme *nvme_device = task->nvme_device;
    if(task->notify_mode == SPDK_PLUS_POLL_MODE) {
        if (task->io_mode == SPDK_PLUS_READ) {
            nvme_device->avg_read_latency[task->io_size] = g_smart_schedule_module_opts.read_alpha * latency +
                (1 - g_smart_schedule_module_opts.read_alpha) * nvme_device->avg_read_latency[task->io_size]; /* 指数加权移动平均 */
        } else if (task->io_mode == SPDK_PLUS_WRITE) {
            nvme_device->avg_write_latency[task->io_size] = g_smart_schedule_module_opts.write_alpha * latency +
                (1 - g_smart_schedule_module_opts.write_alpha) * nvme_device->avg_write_latency[task->io_size]; /* 指数加权移动平均 */
        }
        dequeue(nvme_device->poll_qpair.queue);
    } else if (task->notify_mode == SPDK_PLUS_INTERRUPT_MODE) {
        dequeue(nvme_device->int_qpair.queue);
    } else if (task->notify_mode == SPDK_PLUS_UINTR_MODE) {
        dequeue(nvme_device->uintr_qpair.queue);
    } else if (task->notify_mode == SPDK_PLUS_INT_POLL_MODE) {
        dequeue(nvme_device->poll_qpair.queue);
    } else if (task->notify_mode == SPDK_PLUS_UINTR_POLL_MODE) {
        dequeue(nvme_device->poll_qpair.queue);
    } else {
        SPDK_ERRLOG("Unknown notify mode\n");
        free(task);
        return;
    }
    
    task->cb_fn(task->t, completion);
    free(task);
    return;
}

int spdk_plus_nvme_ns_cmd_readv(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    uint64_t lba, uint32_t lba_count,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
    spdk_nvme_req_reset_sgl_cb reset_sgl_fn,
    spdk_nvme_req_next_sge_cb next_sge_fn) {
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    task = calloc(1, sizeof(struct io_task));
    if (!task) {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_READ;
    task->io_size = nvme_get_statistical_io_size(lba_count);
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->t = cb_arg;
    
    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_READ);
    if (!qpair) {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }


    rc = spdk_nvme_ns_cmd_readv(ns, qpair, lba, lba_count,
        io_complete, task, io_flags,
        reset_sgl_fn, next_sge_fn);
    return rc;

failed:
    if (task) {
        free(task);
    }
    return rc;
}

int spdk_plus_nvme_ns_cmd_writev(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    uint64_t lba, uint32_t lba_count,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
    spdk_nvme_req_reset_sgl_cb reset_sgl_fn,
    spdk_nvme_req_next_sge_cb next_sge_fn) {
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;

    task = calloc(1, sizeof(struct io_task));
    if (!task) {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_WRITE;
    task->io_size = nvme_get_statistical_io_size(lba_count);
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->t = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_WRITE);
    if (!qpair) {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }

    rc = spdk_nvme_ns_cmd_writev(ns, qpair, lba, lba_count,
        io_complete, task, io_flags,
        reset_sgl_fn, next_sge_fn);
    return rc;

failed:
    if (task) {
        free(task);
    }
    return rc;
}

int32_t nvme_process_completions_poll(struct spdk_plus_smart_nvme *nvme_device,
    uint32_t max_completions) {
    int32_t rc = 0;
    int32_t tmp_rc = 0;
    bool no_limited = max_completions == 0;
    if (!queue_empty(nvme_device->poll_qpair.queue)) { // 轮询所在的qpair有未完成命令
        tmp_rc = spdk_nvme_qpair_process_completions(nvme_device->poll_qpair.qpair, max_completions);
        if (tmp_rc < 0) {
            return tmp_rc;
        }
        rc += tmp_rc;
    }
    max_completions = no_limited ? 0 : max_completions - tmp_rc;
    if(!no_limited && max_completions == 0) {
        return rc;
    }
    if (!queue_empty(nvme_device->int_qpair.queue)) { // 内核中断所在的qpair有未完成命令
        tmp_rc = spdk_nvme_qpair_process_completions(nvme_device->int_qpair.qpair, max_completions);
        if (tmp_rc < 0) {
            return tmp_rc;
        }
        rc += tmp_rc;
    }
    max_completions = no_limited ? 0 : max_completions - tmp_rc;
    if(!no_limited && max_completions == 0) {
        return rc;
    }
    if (!queue_empty(nvme_device->uintr_qpair.queue)) { // 用户中断所在的qpair有未完成命令
        tmp_rc = spdk_nvme_qpair_process_completions(nvme_device->uintr_qpair.qpair, max_completions);
        if (tmp_rc < 0) {
            return tmp_rc;
        }
        rc += tmp_rc;
    }
    return rc;
}

int32_t spdk_plus_nvme_process_completions(struct spdk_plus_smart_nvme *nvme_device,
    uint32_t max_completions) {
    int32_t rc = 0;
    if (!queue_empty(nvme_device->poll_qpair.queue)) { // 轮询所在的qpair有未完成命令
        switch(g_smart_schedule_module_opts.status) {
            case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE: /* 和轮询模式形态一致 */
            {
                return nvme_process_completions_poll(nvme_device, max_completions);
            }break;
            case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
            case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
            case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
            case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
            {
                uint64_t sleep_time = nvme_get_sleep_nanotime(nvme_device);
                nvme_sleep(sleep_time);
                return nvme_process_completions_poll(nvme_device, max_completions);
            }break;
            case SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM:
            {
                SPDK_ERRLOG("Custom mode, not support\n");
                return SPDK_PLUS_ERR_NOT_SUPPORTED;
            }break;
            default:
                SPDK_ERRLOG("Unknown schedule module status\n");
                return SPDK_PLUS_ERR_INVALID;
        }
    }
    if(!queue_empty(nvme_device->uintr_qpair.queue)) { // 用户中断所在的qpair有未完成命令
        if(queue_empty(nvme_device->int_qpair.queue)) { // 内核中断所在的qpair没有未完成命令
            /* 所以直接按照用户中断部署的结构来部署即可 */
            if(sched_getcpu() != nvme_device->cpu_id) {
                SPDK_ERRLOG("CPU ID is not match\n");
                return SPDK_PLUS_ERR;
            }
        begin:
            do {
                local_irq_restore(g_curr_thread[nvme_device->cpu_id]->flags);
                g_io_completion_notify[nvme_device->cpu_id] = false;
                uint64_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                if(tmp_rc < 0) {
                    local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                    return tmp_rc;
                }
                rc += tmp_rc;
                if(tmp_rc > 0){ // 达到最小数目
                    local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                    return rc;
                }
            } while (g_io_completion_notify[nvme_device->cpu_id]);
            /* 看来还需要等待 */
            switch_thread(g_work_thread + nvme_device->cpu_id, g_idle_thread + nvme_device->cpu_id);
            g_curr_thread[nvme_device->cpu_id] = g_work_thread + nvme_device->cpu_id;
            goto begin;
            
        } else {
            bool no_limited = max_completions == 0;
            uint64_t uintr_arrival_time = nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->uintr_qpair);
            uint64_t int_arrival_time = nvme_get_sleep_naonotime_internel(nvme_device, nvme_device->int_qpair);
            if(uintr_arrival_time == UINT64_MAX || int_arrival_time == UINT64_MAX) {
                SPDK_ERRLOG("Sleep time is UINT64_MAX\n");
                return SPDK_PLUS_ERR;
            }
            if(uintr_arrival_time <= int_arrival_time) {
                /* 用户中断的时间戳小于等于内核中断的时间戳 */
                if(sched_getcpu() != nvme_device->cpu_id) {
                    SPDK_ERRLOG("CPU ID is not match\n");
                    return SPDK_PLUS_ERR;
                }
            begin:
                do {
                    local_irq_restore(g_curr_thread[nvme_device->cpu_id]->flags);
                    g_io_completion_notify[nvme_device->cpu_id] = false;
                    uint64_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                    if(tmp_rc < 0) {
                        local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                        return tmp_rc;
                    }
                    rc += tmp_rc;
                    if(tmp_rc > 0){ // 达到最小数目
                        local_irq_save(g_curr_thread[nvme_device->cpu_id]->flags);
                        return rc;
                    }
                } while (g_io_completion_notify[nvme_device->cpu_id]);
                /* 看来还需要等待 */
                switch_thread(g_work_thread + nvme_device->cpu_id, g_idle_thread + nvme_device->cpu_id);
                g_curr_thread[nvme_device->cpu_id] = g_work_thread + nvme_device->cpu_id;
                goto begin;
            } else {
                /* 用户中断的时间戳大于内核中断的时间戳 */
                while(1) {
                    uint64_t value = 0;
                    if(read(nvme_device->int_qpair.fd, &value, sizeof(value)) != sizeof(value)) {
                        SPDK_ERRLOG("Failed to read from int qpair fd\n");
                        return SPDK_PLUS_ERR;
                    }
                    uint64_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
                    if(tmp_rc < 0) {
                        return tmp_rc;
                    }
                    rc += tmp_rc;
                    if(tmp_rc > 0) {
                        return rc;
                    }
                }
            }
        }
    }
    if(!queue_empty(nvme_device->int_qpair.queue)) { // 内核中断所在的qpair有未完成命令
        while(1) {
            uint64_t value = 0;
            if(read(nvme_device->int_qpair.fd, &value, sizeof(value)) != sizeof(value)) {
                SPDK_ERRLOG("Failed to read from int qpair fd\n");
                return SPDK_PLUS_ERR;
            }
            uint64_t tmp_rc = nvme_process_completions_poll(nvme_device, max_completions);
            if(tmp_rc < 0) {
                return tmp_rc;
            }
            rc += tmp_rc;
            if(tmp_rc > 0) {
                return rc;
            }
        }
    }
    SPDK_ERRLOG("All qpair are empty\n");
    return SPDK_PLUS_ERR;
}

int spdk_plus_nvme_ns_cmd_flush(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg) {
    struct spdk_nvme_qpair *qpair = NULL;
    struct io_task *task = NULL;
    int rc;
    task = calloc(1, sizeof(struct io_task));
    if (!task) {
        SPDK_ERRLOG("Failed to allocate memory for task\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    task->cb_fn = cb_fn;
    task->io_mode = SPDK_PLUS_FLUSH;
    task->io_size = SPDK_PLUS_MONITOR_FLUSH;
    task->nvme_device = nvme_device;
    clock_gettime(CLOCK_MONOTONIC_RAW, &task->start_time);
    task->t = cb_arg;

    qpair = nvme_get_suitable_io_qpair(nvme_device, task, SPDK_PLUS_FLUSH);
    if (!qpair) {
        SPDK_ERRLOG("Failed to get suitable qpair\n");
        rc = SPDK_PLUS_ERR;
        goto failed;
    }
    rc = spdk_nvme_ns_cmd_flush(ns, qpair, io_complete, task);
    if (rc != 0) {
        SPDK_ERRLOG("Failed to send flush command\n");
        goto failed;
    }
    return rc;

failed:
    if (task) {
        free(task);
    }
    return rc;
}

static int 
spdk_plus_get_default_opts(enum spdk_plus_smart_schedule_module_status status,
    struct spdk_plus_smart_schedule_module_opts *opts) {
    opts->status = status;
    switch(status) {
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE:
            opts->read_sleep_rate = 0.99;
            opts->write_sleep_rate = 0.99;
            opts->read_alpha = 0.5;
            opts->write_alpha = 0.5;
            opts->threshold_ns = 100000; /* 100us */
            break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE:
            opts->read_sleep_rate = 0.9;
            opts->write_sleep_rate = 0.9;
            opts->read_alpha = 0.5;
            opts->write_alpha = 0.5;
            opts->threshold_ns = 100000; /* 100us */
            break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE:
            opts->read_sleep_rate = 0.8;
            opts->write_sleep_rate = 0.8;
            opts->read_alpha = 0.5;
            opts->write_alpha = 0.5;
            opts->threshold_ns = 100000; /* 100us */
            break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE:
            opts->read_sleep_rate = 0.7;
            opts->write_sleep_rate = 0.7;
            opts->read_alpha = 0.5;
            opts->write_alpha = 0.5;
            opts->threshold_ns = 100000; /* 100us */
            break;
        case SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE:
            opts->read_sleep_rate = 0.2;
            opts->write_sleep_rate = 0.2;
            opts->read_alpha = 0.5;
            opts->write_alpha = 0.5;
            opts->threshold_ns = 100000; /* 100us */
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

int spdk_plus_env_init(enum spdk_plus_smart_schedule_module_status status,
    struct spdk_plus_smart_schedule_module_opts *opts) {
    if(opts != NULL) {
        return SPDK_PLUS_ERR_NOT_SUPPORTED;
    }
    int rc;
    rc = spdk_plus_get_default_opts(status, &g_smart_schedule_module_opts);
    if (rc != SPDK_PLUS_SUCCESS) {
        SPDK_ERRLOG("Failed to get default opts\n");
        return rc;
    }
    return SPDK_PLUS_SUCCESS;
}