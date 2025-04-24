/* 这个文档是智能调度模块对外暴露API和定义的头文件 */

#include <stdint.h>
#include <spdk/nvme.h> /* Include SPDK NVMe header for required definitions */
#include <spdk/spdk_plus_log.h>

enum spdk_plus_errno {
    SPDK_PLUS_SUCCESS = 0, /* 成功 */
    SPDK_PLUS_ERR = -1, /* 错误 */
    SPDK_PLUS_ERR_NO_MEMORY = -2, /* 内存不足 */
    SPDK_PLUS_ERR_INVALID = -3, /* 无效参数 */
    SPDK_PLUS_ERR_BUSY = -4, /* 忙 */
    SPDK_PLUS_ERR_TIMEOUT = -5, /* 超时 */
    SPDK_PLUS_ERR_NOT_FOUND = -6, /* 找不到 */
    SPDK_PLUS_ERR_EXIST = -7, /* 已存在 */
    SPDK_PLUS_ERR_NOT_SUPPORTED = -8, /* 不支持 */
};

/* 这个是用于用户设置模块调度总体行为的 */
enum spdk_plus_smart_schedule_module_status {
    SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_POWER_SAVE = 0, /* 超级省电 TODO: 具体效果描述 */
    SPDK_PLUS_SMART_SCHEDULE_MODULE_POWER_SAVE = 1, /* 省电模式 TODO: 具体效果描述 */
    SPDK_PLUS_SMART_SCHEDULE_MODULE_BALANCE = 2, /* 平衡模式 TODO: 具体效果描述 */
    SPDK_PLUS_SMART_SCHEDULE_MODULE_PERFORMANCE = 3, /* 性能模式 TODO: 具体效果描述 */
    SPDK_PLUS_SMART_SCHEDULE_MODULE_SUPER_PERFORMANCE = 4, /* 最高性能 TODO: 具体效果描述 */
    SPDK_PLUS_SMART_SCHEDULE_MODULE_CUSTOM = 5, /* 自定义模式 自定义所有数值 */
};

struct spdk_plus_completion_notify_mode_opts {
    uint8_t poll : 1; /* 轮询模式 */
    uint8_t interrupt : 1; /* 内核中断模式 */
    uint8_t uintr : 1; /* 用户中断模式 */
    uint8_t int_poll : 1; /* 内核中断轮询模式 */
    uint8_t uintr_poll : 1; /* 用户中断轮询模式 */
    uint8_t reserved : 3; /* 保留位 */
};

struct spdk_plus_smart_schedule_module_opts {
    enum spdk_plus_smart_schedule_module_status status; /* 调度模块的预设状态 */
    struct spdk_plus_completion_notify_mode_opts notify_mode; /* 通知模式管理 */
    double read_sleep_rate; /* 休眠率 适用于中断/用户中断轮询 */
    double write_sleep_rate; /* 休眠率 适用于中断/用户中断轮询 */
    uint64_t threshold_ns; /* 阈值 （ns） 用于区分什么时候使用用户中断指令休眠，什么是否使用内核中断指令休眠 */
    double read_alpha; /* 读操作线性加权平均的alpha值 */
    double write_alpha; /* 写操作线性加权平均的alpha值 */
    bool enable_back_ssd; /* 是否开启后备ssd */
};

/* 根据这些跟踪大小记录平均时延 */
enum spdk_plus_monitor_io_size {
    SPDK_PLUS_MONITOR_IO_SIZE_4K = 0, /* 4K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_8K = 1, /* 8K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_16K = 2, /* 16K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_32K = 3, /* 32K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_64K = 4, /* 64K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_128K = 5, /* 128K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_256K = 6, /* 256K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_512K = 7, /* 512K IO */
    SPDK_PLUS_MONITOR_IO_SIZE_1M = 8, /* 1M IO */
    SPDK_PLUS_MONITOR_IO_SIZE_2M = 9, /* 2M IO */
    SPDK_PLUS_MONITOR_IO_SIZE_OVER_2M = 10, /* > 2M IO */
    SPDK_PLUS_MONITOR_FLUSH = 11, /* 刷新操作 */
    SPDK_PLUS_MONITOR_IO_SIZE_TOTAL_NUM /* 跟踪IO大小的总数 */
};

// 队列类型定义（对外暴露为不透明指针）
typedef void* QueueHandle;

struct spdk_plus_nvme_qpair {
    struct spdk_nvme_qpair* qpair; /* NVMe队列对 */
    int32_t fd; /* NVMe队列对的文件描述符 只有中断模式才需要 */
    QueueHandle queue; /* 当前队列时间管理队列 用于中断轮询 */
};

struct spdk_plus_nvme_threshold_opts {
    uint8_t depth_threshold1; /* 阈值深度 */
    uint8_t depth_threshold2; /* 阈值深度 */
    uint8_t depth_threshold3; /* 阈值深度 */
};

/* 读写基本单位数据结构 */
struct spdk_plus_smart_nvme {
    struct spdk_nvme_ctrlr *ctrlr; /* NVMe控制器 */
    struct spdk_nvme_ns *ns; /* NVMe命名空间 */
    struct spdk_plus_nvme_qpair poll_qpair; /* 轮询模式的NVMe队列对 */
    struct spdk_plus_nvme_qpair int_qpair; /* 内核中断模式的NVMe队列对 */
    struct spdk_plus_nvme_qpair uintr_qpair; /* 用户中断模式的NVMe队列对 */
    struct spdk_plus_nvme_qpair back_poll_qpair; /* 后备轮询模式的NVMe队列对 */
    uint16_t cpu_id; /* CPU ID */
    int32_t fd; /* 文件描述符 (用于控制线程通知事务时处理) */
    struct spdk_plus_nvme_threshold_opts threshold_opts; /* 阈值选项 */
    uint64_t io_write_btypes; /* 写入字节数 (循环统计，预定100微秒清除一次) */
    uint64_t io_read_btypes; /* 读取字节数 (循环统计，预定100微秒清除一次) */
    uint64_t avg_write_latency[SPDK_PLUS_MONITOR_IO_SIZE_TOTAL_NUM]; /* 平均写延迟 ns 用于中断轮询 */
    uint64_t avg_read_latency[SPDK_PLUS_MONITOR_IO_SIZE_TOTAL_NUM]; /* 平均读延迟 ns 用于中断轮询 */
    TAILQ_ENTRY(spdk_plus_smart_nvme)	link;
};

/* 系统整体初始化 */
int spdk_plus_env_init(enum spdk_plus_smart_schedule_module_status status,
    struct spdk_plus_smart_schedule_module_opts *opts, const char* dev_name);
/* 整个系统退出 */
int spdk_plus_env_fini(void);

/* 注册IO接口 —— 注意调用的时候必须已经到了固定的核心，否则用户中断可能出现问题 */
struct spdk_plus_smart_nvme *spdk_plus_nvme_ctrlr_alloc_io_device(struct spdk_nvme_ctrlr *ctrlr,
			       const struct spdk_nvme_io_qpair_opts *user_opts,
			       size_t opts_size);


/* 读写IO接口 */
int
spdk_plus_nvme_ns_cmd_read(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device, void *buffer,
		      uint64_t lba,
		      uint32_t lba_count, spdk_nvme_cmd_cb cb_fn, void *cb_arg,
		      uint32_t io_flags);

int spdk_plus_nvme_ns_cmd_readv(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    uint64_t lba, uint32_t lba_count,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
    spdk_nvme_req_reset_sgl_cb reset_sgl_fn,
    spdk_nvme_req_next_sge_cb next_sge_fn);

int
spdk_plus_nvme_ns_cmd_write(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
		       void *buffer, uint64_t lba,
		       uint32_t lba_count, spdk_nvme_cmd_cb cb_fn, void *cb_arg,
		       uint32_t io_flags);

int spdk_plus_nvme_ns_cmd_writev(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    uint64_t lba, uint32_t lba_count,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg, uint32_t io_flags,
    spdk_nvme_req_reset_sgl_cb reset_sgl_fn,
    spdk_nvme_req_next_sge_cb next_sge_fn);


/* 刷新接口 */
int spdk_plus_nvme_ns_cmd_flush(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg);

/* ZNS适配 */
int spdk_plus_nvme_zns_reset_zone(struct spdk_nvme_ns *ns, struct spdk_plus_smart_nvme *nvme_device,
    uint64_t slba, bool select_all,
    spdk_nvme_cmd_cb cb_fn, void *cb_arg);

/* 获取IO完成接口 */
int32_t spdk_plus_nvme_process_completions(struct spdk_plus_smart_nvme *nvme_device,
    uint32_t max_completions);

/* 完全释放qpair */
int spdk_plus_nvme_ctrlr_free_io_qpair(struct spdk_plus_smart_nvme *nvme_device);