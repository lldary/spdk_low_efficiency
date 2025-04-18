#include <sys/queue.h>
#include <stdint.h>
#include <time.h>

struct nvme_timestamp {
    uint32_t io_mode;
    uint32_t io_size;
    struct timespec ts;
    TAILQ_ENTRY(nvme_timestamp) link;
};

// 队列类型定义（对外暴露为不透明指针）
typedef void* QueueHandle;

// 创建队列
QueueHandle create_queue(void);

// 入队
void enqueue(QueueHandle q, struct nvme_timestamp value);

// 获取队头元素
// 注意：这里的获取队头元素是非阻塞的，如果队列为空，返回一个空的 timespec
struct nvme_timestamp queue_front(QueueHandle q);

// 出队
struct nvme_timestamp dequeue(QueueHandle q);

// 判断是否为空
uint8_t queue_empty(QueueHandle q);

// 获取队列大小
// 注意：这里的获取队列大小是非阻塞的，如果队列为空，返回0
uint32_t queue_size(QueueHandle q);

// 销毁队列
void destroy_queue(QueueHandle q);