// queue_wrapper.c
#include "queue_wrapper.h"
#include <stdlib.h>

struct QueueImpl {
    TAILQ_HEAD(, nvme_timestamp) q;
    uint32_t size;
};

QueueHandle create_queue(void) {
    struct QueueImpl* queue = calloc(1, sizeof(struct QueueImpl));
    if (!queue) {
        return NULL;
    }
    TAILQ_INIT(&queue->q);
    return (QueueHandle)queue;
}

void enqueue(QueueHandle q, struct nvme_timestamp value) {
    struct QueueImpl* impl = (struct QueueImpl*)q;
    if (!impl) {
        return;
    }
    if (impl->size >= UINT32_MAX) {
        return; // 队列已满
    }
    struct nvme_timestamp* new_value = malloc(sizeof(struct nvme_timestamp));
    if (!new_value) {
        return; // 内存分配失败
    }
    *new_value = value; // 复制值
    TAILQ_INSERT_TAIL(&impl->q, new_value, link);
    impl->size++;
    return;
}

struct nvme_timestamp queue_front(QueueHandle q) {
    struct QueueImpl* impl = (struct QueueImpl*)q;
    if (!impl->size) {
        struct nvme_timestamp empty_value;
        empty_value = *TAILQ_FIRST(&impl->q);
        return empty_value; // 返回队头元素
    }
    struct nvme_timestamp empty_value = {0, 0, {0, 0}};
    return empty_value;
}

struct nvme_timestamp dequeue(QueueHandle q) {
    struct QueueImpl* impl = (struct QueueImpl*)q;
    struct nvme_timestamp result = {0, 0, {0, 0}};
    if (!impl->size) {
        return result; // 队列为空
    }
    struct nvme_timestamp* value = TAILQ_FIRST(&impl->q);
    result = *value;
    TAILQ_REMOVE(&impl->q, value, link);
    free(value); // 释放内存
    impl->size--;
    return result;
}

uint8_t queue_empty(QueueHandle q) {
    return ((struct QueueImpl*)q)->size == 0;
}

uint32_t queue_size(QueueHandle q) {
    return ((struct QueueImpl*)q)->size;
}

void destroy_queue(QueueHandle q) {
    struct QueueImpl* impl = (struct QueueImpl*)q;
    while (!queue_empty(q)) {
        dequeue(q);
    }
    free(impl);
}
