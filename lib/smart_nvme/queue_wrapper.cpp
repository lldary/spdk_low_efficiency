// queue_wrapper.cpp
#include "queue_wrapper.hpp"

struct QueueImpl {
    std::queue<struct nvme_timestamp> q;
};

QueueHandle create_queue() {
    return new QueueImpl();
}

void enqueue(QueueHandle q, struct nvme_timestamp value) {
    ((QueueImpl*)q)->q.push(value);
}

struct nvme_timestamp queue_front(QueueHandle q) {
    QueueImpl* impl = (QueueImpl*)q;
    if (!impl->q.empty()) {
        return impl->q.front();
    }
    return {0, 0}; // 返回一个空的 timespec
}

struct nvme_timestamp dequeue(QueueHandle q) {
    QueueImpl* impl = (QueueImpl*)q;
    if (!impl->q.empty()) {
        struct nvme_timestamp val = impl->q.front();
        impl->q.pop();
        return val;
    }
    return {0, 0}; // 返回一个空的 timespec
}

uint8_t queue_empty(QueueHandle q) {
    return ((QueueImpl*)q)->q.empty();
}

uint32_t queue_size(QueueHandle q) {
    return ((QueueImpl*)q)->q.size();
}

void destroy_queue(QueueHandle q) {
    delete (QueueImpl*)q;
}
