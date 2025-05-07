#include <numa.h>
#include <numaif.h>
#include <spdk/spdk_plus_log.h>
#include <spdk/log.h>
#include <spdk/smart_nvme.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>

#define CORE_NUMBER 0XFF

int32_t last_core_id = 0;

uint8_t cpus[CORE_NUMBER] = {0};
pthread_mutex_t cpu_mutex = PTHREAD_MUTEX_INITIALIZER;

int32_t spdk_plus_get_sutiable_core_id(struct spdk_nvme_ctrlr *ctrlr)
{
    if (ctrlr == NULL)
    {
        ERRLOG("ctrlr is NULL\n");
        return SPDK_PLUS_ERR_INVALID;
    }
    int32_t numa_id = spdk_nvme_ctrlr_get_numa_id(ctrlr);
    int32_t core_id = -1;
    int32_t cpu_number = numa_num_configured_cpus();
    INFOLOG("numa_id: %d, cpu_number: %d\n", numa_id, cpu_number);
    SPDK_ERRLOG("numa_id: %d, cpu_number: %d\n", numa_id, cpu_number);
    pthread_mutex_lock(&cpu_mutex);
    for (int32_t cpu = 0; cpu < cpu_number; cpu++)
    {
        int node = numa_node_of_cpu(cpu);
        if (numa_id == node)
        {
            DEBUGLOG("CPU %d is in NUMA node %d\n", cpu, numa_id);
            SPDK_ERRLOG("[ DEBUG ] CPU %d is in NUMA node %d\n", cpu, numa_id);
            if (core_id == -1 || cpus[cpu] <= cpus[core_id])
            {
                core_id = cpu;
            }
        }
    }
    if (core_id == -1)
    {
        ERRLOG("No suitable core found\n");
        SPDK_ERRLOG("No suitable core found\n");
        pthread_mutex_unlock(&cpu_mutex);
        return SPDK_PLUS_ERR_KERNEL_API_FAILED;
    }

    if (last_core_id == 0)
    {
        last_core_id = rand() % ((((uint64_t)ctrlr) & 0xf0000) >> 16) + 1;
    }
    else
    {
        last_core_id++;
    }
    core_id = last_core_id;
    cpus[core_id]++;
    pthread_mutex_unlock(&cpu_mutex);
    return core_id;
}

void spdk_plus_set_thread_affinity(int32_t core_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
    {
        ERRLOG("pthread_setaffinity_np failed\n");
        return;
    }
    DEBUGLOG("Set thread affinity to core %d\n", core_id);
    return;
}