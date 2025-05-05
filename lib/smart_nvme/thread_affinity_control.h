#include <stdint.h>
#include <spdk/nvme.h>

int32_t spdk_plus_get_sutiable_core_id(struct spdk_nvme_ctrlr *ctrlr);

void spdk_plus_set_thread_affinity(int32_t core_id);