SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 10
SO_MINOR := 0

C_SRCS = smart_nvme.c queue_wrapper.c power-scheduler.c

AS_SRCS = switch_thread.S

LIBNAME = smart_nvme

CFLAGS += -Wpointer-arith -muintr -I$(DPDK_INC_DIR)

LCFLAGS += -L$(DPDK_LIB_DIR)

SPDK_MAP_FILE = $(abspath $(CURDIR)/spdk_smart_nvme.map)

include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk