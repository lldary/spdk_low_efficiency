#  SPDX-License-Identifier: BSD-3-Clause
#  Copyright (C) 2015 Intel Corporation.
#  Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES
#  All rights reserved.
#

SPDK_ROOT_DIR := $(abspath $(CURDIR)/../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk
include $(SPDK_ROOT_DIR)/mk/spdk.modules.mk

APP = spdk_nvme_perf

C_SRCS := perf.c 

AS_SRCS = switch_thread.S

SPDK_LIB_LIST += $(SOCK_MODULES_LIST) nvme vmd keyring_file

ifeq ($(OS),Linux)
SYS_LIBS += -laio
CFLAGS += -DHAVE_LIBAIO
endif

include $(SPDK_ROOT_DIR)/mk/spdk.app.mk

install: $(APP)
	$(INSTALL_APP)

uninstall:
	$(UNINSTALL_APP)
