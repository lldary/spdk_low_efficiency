/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 * Copyright (c) 2020 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MLX5_H
#define MLX5_H

#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <limits.h>


#include <valgrind/memcheck.h>

#define PFX		"mlx5: "

#ifndef PCI_VENDOR_ID_MELLANOX
#define PCI_VENDOR_ID_MELLANOX 0x15b3
#endif
#define to_mxxx(xxx, type) container_of(ib##xxx, struct mlx5_##type, ibv_##xxx)
typedef _Atomic(uint32_t) atomic_uint32_t;

enum {
	MLX5_IB_MMAP_CMD_SHIFT	= 8,
	MLX5_IB_MMAP_CMD_MASK	= 0xff,
};

enum {
	MLX5_CQE_VERSION_V0	= 0,
	MLX5_CQE_VERSION_V1	= 1,
};

enum {
	MLX5_ADAPTER_PAGE_SIZE		= 4096,
	MLX5_ADAPTER_PAGE_SHIFT		= 12,
};

#define MLX5_CQ_PREFIX "MLX_CQ"
#define MLX5_QP_PREFIX "MLX_QP"
#define MLX5_MR_PREFIX "MLX_MR"
#define MLX5_RWQ_PREFIX "MLX_RWQ"
#define MLX5_SRQ_PREFIX "MLX_SRQ"
#define MLX5_MAX_LOG2_CONTIG_BLOCK_SIZE 23
#define MLX5_MIN_LOG2_CONTIG_BLOCK_SIZE 12


#ifdef MLX5_DEBUG
#define mlx5_dbg(fp, mask, format, arg...)				\
do {									\
	if (mask & mlx5_debug_mask) {					\
		int tmp = errno;					\
		fprintf(fp, "%s:%d: " format, __func__, __LINE__, ##arg);	\
		errno = tmp;						\
	}								\
} while (0)

#else
static inline void mlx5_dbg(FILE *fp, uint32_t mask, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
static inline void mlx5_dbg(FILE *fp, uint32_t mask, const char *fmt, ...)
{
}
#endif


enum mlx5_alloc_type {
	MLX5_ALLOC_TYPE_ANON,
	MLX5_ALLOC_TYPE_HUGE,
	MLX5_ALLOC_TYPE_CONTIG,
	MLX5_ALLOC_TYPE_PREFER_HUGE,
	MLX5_ALLOC_TYPE_PREFER_CONTIG,
	MLX5_ALLOC_TYPE_EXTERNAL,
	MLX5_ALLOC_TYPE_CUSTOM,
	MLX5_ALLOC_TYPE_ALL
};




struct mlx5_spinlock {
	pthread_spinlock_t		lock;
	int				in_use;
	int				need_lock;
};

struct list_node
{
	struct list_node *next, *prev;
};


struct mlx5_hugetlb_mem {
	int			shmid;
	void		       *shmaddr;
	unsigned long		*bitmap;
	unsigned long		bmp_size;
	struct list_node	entry;
};

struct mlx5_buf {
	void			       *buf;
	size_t				length;
	int                             base;
	struct mlx5_hugetlb_mem	       *hmem;
	enum mlx5_alloc_type		type;
	uint64_t			resource_type;
	size_t				req_alignment;
	void	*mparent_domain;
};


struct verbs_cq {
	union {
		struct ibv_cq cq;
		struct ibv_cq_ex cq_ex;
	};
};



struct mlx5_cq {
	struct verbs_cq			verbs_cq;
	struct mlx5_buf			buf_a;
	struct mlx5_buf			buf_b;
	struct mlx5_buf		       *active_buf;
	struct mlx5_buf		       *resize_buf;
	int				resize_cqes;
	int				active_cqes;
	struct mlx5_spinlock		lock;
	uint32_t			cqn;
	uint32_t			cons_index;
	__be32			       *dbrec;
	bool				custom_db;
	int				arm_sn;
};


#define to_mxxx(xxx, type) container_of(ib##xxx, struct mlx5_##type, ibv_##xxx)

static inline struct mlx5_cq *to_mcq(struct ibv_cq *ibcq)
{
	return ibcq;
}


#endif /* MLX5_H */
