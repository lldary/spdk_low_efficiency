/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2017 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/bdev_zone.h"
#include "spdk/accel.h"
#include "spdk/env.h"
#include "spdk/file.h"
#include "spdk/init.h"
#include "spdk/thread.h"
#include "spdk/log.h"
#include "spdk/string.h"
#include "spdk/queue.h"
#include "spdk/util.h"
#include "spdk/rpc.h"

#include "spdk_internal/event.h"

#include "config-host.h"
#include "fio.h"
#include "optgroup.h"
#include <cpufreq.h>

#ifdef for_each_rw_ddir
#define FIO_HAS_ZBD (FIO_IOOPS_VERSION >= 26)
#else
#define FIO_HAS_ZBD (0)
#endif

/* FreeBSD is missing CLOCK_MONOTONIC_RAW,
 * so alternative is provided. */
#ifndef CLOCK_MONOTONIC_RAW /* Defined in glibc bits/time.h */
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#ifdef SPDK_CONFIG_UINTR_MODE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <x86gprintrin.h>


#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>

#ifndef __NR_uintr_register_handler
#define __NR_uintr_wait_msix_interrupt 470
#define __NR_uintr_register_handler	471
#define __NR_uintr_unregister_handler	472
#define __NR_uintr_create_fd		473
#define __NR_uintr_register_sender	474
#define __NR_uintr_unregister_sender	475
#define __NR_uintr_wait			476
#endif

#define uintr_wait_msix_interrupt(ptr, flags)   syscall(__NR_uintr_wait_msix_interrupt, ptr, flags)
#define uintr_register_handler(handler, flags)	syscall(__NR_uintr_register_handler, handler, flags)
#define uintr_unregister_handler(flags)		syscall(__NR_uintr_unregister_handler, flags)
#define uintr_create_fd(vector, flags)		syscall(__NR_uintr_create_fd, vector, flags)
#define uintr_register_sender(fd, flags)	syscall(__NR_uintr_register_sender, fd, flags)
#define uintr_unregister_sender(ipi_idx, flags)	syscall(__NR_uintr_unregister_sender, ipi_idx, flags)
#define uintr_wait(usec, flags)			syscall(__NR_uintr_wait, usec, flags)

volatile uint32_t uintr_index = 0;
volatile uint32_t uintr_count[0xFF] = {0};
uint32_t cpuid_uipi_map[0xFF] = {0};
uint32_t uipi_list_count = 0;
uint32_t uipi_list[1024] = {0};
// struct spdk_fio_thread		*gl_fio_thread;
volatile bool is_idle = 0;
volatile bool should_run = 0; // TODO: 多线程需要修改
struct user_thread {
	uint64_t stack_space[0x10000];
	uint64_t rsp;
	uint64_t rip;
	uint64_t rflags;
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rbp;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
};
struct user_thread work_thread[0xFF], idle_thread[0xFF];
struct user_thread* current_thread[0xFF];
const uint64_t cpu_freq[0x10] = {800000UL,900000UL,1000000UL,1100000UL,1200000UL,1300000UL,1400000UL,1500000UL,1600000UL,1700000UL,1800000UL,1900000UL,2100000UL,2101000UL};
#define MAX_CPU_FREQ_STATE 13
#define MIN_CPU_FREQ_STATE 0
uint64_t freq_state[0xFF] = {0};
#endif

#ifdef SPDK_CONFIG_FREQ_MODE
#define UINTR_WAIT_EXPERIMENTAL_FLAG 0x1
#define __NR_uintr_wait_msix_interrupt 470
#define uintr_wait_msix_interrupt(ptr, flags)   syscall(__NR_uintr_wait_msix_interrupt, ptr, flags)
#endif

#if defined(SPDK_CONFIG_INT_POLL_MODE) || defined(SPDK_CONFIG_UINTR_POLL_MODE)
bool is128 = false; // IO大小获知
#endif

#ifdef SPDK_CONFIG_UINTR_POLL_MODE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <x86gprintrin.h>


#include <pthread.h>
#include <sched.h>

#ifndef __NR_uintr_register_handler
#define __NR_uintr_register_handler	471
#define __NR_uintr_unregister_handler	472
#define __NR_uintr_create_fd		473
#define __NR_uintr_register_sender	474
#define __NR_uintr_unregister_sender	475
#define __NR_uintr_wait			476
#endif

#define uintr_register_handler(handler, flags)	syscall(__NR_uintr_register_handler, handler, flags)
#define uintr_unregister_handler(flags)		syscall(__NR_uintr_unregister_handler, flags)
#define uintr_create_fd(vector, flags)		syscall(__NR_uintr_create_fd, vector, flags)
#define uintr_register_sender(fd, flags)	syscall(__NR_uintr_register_sender, fd, flags)
#define uintr_unregister_sender(ipi_idx, flags)	syscall(__NR_uintr_unregister_sender, ipi_idx, flags)
#define uintr_wait(usec, flags)			syscall(__NR_uintr_wait, usec, flags)
#endif

struct spdk_fio_options {
	void *pad;
	char *conf;
	char *json_conf;
	char *env_context;
	char *log_flags;
	unsigned mem_mb;
	int mem_single_seg;
	int initial_zone_reset;
	int zone_append;
	char *rpc_listen_addr;
};

struct spdk_fio_request {
	struct io_u		*io;
	struct thread_data	*td;
};

struct spdk_fio_target {
	struct spdk_bdev	*bdev;
	struct spdk_bdev_desc	*desc;
	struct spdk_io_channel	*ch;
	int32_t uipi_index;
	bool zone_append_enabled;

	TAILQ_ENTRY(spdk_fio_target) link;
};

struct spdk_fio_thread {
	struct thread_data		*td; /* fio thread context */
	struct spdk_thread		*thread; /* spdk thread context */

	TAILQ_HEAD(, spdk_fio_target)	targets;
	bool				failed; /* true if the thread failed to initialize */

	struct io_u		**iocq;		/* io completion queue */
	unsigned int		iocq_count;	/* number of iocq entries filled by last getevents */
	volatile unsigned int temp_iocq_count;
	unsigned int		iocq_size;	/* number of iocq entries allocated */
	TAILQ_ENTRY(spdk_fio_thread)	link;
	uint64_t cpu_id;
	int fd;
};

struct spdk_fio_zone_cb_arg {
	struct spdk_fio_target *target;
	struct spdk_bdev_zone_info *spdk_zones;
	int completed;
	uint64_t offset_blocks;
	struct zbd_zone *fio_zones;
	unsigned int nr_zones;
};

/* On App Thread (oat) context used for making sync calls from async calls. */
struct spdk_fio_oat_ctx {
	union {
		struct spdk_fio_setup_args {
			struct thread_data *td;
		} sa;
		struct spdk_fio_bdev_get_zoned_model_args {
			struct fio_file *f;
			enum zbd_zoned_model *model;
		} zma;
		struct spdk_fio_bdev_get_max_open_zones_args {
			struct fio_file *f;
			unsigned int *max_open_zones;
		} moza;
	} u;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int ret;
};

static bool g_spdk_env_initialized = false;
static const char *g_json_config_file = NULL;
static void *g_json_data;
static size_t g_json_data_size;
static const char *g_rpc_listen_addr = NULL;

static int spdk_fio_init(struct thread_data *td);
static void spdk_fio_cleanup(struct thread_data *td);
static size_t spdk_fio_poll_thread(struct spdk_fio_thread *fio_thread);
static int spdk_fio_handle_options(struct thread_data *td, struct fio_file *f,
				   struct spdk_bdev *bdev);
static int spdk_fio_handle_options_per_target(struct thread_data *td, struct fio_file *f);
static void spdk_fio_setup_oat(void *ctx);

static pthread_t g_init_thread_id = 0;
static pthread_mutex_t g_init_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_init_cond;
static bool g_poll_loop = true;
static TAILQ_HEAD(, spdk_fio_thread) g_threads = TAILQ_HEAD_INITIALIZER(g_threads);

/* Default polling timeout (ns) */
#define SPDK_FIO_POLLING_TIMEOUT 1000000000ULL

static __thread bool g_internal_thread = false;

/* Run msg_fn on app thread ("oat") and wait for it to call spdk_fio_wake_oat_waiter() */
static void
spdk_fio_sync_run_oat(void (*msg_fn)(void *), struct spdk_fio_oat_ctx *ctx)
{
	assert(!spdk_thread_is_app_thread(NULL));

	pthread_mutex_init(&ctx->mutex, NULL);
	pthread_cond_init(&ctx->cond, NULL);
	pthread_mutex_lock(&ctx->mutex);

	spdk_thread_send_msg(spdk_thread_get_app_thread(), msg_fn, ctx);

	/* Wake up the poll loop in spdk_init_thread_poll() */
	pthread_mutex_lock(&g_init_mtx);
	pthread_cond_signal(&g_init_cond);
	pthread_mutex_unlock(&g_init_mtx);

	/* Wait for msg_fn() to call spdk_fio_wake_oat_waiter() */
	pthread_cond_wait(&ctx->cond, &ctx->mutex);
	pthread_mutex_unlock(&ctx->mutex);

	pthread_mutex_destroy(&ctx->mutex);
	pthread_cond_destroy(&ctx->cond);
}

static void
spdk_fio_wake_oat_waiter(struct spdk_fio_oat_ctx *ctx)
{
	pthread_mutex_lock(&ctx->mutex);
	pthread_cond_signal(&ctx->cond);
	pthread_mutex_unlock(&ctx->mutex);
}

static int
spdk_fio_schedule_thread(struct spdk_thread *thread)
{
	struct spdk_fio_thread *fio_thread;

	if (g_internal_thread) {
		/* Do nothing. */
		return 0;
	}

	fio_thread = spdk_thread_get_ctx(thread);

	pthread_mutex_lock(&g_init_mtx);
	TAILQ_INSERT_TAIL(&g_threads, fio_thread, link);
	pthread_mutex_unlock(&g_init_mtx);

	return 0;
}

static int
spdk_fio_init_thread(struct thread_data *td)
{
	struct spdk_fio_thread *fio_thread;
	struct spdk_thread *thread;

	g_internal_thread = true;
	thread = spdk_thread_create("fio_thread", NULL);
	g_internal_thread = false;
	if (!thread) {
		SPDK_ERRLOG("failed to allocate thread\n");
		return -1;
	}

	fio_thread = spdk_thread_get_ctx(thread);
	fio_thread->td = td;
	fio_thread->thread = thread;
	td->io_ops_data = fio_thread;

	spdk_set_thread(thread);

	fio_thread->iocq_size = td->o.iodepth;
	fio_thread->iocq = calloc(fio_thread->iocq_size, sizeof(struct io_u *));
	assert(fio_thread->iocq != NULL);

	TAILQ_INIT(&fio_thread->targets);

	return 0;
}

static void
spdk_fio_bdev_close_targets(void *arg)
{
	struct spdk_fio_thread *fio_thread = arg;
	struct spdk_fio_target *target, *tmp;

	TAILQ_FOREACH_SAFE(target, &fio_thread->targets, link, tmp) {
		TAILQ_REMOVE(&fio_thread->targets, target, link);
		spdk_put_io_channel(target->ch);
		spdk_bdev_close(target->desc);
		free(target);
	}
}

static void
spdk_fio_cleanup_thread(struct spdk_fio_thread *fio_thread)
{
	spdk_thread_send_msg(fio_thread->thread, spdk_fio_bdev_close_targets, fio_thread);

	pthread_mutex_lock(&g_init_mtx);
	TAILQ_INSERT_TAIL(&g_threads, fio_thread, link);
	pthread_mutex_unlock(&g_init_mtx);
}

static void
spdk_fio_calc_timeout(struct spdk_fio_thread *fio_thread, struct timespec *ts)
{
	uint64_t timeout, now;

	if (spdk_thread_has_active_pollers(fio_thread->thread)) {
		return;
	}

	timeout = spdk_thread_next_poller_expiration(fio_thread->thread);
	now = spdk_get_ticks();

	if (timeout == 0) {
		timeout = now + (SPDK_FIO_POLLING_TIMEOUT * spdk_get_ticks_hz()) / SPDK_SEC_TO_NSEC;
	}

	if (timeout > now) {
		timeout = ((timeout - now) * SPDK_SEC_TO_NSEC) / spdk_get_ticks_hz() +
			  ts->tv_sec * SPDK_SEC_TO_NSEC + ts->tv_nsec;

		ts->tv_sec  = timeout / SPDK_SEC_TO_NSEC;
		ts->tv_nsec = timeout % SPDK_SEC_TO_NSEC;
	}
}

static void
spdk_fio_bdev_init_done(int rc, void *cb_arg)
{
	*(bool *)cb_arg = true;

	free(g_json_data);
	if (rc) {
		SPDK_ERRLOG("RUNTIME RPCs failed\n");
		exit(1);
	}
}

static void
spdk_fio_bdev_subsystem_init_done(int rc, void *cb_arg)
{
	if (rc) {
		SPDK_ERRLOG("subsystem init failed\n");
		exit(1);
	}

	spdk_rpc_set_state(SPDK_RPC_RUNTIME);
	spdk_subsystem_load_config(g_json_data, g_json_data_size,
				   spdk_fio_bdev_init_done, cb_arg, true);
}

static void
spdk_fio_bdev_startup_done(int rc, void *cb_arg)
{
	if (rc) {
		SPDK_ERRLOG("STARTUP RPCs failed\n");
		exit(1);
	}

	if (g_rpc_listen_addr != NULL) {
		if (spdk_rpc_initialize(g_rpc_listen_addr, NULL) != 0) {
			SPDK_ERRLOG("could not initialize RPC address %s\n", g_rpc_listen_addr);
			exit(1);
		}
	}

	spdk_subsystem_init(spdk_fio_bdev_subsystem_init_done, cb_arg);
}

static void
spdk_fio_bdev_init_start(void *arg)
{
	bool *done = arg;

	g_json_data = spdk_posix_file_load_from_name(g_json_config_file, &g_json_data_size);

	if (g_json_data == NULL) {
		SPDK_ERRLOG("could not allocate buffer for json config file\n");
		exit(1);
	}

	/* Load SPDK_RPC_STARTUP RPCs from config file */
	assert(spdk_rpc_get_state() == SPDK_RPC_STARTUP);
	spdk_subsystem_load_config(g_json_data, g_json_data_size,
				   spdk_fio_bdev_startup_done, done, true);
}

static void
spdk_fio_bdev_fini_done(void *cb_arg)
{
	*(bool *)cb_arg = true;

	spdk_rpc_finish();
}

static void
spdk_fio_bdev_fini_start(void *arg)
{
	bool *done = arg;

	spdk_subsystem_fini(spdk_fio_bdev_fini_done, done);
}

static void *
spdk_init_thread_poll(void *arg)
{
	struct spdk_fio_options		*eo = arg;
	struct spdk_fio_thread		*fio_thread;
	struct spdk_fio_thread		*thread, *tmp;
	struct spdk_env_opts		opts;
	bool				done;
	int				rc;
	struct timespec			ts;
	struct thread_data		td = {};

	/* Create a dummy thread data for use on the initialization thread. */
	td.o.iodepth = 32;
	td.eo = eo;

	/* Parse the SPDK configuration file */
	eo = arg;

	if (eo->conf && eo->json_conf) {
		SPDK_ERRLOG("Cannot provide two types of configuration files\n");
		rc = EINVAL;
		goto err_exit;
	} else if (eo->conf && strlen(eo->conf)) {
		g_json_config_file = eo->conf;
	} else if (eo->json_conf && strlen(eo->json_conf)) {
		g_json_config_file = eo->json_conf;
	} else {
		SPDK_ERRLOG("No configuration file provided\n");
		rc = EINVAL;
		goto err_exit;
	}

	/* Initialize the RPC listen address */
	if (eo->rpc_listen_addr) {
		g_rpc_listen_addr = eo->rpc_listen_addr;
	}

	/* Initialize the environment library */
	opts.opts_size = sizeof(opts);
	spdk_env_opts_init(&opts);
	opts.name = "fio";

	if (eo->mem_mb) {
		opts.mem_size = eo->mem_mb;
	}
	opts.hugepage_single_segments = eo->mem_single_seg;
	if (eo->env_context) {
		opts.env_context = eo->env_context;
	}

	if (spdk_env_init(&opts) < 0) {
		SPDK_ERRLOG("Unable to initialize SPDK env\n");
		rc = EINVAL;
		goto err_exit;
	}
	spdk_unaffinitize_thread();

	if (eo->log_flags) {
		char *tok = strtok(eo->log_flags, ",");
		do {
			rc = spdk_log_set_flag(tok);
			if (rc < 0) {
				SPDK_ERRLOG("unknown spdk log flag %s\n", tok);
				rc = EINVAL;
				goto err_exit;
			}
		} while ((tok = strtok(NULL, ",")) != NULL);
#ifdef DEBUG
		spdk_log_set_print_level(SPDK_LOG_DEBUG);
#endif
	}

	spdk_thread_lib_init(spdk_fio_schedule_thread, sizeof(struct spdk_fio_thread));

	/* Create an SPDK thread temporarily */
	rc = spdk_fio_init_thread(&td);
	if (rc < 0) {
		SPDK_ERRLOG("Failed to create initialization thread\n");
		goto err_exit;
	}

	fio_thread = td.io_ops_data;

	/* Initialize the bdev layer */
	done = false;
	spdk_thread_send_msg(fio_thread->thread, spdk_fio_bdev_init_start, &done);

	do {
		spdk_fio_poll_thread(fio_thread);
	} while (!done);

	/*
	 * Continue polling until there are no more events.
	 * This handles any final events posted by pollers.
	 */
	while (spdk_fio_poll_thread(fio_thread) > 0) {};

	/* Set condition variable */
	pthread_mutex_lock(&g_init_mtx);
	pthread_cond_signal(&g_init_cond);

	pthread_mutex_unlock(&g_init_mtx);

	while (g_poll_loop) {
		spdk_fio_poll_thread(fio_thread);

		pthread_mutex_lock(&g_init_mtx);
		if (!TAILQ_EMPTY(&g_threads)) {
			TAILQ_FOREACH_SAFE(thread, &g_threads, link, tmp) {
				if (spdk_thread_is_exited(thread->thread)) {
					TAILQ_REMOVE(&g_threads, thread, link);
					free(thread->iocq);
					spdk_thread_destroy(thread->thread);
				} else {
					spdk_fio_poll_thread(thread);
				}
			}

			/* If there are exiting threads to poll, don't sleep. */
			pthread_mutex_unlock(&g_init_mtx);
			continue;
		}

		/* Figure out how long to sleep. */
		clock_gettime(CLOCK_MONOTONIC, &ts);
		spdk_fio_calc_timeout(fio_thread, &ts);

		rc = pthread_cond_timedwait(&g_init_cond, &g_init_mtx, &ts);
		pthread_mutex_unlock(&g_init_mtx);

		if (rc != 0 && rc != ETIMEDOUT) {
			break;
		}
	}

	spdk_fio_cleanup_thread(fio_thread);

	/* Finalize the bdev layer */
	done = false;
	spdk_thread_send_msg(fio_thread->thread, spdk_fio_bdev_fini_start, &done);

	do {
		spdk_fio_poll_thread(fio_thread);

		TAILQ_FOREACH_SAFE(thread, &g_threads, link, tmp) {
			spdk_fio_poll_thread(thread);
		}
	} while (!done);

	/* Now exit all the threads */
	TAILQ_FOREACH(thread, &g_threads, link) {
		spdk_set_thread(thread->thread);
		spdk_thread_exit(thread->thread);
		spdk_set_thread(NULL);
	}

	/* And wait for them to gracefully exit */
	while (!TAILQ_EMPTY(&g_threads)) {
		TAILQ_FOREACH_SAFE(thread, &g_threads, link, tmp) {
			if (spdk_thread_is_exited(thread->thread)) {
				TAILQ_REMOVE(&g_threads, thread, link);
				free(thread->iocq);
				spdk_thread_destroy(thread->thread);
			} else {
				spdk_thread_poll(thread->thread, 0, 0);
			}
		}
	}

	pthread_exit(NULL);

err_exit:
	exit(rc);
	return NULL;
}

static int
spdk_fio_init_env(struct thread_data *td)
{
	pthread_condattr_t attr;
	int rc = -1;

	if (pthread_condattr_init(&attr)) {
		SPDK_ERRLOG("Unable to initialize condition variable\n");
		return -1;
	}

	if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC)) {
		SPDK_ERRLOG("Unable to initialize condition variable\n");
		goto out;
	}

	if (pthread_cond_init(&g_init_cond, &attr)) {
		SPDK_ERRLOG("Unable to initialize condition variable\n");
		goto out;
	}

	/*
	 * Spawn a thread to handle initialization operations and to poll things
	 * like the admin queues periodically.
	 */
	rc = pthread_create(&g_init_thread_id, NULL, &spdk_init_thread_poll, td->eo);
	if (rc != 0) {
		SPDK_ERRLOG("Unable to spawn thread to poll admin queue. It won't be polled.\n");
	}

	/* Wait for background thread to advance past the initialization */
	pthread_mutex_lock(&g_init_mtx);
	pthread_cond_wait(&g_init_cond, &g_init_mtx);
	pthread_mutex_unlock(&g_init_mtx);
out:
	pthread_condattr_destroy(&attr);
	return rc;
}

static bool
fio_redirected_to_dev_null(void)
{
	char path[PATH_MAX] = "";
	ssize_t ret;

	ret = readlink("/proc/self/fd/1", path, sizeof(path));

	if (ret == -1 || strcmp(path, "/dev/null") != 0) {
		return false;
	}

	ret = readlink("/proc/self/fd/2", path, sizeof(path));

	if (ret == -1 || strcmp(path, "/dev/null") != 0) {
		return false;
	}

	return true;
}

static int
spdk_fio_init_spdk_env(struct thread_data *td)
{
	static pthread_mutex_t setup_lock = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&setup_lock);
	if (!g_spdk_env_initialized) {
		if (spdk_fio_init_env(td)) {
			pthread_mutex_unlock(&setup_lock);
			SPDK_ERRLOG("failed to initialize\n");
			return -1;
		}

		g_spdk_env_initialized = true;
	}
	pthread_mutex_unlock(&setup_lock);

	return 0;
}

/* Called for each thread to fill in the 'real_file_size' member for
 * each file associated with this thread. This is called prior to
 * the init operation (spdk_fio_init()) below. This call will occur
 * on the initial start up thread if 'create_serialize' is true, or
 * on the thread actually associated with 'thread_data' if 'create_serialize'
 * is false.
 */
static int
spdk_fio_setup(struct thread_data *td)
{
	struct spdk_fio_oat_ctx ctx = { 0 };

	/*
	 * If we're running in a daemonized FIO instance, it's possible
	 * fd 1/2 were re-used for something important by FIO. Newer fio
	 * versions are careful to redirect those to /dev/null, but if we're
	 * not, we'll abort early, so we don't accidentally write messages to
	 * an important file, etc.
	 */
	if (is_backend && !fio_redirected_to_dev_null()) {
		char buf[1024];
		snprintf(buf, sizeof(buf),
			 "SPDK FIO plugin is in daemon mode, but stdout/stderr "
			 "aren't redirected to /dev/null. Aborting.");
		fio_server_text_output(FIO_LOG_ERR, buf, sizeof(buf));
		return -1;
	}

	if (!td->o.use_thread) {
		SPDK_ERRLOG("must set thread=1 when using spdk plugin\n");
		return -1;
	}

	if (spdk_fio_init_spdk_env(td) != 0) {
		return -1;
	}

	ctx.u.sa.td = td;
	spdk_fio_sync_run_oat(spdk_fio_setup_oat, &ctx);
	return ctx.ret;
}

static int
_spdk_fio_add_file(void *ctx, struct spdk_bdev *bdev)
{
	struct thread_data *td = ctx;

	add_file(td, spdk_bdev_get_name(bdev), 0, 1);
	return 0;
}

static void
spdk_fio_setup_oat(void *_ctx)
{
	struct spdk_fio_oat_ctx *ctx = _ctx;
	struct thread_data *td = ctx->u.sa.td;
	unsigned int i;
	struct fio_file *f;

	if (td->o.nr_files == 1 && strcmp(td->files[0]->file_name, "*") == 0) {
		/* add all available bdevs as fio targets */
		spdk_for_each_bdev_leaf(td, _spdk_fio_add_file);
	}

	for_each_file(td, f, i) {
		struct spdk_bdev *bdev;

		if (strcmp(f->file_name, "*") == 0) {
			/* Explicitly set file size to 0 here to make sure fio doesn't try to
			 * actually send I/O to this "*" file.
			 */
			f->real_file_size = 0;
			continue;
		}

		bdev = spdk_bdev_get_by_name(f->file_name);
		if (!bdev) {
			SPDK_ERRLOG("Unable to find bdev with name %s\n", f->file_name);
			ctx->ret = -1;
			goto out;
		}

		f->real_file_size = spdk_bdev_get_num_blocks(bdev) *
				    spdk_bdev_get_block_size(bdev);
		f->filetype = FIO_TYPE_BLOCK;
		fio_file_set_size_known(f);

		ctx->ret = spdk_fio_handle_options(td, f, bdev);
		if (ctx->ret) {
			goto out;
		}
	}

	ctx->ret = 0;
out:
	spdk_fio_wake_oat_waiter(ctx);
}

static void
fio_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
		  void *event_ctx)
{
	SPDK_WARNLOG("Unsupported bdev event: type %d\n", type);
}

static void
spdk_fio_bdev_open(void *arg)
{
	struct thread_data *td = arg;
	struct spdk_fio_thread *fio_thread;
	unsigned int i;
	struct fio_file *f;
	int rc;

	fio_thread = td->io_ops_data;

	for_each_file(td, f, i) {
		struct spdk_fio_target *target;

		if (strcmp(f->file_name, "*") == 0) {
			continue;
		}

		target = calloc(1, sizeof(*target));
		if (!target) {
			SPDK_ERRLOG("Unable to allocate memory for I/O target.\n");
			fio_thread->failed = true;
			return;
		}

		rc = spdk_bdev_open_ext(f->file_name, true, fio_bdev_event_cb, NULL,
					&target->desc);
		if (rc) {
			SPDK_ERRLOG("Unable to open bdev %s\n", f->file_name);
			free(target);
			fio_thread->failed = true;
			return;
		}

		target->bdev = spdk_bdev_desc_get_bdev(target->desc);

#define __bdev_to_io_dev(bdev) (((char *)bdev) + 1)
#ifdef SPDK_CONFIG_INT_MODE
		// TODO: 设置中断模式
		SPDK_ERRLOG("中断模式\n");
		bool interrupt_mode = true;
#else
		bool interrupt_mode = false;
#endif
		target->ch = spdk_bdev_get_io_channel_int(target->desc, interrupt_mode);
		if (!target->ch) {
			SPDK_ERRLOG("Unable to get I/O channel for bdev.\n");
			spdk_bdev_close(target->desc);
			free(target);
			fio_thread->failed = true;
			return;
		}

#ifdef SPDK_CONFIG_UINTR_MODE
		int fd = get_channel_fd(target->ch);
		target->uipi_index = uintr_register_sender(fd, 0);
		if(target->uipi_index < 0) {
			SPDK_ERRLOG("Unable to register sender\n");
			spdk_put_io_channel(target->ch);
			spdk_bdev_close(target->desc);
			free(target);
			fio_thread->failed = true;
			return;
		}
		cpuid_uipi_map[fio_thread->cpu_id] = target->uipi_index;
		uipi_list[uipi_list_count++] = target->uipi_index;
		SPDK_ERRLOG("uipi_index: %d\n", target->uipi_index);
		_senduipi(target->uipi_index);
#endif

		f->engine_data = target;

		rc = spdk_fio_handle_options_per_target(td, f);
		if (rc) {
			SPDK_ERRLOG("Failed to handle options for: %s\n", f->file_name);
			f->engine_data = NULL;
			spdk_put_io_channel(target->ch);
			spdk_bdev_close(target->desc);
			free(target);
			fio_thread->failed = true;
			return;
		}

		TAILQ_INSERT_TAIL(&fio_thread->targets, target, link);
	}
}

#ifdef SPDK_CONFIG_UINTR_MODE

void switch_thread(struct user_thread *from, struct user_thread *to);
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


// 函数声明
void __attribute__((interrupt)) __attribute__((target("general-regs-only", "inline-all-stringops")))
uintr_get_handler(struct __uintr_frame *ui_frame, unsigned long long vector);

void __attribute__((interrupt))__attribute__((target("general-regs-only", "inline-all-stringops")))
uintr_get_handler(struct __uintr_frame *ui_frame,
	      unsigned long long vector)
{
#ifndef SPDK_CONFIG_FAST_MODE
	uintr_wait_msix_interrupt(2101000UL, vector);
#endif
	// uintr_count[vector]++;
	_senduipi(cpuid_uipi_map[vector]);
	uint64_t cpu_index = vector;
	if(current_thread[cpu_index] == &idle_thread[cpu_index]) {
		int flags;
		local_irq_save(flags);
		current_thread[cpu_index] = &work_thread[cpu_index];
		switch_thread(idle_thread + cpu_index, work_thread + cpu_index);	
		local_irq_restore(flags);
	}
}

void switch_thread(struct user_thread *from, struct user_thread *to) {
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
	_stui();
	asm volatile ("ret");
}

void idle_thread_func(void);

void idle_thread_func(void) {
	int loop = 0;
	uint64_t cpu_id;

    // 使用内联汇编将 %rbx 的值赋给 loop
    asm volatile(
        "mov %%rbx, %0"  // 将 %rbx 的值移动到 loop（%0）
        : "=r"(cpu_id)      // 输出操作数：将 %rbx 的值存储到 loop
    );
	// void *ptr = (void*)(current_thread + cpu_id);
	begin:
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	// _umonitor(ptr);
    // _umwait(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	_tpause(0, 1000000000UL);
	if(loop > 1 << 12) {
#ifndef SPDK_CONFIG_FAST_MODE
		uintr_wait_msix_interrupt(2101000UL, cpu_id);
#endif
		int flags;
		local_irq_save(flags);
		current_thread[cpu_id] = &work_thread[cpu_id];
		switch_thread(idle_thread + cpu_id, work_thread + cpu_id);
		local_irq_restore(flags);
	}
	loop++;
	// freq_state[cpu_id] = freq_state[cpu_id] == 0 ? 0 : freq_state[cpu_id]--; 
	// uintr_wait_msix_interrupt(cpu_freq[freq_state[cpu_id]], 0x1);
	// write(STDOUT_FILENO, "Idle Thread1\n", 13);
	// write(STDOUT_FILENO, "Idle Thread2\n", 13);
	goto begin;
}
#endif

/* Called for each thread, on that thread, shortly after the thread
 * starts.
 *
 * Also called by spdk_fio_report_zones(), since we need an I/O channel
 * in order to get the zone report. (fio calls the .report_zones callback
 * before it calls the .init callback.)
 * Therefore, if fio was run with --zonemode=zbd, the thread will already
 * be initialized by the time that fio calls the .init callback.
 */
static int
spdk_fio_init(struct thread_data *td)
{
	struct spdk_fio_thread *fio_thread;
	int rc;

#if defined(SPDK_CONFIG_UINTR_MODE) || defined(SPDK_CONFIG_FAST_MODE)
	int cpu_id = td->thread_number % 10 + 20;
	cpufreq_set_frequency(cpu_id, 2101000UL);
#elif SPDK_CONFIG_FREQ_MODE
	int cpu_id = td->thread_number % 10 + 30;
#else
	int cpu_id = td->thread_number % 10;
#endif 

	cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    // 将当前线程绑定到指定的 CPU
    pthread_t thread = pthread_self();
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0) {
        SPDK_ERRLOG("pthread_setaffinity_np");
    }
#ifdef SPDK_CONFIG_UINTR_MODE
	SPDK_ERRLOG("开始注册用户态中断处理函数\n");
	#define UINTR_HANDLER_FLAG_WAITING_RECEIVER	0x1000 // TODO: 这个定义也一直需要吗？
	if (uintr_register_handler(uintr_get_handler, UINTR_HANDLER_FLAG_WAITING_RECEIVER)) {
		SPDK_ERRLOG("Interrupt handler register error");
		exit(EXIT_FAILURE);
	}
	idle_thread[cpu_id].rsp = (uint64_t)((unsigned char*)(idle_thread[cpu_id].stack_space) + sizeof(idle_thread[cpu_id].stack_space) - 0x38);
	idle_thread[cpu_id].rip = (uint64_t)idle_thread_func;
	idle_thread[cpu_id].stack_space[0xFFFF] = idle_thread_func;
	idle_thread[cpu_id].stack_space[0xFFFE] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFFD] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFFC] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFFB] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFFA] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF9] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF8] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF7] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF6] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF5] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF4] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF3] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF2] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF1] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFF0] = cpu_id;
	idle_thread[cpu_id].stack_space[0xFFEF] = cpu_id;
	uint64_t ptr = *(uint64_t*)((unsigned char*)(idle_thread[cpu_id].rsp) + 0x30);
	if(ptr != (uint64_t)idle_thread_func) {
		SPDK_ERRLOG("Error: %lx\n", ptr);
		exit(EXIT_FAILURE);
	}
#endif
	if (spdk_fio_init_spdk_env(td) != 0) {
		return -1;
	}

	/* If thread has already been initialized, do nothing. */
	if (td->io_ops_data) {
		return 0;
	}

	rc = spdk_fio_init_thread(td);
	if (rc) {
		return rc;
	}

	fio_thread = td->io_ops_data;
	assert(fio_thread);
	fio_thread->fd = 0;
	fio_thread->failed = false;

#if defined(SPDK_CONFIG_UINTR_MODE) || defined(SPDK_CONFIG_FREQ_MODE)
	fio_thread->cpu_id = cpu_id;
#endif

	spdk_thread_send_msg(fio_thread->thread, spdk_fio_bdev_open, td);

	while (spdk_fio_poll_thread(fio_thread) > 0) {}

	if (fio_thread->failed) {
		return -1;
	}

	return 0;
}

static void
spdk_fio_cleanup(struct thread_data *td)
{
	struct spdk_fio_thread *fio_thread = td->io_ops_data;

	spdk_fio_cleanup_thread(fio_thread);
	td->io_ops_data = NULL;
}

static int
spdk_fio_open(struct thread_data *td, struct fio_file *f)
{

	return 0;
}

static int
spdk_fio_close(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int
spdk_fio_iomem_alloc(struct thread_data *td, size_t total_mem)
{
	struct spdk_fio_thread	*fio_thread = td->io_ops_data;
	struct spdk_fio_target	*fio_target;
	int32_t numa_id = SPDK_ENV_NUMA_ID_ANY, tmp_numa_id;

	/* If all bdevs used by this fio_thread have the same numa socket
	 * id, allocate from that socket. If they come from different numa
	 * sockets, then don't try to optimize and just use NUMA_ID_ANY.
	 */
	TAILQ_FOREACH(fio_target, &fio_thread->targets, link) {
		tmp_numa_id = spdk_bdev_get_numa_id(fio_target->bdev);
		if (numa_id == SPDK_ENV_NUMA_ID_ANY) {
			numa_id = tmp_numa_id;
		} else if (tmp_numa_id != numa_id &&
			   tmp_numa_id != SPDK_ENV_NUMA_ID_ANY) {
			numa_id = SPDK_ENV_NUMA_ID_ANY;
			break;
		}
	}

	td->orig_buffer = spdk_dma_zmalloc_socket(total_mem, 0x1000, NULL, numa_id);
	return td->orig_buffer == NULL;
}

static void
spdk_fio_iomem_free(struct thread_data *td)
{
	spdk_dma_free(td->orig_buffer);
}

static int
spdk_fio_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct spdk_fio_request	*fio_req;

	io_u->engine_data = NULL;

	fio_req = calloc(1, sizeof(*fio_req));
	if (fio_req == NULL) {
		return 1;
	}
	fio_req->io = io_u;
	fio_req->td = td;

	io_u->engine_data = fio_req;

	return 0;
}

static void
spdk_fio_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct spdk_fio_request *fio_req = io_u->engine_data;

	if (fio_req) {
		assert(fio_req->io == io_u);
		free(fio_req);
		io_u->engine_data = NULL;
	}
}

static void
spdk_fio_completion_cb(struct spdk_bdev_io *bdev_io,
		       bool success,
		       void *cb_arg)
{
	struct spdk_fio_request		*fio_req = cb_arg;
	struct thread_data		*td = fio_req->td;
	struct spdk_fio_thread		*fio_thread = td->io_ops_data;

	assert(fio_thread->iocq_count < fio_thread->iocq_size);
	fio_req->io->error = success ? 0 : EIO;
	fio_thread->iocq[fio_thread->iocq_count++] = fio_req->io;
	// fio_thread->iocq[fio_thread->temp_iocq_count++] = fio_req->io;
	// SPDK_ERRLOG("temp_iocq_count = %d\n", fio_thread->temp_iocq_count);

	spdk_bdev_free_io(bdev_io);
}

#if FIO_IOOPS_VERSION >= 24
typedef enum fio_q_status fio_q_status_t;
#else
typedef int fio_q_status_t;
#endif

static uint64_t
spdk_fio_zone_bytes_to_blocks(struct spdk_bdev *bdev, uint64_t offset_bytes, uint64_t *zone_start,
			      uint64_t num_bytes, uint64_t *num_blocks)
{
	uint32_t block_size = spdk_bdev_get_block_size(bdev);
	*zone_start = spdk_bdev_get_zone_id(bdev, offset_bytes / block_size);
	*num_blocks = num_bytes / block_size;
	return (offset_bytes % block_size) | (num_bytes % block_size);
}

static fio_q_status_t
spdk_fio_queue(struct thread_data *td, struct io_u *io_u)
{
	int rc = 1;
	struct spdk_fio_request	*fio_req = io_u->engine_data;
	struct spdk_fio_target *target = io_u->file->engine_data;

	assert(fio_req->td == td);

	if (!target) {
		SPDK_ERRLOG("Unable to look up correct I/O target.\n");
		fio_req->io->error = ENODEV;
		return FIO_Q_COMPLETED;
	}

#if defined(SPDK_CONFIG_UINTR_POLL_MODE) || defined(SPDK_CONFIG_INT_POLL_MODE)
	if(io_u->xfer_buflen == 128 * 1024){
		is128 = true;
	} else {
		is128 = false;
	}
#endif
#ifdef SPDK_CONFIG_UINTR_MODE
	_senduipi(target->uipi_index);
#endif
	switch (io_u->ddir) {
	case DDIR_READ:
		rc = spdk_bdev_read(target->desc, target->ch,
				    io_u->buf, io_u->offset, io_u->xfer_buflen,
				    spdk_fio_completion_cb, fio_req);
		break;
	case DDIR_WRITE:
		if (!target->zone_append_enabled) {
			rc = spdk_bdev_write(target->desc, target->ch,
					     io_u->buf, io_u->offset, io_u->xfer_buflen,
					     spdk_fio_completion_cb, fio_req);
		} else {
			uint64_t zone_start, num_blocks;
			if (spdk_fio_zone_bytes_to_blocks(target->bdev, io_u->offset, &zone_start,
							  io_u->xfer_buflen, &num_blocks) != 0) {
				rc = -EINVAL;
				break;
			}
			rc = spdk_bdev_zone_append(target->desc, target->ch, io_u->buf,
						   zone_start, num_blocks, spdk_fio_completion_cb,
						   fio_req);
		}
		break;
	case DDIR_TRIM:
		rc = spdk_bdev_unmap(target->desc, target->ch,
				     io_u->offset, io_u->xfer_buflen,
				     spdk_fio_completion_cb, fio_req);
		break;
	case DDIR_SYNC:
		rc = spdk_bdev_flush(target->desc, target->ch,
				     io_u->offset, io_u->xfer_buflen,
				     spdk_fio_completion_cb, fio_req);
		break;
	default:
		assert(false);
		break;
	}

	if (rc == -ENOMEM) {
		return FIO_Q_BUSY;
	}

	if (rc != 0) {
		fio_req->io->error = abs(rc);
		return FIO_Q_COMPLETED;
	}

	return FIO_Q_QUEUED;
}

static struct io_u *
spdk_fio_event(struct thread_data *td, int event)
{
	struct spdk_fio_thread *fio_thread = td->io_ops_data;

	assert(event >= 0);
	assert((unsigned)event < fio_thread->iocq_count);
	return fio_thread->iocq[event];
}

static size_t
spdk_fio_poll_thread(struct spdk_fio_thread *fio_thread)
{
	return spdk_thread_poll(fio_thread->thread, 0, 0);
}

static size_t
spdk_fio_poll_thread_int(struct spdk_fio_thread *fio_thread)
{
#ifdef SPDK_CONFIG_INT_MODE
#ifdef SPDK_CONFIG_UINTR_MODE
	spdk_thread_poll(fio_thread->thread, 0, 0);
	if(fio_thread->iocq_count >= 1){
		return 0;
	}
	uint64_t cpu_id = fio_thread->cpu_id;
#ifndef SPDK_CONFIG_FAST_MODE
	// #define UINTR_WAIT_EXPERIMENTAL_FLAG 0x1
	uintr_wait_msix_interrupt(800000UL, cpu_id);
#endif
	int flags;
	local_irq_save(flags);
	current_thread[cpu_id] = &idle_thread[cpu_id];
	switch_thread(work_thread + cpu_id, idle_thread + cpu_id);
	local_irq_restore(flags);
	spdk_thread_poll(fio_thread->thread, 0, 0);
	return 0;

#else
	int max_fd = 0;
	struct spdk_fio_target *target = NULL;
	uint32_t i = 0;
	int epfd = fio_thread->fd;
	if(epfd == 0){
		epfd = epoll_create1(0);
		if (epfd == -1) {
			SPDK_ERRLOG("epoll_create1 failed");
			exit(EXIT_FAILURE);
		}
		TAILQ_FOREACH(target, &fio_thread->targets, link) {
			int fd = get_channel_fd(target->ch);
			// fd_array[i++] = fd;
			SPDK_ERRLOG("fd = %d\n", fd);
			if (fd >= 0) {
				struct epoll_event ev;
				ev.events = EPOLLIN;  // 监听可读事件
				ev.data.fd = fd;  // 关联的文件描述符
				if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
					SPDK_ERRLOG("epoll_ctl failed");
					exit(EXIT_FAILURE);
				}
			}
			max_fd = fd > max_fd ? fd : max_fd;
		}
		fio_thread->fd = epfd;
	}	
	struct epoll_event events[10];
	int nfds = epoll_wait(epfd, events, 10, -1);
	if (nfds == -1) {
		perror("epoll_wait failed");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < nfds; i++) {
		if (events[i].events & EPOLLIN) {
			// printf("Data available to read on fd %d\n", events[i].data.fd);
			// 读取数据
			uint64_t value;
			int rc = 0;
			while(rc >= 0) 
				rc = read(events[i].data.fd, &value, sizeof(value));
		}
	}
#endif
	return spdk_thread_poll(fio_thread->thread, 0, 0);
#else
	return spdk_thread_poll(fio_thread->thread, 0, 0);
#endif
}

static int
spdk_fio_getevents(struct thread_data *td, unsigned int min,
		   unsigned int max, const struct timespec *t)
{	
	struct spdk_fio_thread *fio_thread = td->io_ops_data;
#ifdef SPDK_CONFIG_FREQ_MODE
	uintr_wait_msix_interrupt(800000UL, fio_thread->cpu_id);
#endif
	struct timespec t0, t1;
	uint64_t timeout = 0;

	if (t) {
		timeout = t->tv_sec * SPDK_SEC_TO_NSEC + t->tv_nsec;
		clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
	}

	fio_thread->iocq_count = 0;

#ifdef SPDK_CONFIG_INT_POLL_MODE
	spdk_fio_poll_thread_int(fio_thread);

	if (fio_thread->iocq_count >= min) {
		return fio_thread->iocq_count;
	}
	if(is128){
		struct timespec sleep_time;
		sleep_time.tv_sec = 0;
		sleep_time.tv_nsec = 22000;
		nanosleep(&sleep_time, NULL);
	} else {
		struct timespec sleep_time;
		sleep_time.tv_sec = 0;
		sleep_time.tv_nsec = 2000;
		nanosleep(&sleep_time, NULL);
	}
#endif
#ifdef SPDK_CONFIG_UINTR_POLL_MODE
	spdk_fio_poll_thread_int(fio_thread);

	if (fio_thread->iocq_count >= min) {
		return fio_thread->iocq_count;
	}
	if(is128){
		uintr_wait(22, 0);
	} else {
		uintr_wait(2, 0);
	}
#endif

#if defined(SPDK_CONFIG_INT_MODE) && !defined(SPDK_CONFIG_UINTR_MODE)
	static bool temp = true;
	if(false){
		temp = false;
		for(;;){
			spdk_thread_poll(fio_thread->thread, 0, 0);
			if (fio_thread->iocq_count >= min) {
				return fio_thread->iocq_count;
			}
		}
	}else{
		spdk_thread_poll(fio_thread->thread, 0, 0);
	}
	if (fio_thread->iocq_count >= min) {
		return fio_thread->iocq_count;
	}
	// SPDK_ERRLOG("中断模式\n");
#endif

	for (;;) {
		spdk_fio_poll_thread_int(fio_thread);

		if (fio_thread->iocq_count >= min) {
#ifdef SPDK_CONFIG_FREQ_MODE
			uintr_wait_msix_interrupt(2101000UL, fio_thread->cpu_id);
#endif
			return fio_thread->iocq_count;
		}

		if (t) {
			clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
			uint64_t elapse = ((t1.tv_sec - t0.tv_sec) * SPDK_SEC_TO_NSEC)
					  + t1.tv_nsec - t0.tv_nsec;
			if (elapse > timeout) {
				break;
			}
		}
	}
#ifdef SPDK_CONFIG_FREQ_MODE
	uintr_wait_msix_interrupt(2101000UL, fio_thread->cpu_id);
#endif
	return fio_thread->iocq_count;
}

static int
spdk_fio_invalidate(struct thread_data *td, struct fio_file *f)
{
	/* TODO: This should probably send a flush to the device, but for now just return successful. */
	return 0;
}

#if FIO_HAS_ZBD
/* Runs on app thread (oat) */
static void
spdk_fio_get_zoned_model_oat(void *arg)
{
	struct spdk_fio_oat_ctx *ctx = arg;
	struct fio_file *f = ctx->u.zma.f;
	enum zbd_zoned_model *model = ctx->u.zma.model;
	struct spdk_bdev *bdev;

	if (f->filetype != FIO_TYPE_BLOCK) {
		SPDK_ERRLOG("Unsupported filetype: %d\n", f->filetype);
		ctx->ret = -EINVAL;
		goto out;
	}

	bdev = spdk_bdev_get_by_name(f->file_name);
	if (!bdev) {
		SPDK_ERRLOG("Cannot get zoned model, no bdev with name: %s\n", f->file_name);
		ctx->ret = -ENODEV;
		goto out;
	}

	if (spdk_bdev_is_zoned(bdev)) {
		*model = ZBD_HOST_MANAGED;
	} else {
		*model = ZBD_NONE;
	}

	ctx->ret = 0;
out:
	spdk_fio_wake_oat_waiter(ctx);
}

static int
spdk_fio_get_zoned_model(struct thread_data *td, struct fio_file *f, enum zbd_zoned_model *model)
{
	struct spdk_fio_oat_ctx ctx = { 0 };

	ctx.u.zma.f = f;
	ctx.u.zma.model = model;

	spdk_fio_sync_run_oat(spdk_fio_get_zoned_model_oat, &ctx);

	return ctx.ret;
}


static void
spdk_fio_bdev_get_zone_info_done(struct spdk_bdev_io *bdev_io, bool success, void *arg)
{
	struct spdk_fio_zone_cb_arg *cb_arg = arg;
	unsigned int i;
	int handled_zones = 0;

	if (!success) {
		spdk_bdev_free_io(bdev_io);
		cb_arg->completed = -EIO;
		return;
	}

	for (i = 0; i < cb_arg->nr_zones; i++) {
		struct spdk_bdev_zone_info *zone_src = &cb_arg->spdk_zones[handled_zones];
		struct zbd_zone *zone_dest = &cb_arg->fio_zones[handled_zones];
		uint32_t block_size = spdk_bdev_get_block_size(cb_arg->target->bdev);

		switch (zone_src->type) {
		case SPDK_BDEV_ZONE_TYPE_SEQWR:
			zone_dest->type = ZBD_ZONE_TYPE_SWR;
			break;
		case SPDK_BDEV_ZONE_TYPE_SEQWP:
			zone_dest->type = ZBD_ZONE_TYPE_SWP;
			break;
		case SPDK_BDEV_ZONE_TYPE_CNV:
			zone_dest->type = ZBD_ZONE_TYPE_CNV;
			break;
		default:
			spdk_bdev_free_io(bdev_io);
			cb_arg->completed = -EIO;
			return;
		}

		zone_dest->len = spdk_bdev_get_zone_size(cb_arg->target->bdev) * block_size;
		zone_dest->capacity = zone_src->capacity * block_size;
		zone_dest->start = zone_src->zone_id * block_size;
		zone_dest->wp = zone_src->write_pointer * block_size;

		switch (zone_src->state) {
		case SPDK_BDEV_ZONE_STATE_EMPTY:
			zone_dest->cond = ZBD_ZONE_COND_EMPTY;
			break;
		case SPDK_BDEV_ZONE_STATE_IMP_OPEN:
			zone_dest->cond = ZBD_ZONE_COND_IMP_OPEN;
			break;
		case SPDK_BDEV_ZONE_STATE_EXP_OPEN:
			zone_dest->cond = ZBD_ZONE_COND_EXP_OPEN;
			break;
		case SPDK_BDEV_ZONE_STATE_FULL:
			zone_dest->cond = ZBD_ZONE_COND_FULL;
			break;
		case SPDK_BDEV_ZONE_STATE_CLOSED:
			zone_dest->cond = ZBD_ZONE_COND_CLOSED;
			break;
		case SPDK_BDEV_ZONE_STATE_READ_ONLY:
			zone_dest->cond = ZBD_ZONE_COND_READONLY;
			break;
		case SPDK_BDEV_ZONE_STATE_OFFLINE:
			zone_dest->cond = ZBD_ZONE_COND_OFFLINE;
			break;
		case SPDK_BDEV_ZONE_STATE_NOT_WP:
			zone_dest->cond = ZBD_ZONE_COND_NOT_WP;
			/* Set WP to end of zone for zone types w/o WP (e.g. Conv. zones in SMR) */
			zone_dest->wp = zone_dest->start + zone_dest->capacity;
			break;
		default:
			spdk_bdev_free_io(bdev_io);
			cb_arg->completed = -EIO;
			return;
		}
		handled_zones++;
	}

	spdk_bdev_free_io(bdev_io);
	cb_arg->completed = handled_zones;
}

static void
spdk_fio_bdev_get_zone_info(void *arg)
{
	struct spdk_fio_zone_cb_arg *cb_arg = arg;
	struct spdk_fio_target *target = cb_arg->target;
	int rc;

	rc = spdk_bdev_get_zone_info(target->desc, target->ch, cb_arg->offset_blocks,
				     cb_arg->nr_zones, cb_arg->spdk_zones,
				     spdk_fio_bdev_get_zone_info_done, cb_arg);
	if (rc < 0) {
		cb_arg->completed = rc;
	}
}

static int
spdk_fio_report_zones(struct thread_data *td, struct fio_file *f, uint64_t offset,
		      struct zbd_zone *zones, unsigned int nr_zones)
{
	struct spdk_fio_target *target;
	struct spdk_fio_thread *fio_thread;
	struct spdk_fio_zone_cb_arg cb_arg;
	uint32_t block_size;
	int rc;

	if (nr_zones == 0) {
		return 0;
	}

	/* spdk_fio_report_zones() is only called before the bdev I/O channels have been created.
	 * Since we need an I/O channel for report_zones(), call spdk_fio_init() to initialize
	 * the thread early.
	 * spdk_fio_report_zones() might be called several times by fio, if e.g. the zone report
	 * for all zones does not fit in the buffer that fio has allocated for the zone report.
	 * It is safe to call spdk_fio_init(), even if the thread has already been initialized.
	 */
	rc = spdk_fio_init(td);
	if (rc) {
		return rc;
	}
	fio_thread = td->io_ops_data;
	target = f->engine_data;

	assert(fio_thread);
	assert(target);

	block_size = spdk_bdev_get_block_size(target->bdev);

	cb_arg.target = target;
	cb_arg.completed = 0;
	cb_arg.offset_blocks = offset / block_size;
	cb_arg.fio_zones = zones;
	cb_arg.nr_zones = spdk_min(nr_zones, spdk_bdev_get_num_zones(target->bdev));

	cb_arg.spdk_zones = calloc(1, sizeof(*cb_arg.spdk_zones) * cb_arg.nr_zones);
	if (!cb_arg.spdk_zones) {
		SPDK_ERRLOG("Could not allocate memory for zone report!\n");
		rc = -ENOMEM;
		goto cleanup_thread;
	}

	spdk_thread_send_msg(fio_thread->thread, spdk_fio_bdev_get_zone_info, &cb_arg);
	do {
		spdk_fio_poll_thread(fio_thread);
	} while (!cb_arg.completed);

	/* Free cb_arg.spdk_zones. The report in fio format is stored in cb_arg.fio_zones/zones. */
	free(cb_arg.spdk_zones);

	rc = cb_arg.completed;
	if (rc < 0) {
		SPDK_ERRLOG("Failed to get zone info: %d\n", rc);
		goto cleanup_thread;
	}

	/* Return the amount of zones successfully copied. */
	return rc;

cleanup_thread:
	spdk_fio_cleanup(td);

	return rc;
}

static void
spdk_fio_bdev_zone_reset_done(struct spdk_bdev_io *bdev_io, bool success, void *arg)
{
	struct spdk_fio_zone_cb_arg *cb_arg = arg;

	spdk_bdev_free_io(bdev_io);

	if (!success) {
		cb_arg->completed = -EIO;
	} else {
		cb_arg->completed = 1;
	}
}

static void
spdk_fio_bdev_zone_reset(void *arg)
{
	struct spdk_fio_zone_cb_arg *cb_arg = arg;
	struct spdk_fio_target *target = cb_arg->target;
	int rc;

	rc = spdk_bdev_zone_management(target->desc, target->ch, cb_arg->offset_blocks,
				       SPDK_BDEV_ZONE_RESET,
				       spdk_fio_bdev_zone_reset_done, cb_arg);
	if (rc < 0) {
		cb_arg->completed = rc;
	}
}

static int
spdk_fio_reset_zones(struct spdk_fio_thread *fio_thread, struct spdk_fio_target *target,
		     uint64_t offset, uint64_t length)
{
	uint64_t zone_size_bytes;
	uint32_t block_size;
	int rc;

	assert(fio_thread);
	assert(target);

	block_size = spdk_bdev_get_block_size(target->bdev);
	zone_size_bytes = spdk_bdev_get_zone_size(target->bdev) * block_size;

	for (uint64_t cur = offset; cur < offset + length; cur += zone_size_bytes) {
		struct spdk_fio_zone_cb_arg cb_arg = {
			.target = target,
			.completed = 0,
			.offset_blocks = cur / block_size,
		};

		spdk_thread_send_msg(fio_thread->thread, spdk_fio_bdev_zone_reset, &cb_arg);
		do {
			spdk_fio_poll_thread(fio_thread);
		} while (!cb_arg.completed);

		rc = cb_arg.completed;
		if (rc < 0) {
			SPDK_ERRLOG("Failed to reset zone: %d\n", rc);
			return rc;
		}
	}

	return 0;
}

static int
spdk_fio_reset_wp(struct thread_data *td, struct fio_file *f, uint64_t offset, uint64_t length)
{
	return spdk_fio_reset_zones(td->io_ops_data, f->engine_data, offset, length);
}
#endif

#if FIO_IOOPS_VERSION >= 30
static void
spdk_fio_get_max_open_zones_oat(void *_ctx)
{
	struct spdk_fio_oat_ctx *ctx = _ctx;
	struct fio_file *f = ctx->u.moza.f;
	struct spdk_bdev *bdev;

	bdev = spdk_bdev_get_by_name(f->file_name);
	if (!bdev) {
		SPDK_ERRLOG("Cannot get max open zones, no bdev with name: %s\n", f->file_name);
		ctx->ret = -ENODEV;
	} else {
		*ctx->u.moza.max_open_zones = spdk_bdev_get_max_open_zones(bdev);
		ctx->ret = 0;
	}

	spdk_fio_wake_oat_waiter(ctx);
}

static int
spdk_fio_get_max_open_zones(struct thread_data *td, struct fio_file *f,
			    unsigned int *max_open_zones)
{
	struct spdk_fio_oat_ctx ctx = { 0 };

	ctx.u.moza.f = f;
	ctx.u.moza.max_open_zones = max_open_zones;

	spdk_fio_sync_run_oat(spdk_fio_get_max_open_zones_oat, &ctx);

	return ctx.ret;
}
#endif

static int
spdk_fio_handle_options(struct thread_data *td, struct fio_file *f, struct spdk_bdev *bdev)
{
	struct spdk_fio_options *fio_options = td->eo;

	if (fio_options->initial_zone_reset && spdk_bdev_is_zoned(bdev)) {
#if FIO_HAS_ZBD
		int rc = spdk_fio_init(td);
		if (rc) {
			return rc;
		}
		/* offset used to indicate conventional zones that need to be skipped (reset not allowed) */
		rc = spdk_fio_reset_zones(td->io_ops_data, f->engine_data, td->o.start_offset,
					  f->real_file_size - td->o.start_offset);
		if (rc) {
			spdk_fio_cleanup(td);
			return rc;
		}
#else
		SPDK_ERRLOG("fio version is too old to support zoned block devices\n");
#endif
	}

	return 0;
}

static int
spdk_fio_handle_options_per_target(struct thread_data *td, struct fio_file *f)
{
	struct spdk_fio_target *target = f->engine_data;
	struct spdk_fio_options *fio_options = td->eo;

	if (fio_options->zone_append && spdk_bdev_is_zoned(target->bdev)) {
		if (spdk_bdev_io_type_supported(target->bdev, SPDK_BDEV_IO_TYPE_ZONE_APPEND)) {
			SPDK_DEBUGLOG(fio_bdev, "Using zone appends instead of writes on: '%s'\n",
				      f->file_name);
			target->zone_append_enabled = true;
		} else {
			SPDK_WARNLOG("Falling back to writes on: '%s' - bdev lacks zone append cmd\n",
				     f->file_name);
		}
	}

	return 0;
}

static struct fio_option options[] = {
	{
		.name		= "spdk_conf",
		.lname		= "SPDK configuration file",
		.type		= FIO_OPT_STR_STORE,
		.off1		= offsetof(struct spdk_fio_options, conf),
		.help		= "A SPDK JSON configuration file",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_INVALID,
	},
	{
		.name           = "spdk_json_conf",
		.lname          = "SPDK JSON configuration file",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct spdk_fio_options, json_conf),
		.help           = "A SPDK JSON configuration file",
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_INVALID,
	},
	{
		.name		= "spdk_mem",
		.lname		= "SPDK memory in MB",
		.type		= FIO_OPT_INT,
		.off1		= offsetof(struct spdk_fio_options, mem_mb),
		.help		= "Amount of memory in MB to allocate for SPDK",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_INVALID,
	},
	{
		.name		= "spdk_single_seg",
		.lname		= "SPDK switch to create just a single hugetlbfs file",
		.type		= FIO_OPT_BOOL,
		.off1		= offsetof(struct spdk_fio_options, mem_single_seg),
		.help		= "If set to 1, SPDK will use just a single hugetlbfs file",
		.def            = "0",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_INVALID,
	},
	{
		.name           = "log_flags",
		.lname          = "log flags",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct spdk_fio_options, log_flags),
		.help           = "SPDK log flags to enable",
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_INVALID,
	},
	{
		.name		= "initial_zone_reset",
		.lname		= "Reset Zones on initialization",
		.type		= FIO_OPT_INT,
		.off1		= offsetof(struct spdk_fio_options, initial_zone_reset),
		.def		= "0",
		.help		= "Reset Zones on initialization (0=disable, 1=Reset All Zones)",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_INVALID,
	},
	{
		.name		= "zone_append",
		.lname		= "Use zone append instead of write",
		.type		= FIO_OPT_INT,
		.off1		= offsetof(struct spdk_fio_options, zone_append),
		.def		= "0",
		.help		= "Use zone append instead of write (1=zone append, 0=write)",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_INVALID,
	},
	{
		.name           = "env_context",
		.lname          = "Environment context options",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct spdk_fio_options, env_context),
		.help           = "Opaque context for use of the env implementation",
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_INVALID,
	},
	{
		.name		= "spdk_rpc_listen_addr",
		.lname		= "SPDK RPC listen address",
		.type		= FIO_OPT_STR_STORE,
		.off1		= offsetof(struct spdk_fio_options, rpc_listen_addr),
		.help		= "The address to listen the RPC operations",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_INVALID,
	},
	{
		.name		= NULL,
	},
};

/* FIO imports this structure using dlsym */
struct ioengine_ops ioengine = {
	.name			= "spdk_bdev",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_RAWIO | FIO_NOEXTEND | FIO_NODISKUTIL | FIO_MEMALIGN | FIO_DISKLESSIO,
	.setup			= spdk_fio_setup,
	.init			= spdk_fio_init,
	/* .prep		= unused, */
	.queue			= spdk_fio_queue,
	/* .commit		= unused, */
	.getevents		= spdk_fio_getevents,
	.event			= spdk_fio_event,
	/* .errdetails		= unused, */
	/* .cancel		= unused, */
	.cleanup		= spdk_fio_cleanup,
	.open_file		= spdk_fio_open,
	.close_file		= spdk_fio_close,
	.invalidate		= spdk_fio_invalidate,
	/* .unlink_file		= unused, */
	/* .get_file_size	= unused, */
	/* .terminate		= unused, */
	.iomem_alloc		= spdk_fio_iomem_alloc,
	.iomem_free		= spdk_fio_iomem_free,
	.io_u_init		= spdk_fio_io_u_init,
	.io_u_free		= spdk_fio_io_u_free,
#if FIO_HAS_ZBD
	.get_zoned_model	= spdk_fio_get_zoned_model,
	.report_zones		= spdk_fio_report_zones,
	.reset_wp		= spdk_fio_reset_wp,
#endif
#if FIO_IOOPS_VERSION >= 30
	.get_max_open_zones	= spdk_fio_get_max_open_zones,
#endif
	.option_struct_size	= sizeof(struct spdk_fio_options),
	.options		= options,
};

static void fio_init
spdk_fio_register(void)
{
	register_ioengine(&ioengine);
}

static void
spdk_fio_finish_env(void)
{
	pthread_mutex_lock(&g_init_mtx);
	g_poll_loop = false;
	pthread_cond_signal(&g_init_cond);
	pthread_mutex_unlock(&g_init_mtx);
	pthread_join(g_init_thread_id, NULL);

	spdk_thread_lib_fini();
	spdk_env_fini();
}

static void fio_exit
spdk_fio_unregister(void)
{
	if (g_spdk_env_initialized) {
		spdk_fio_finish_env();
		g_spdk_env_initialized = false;
	}
	unregister_ioengine(&ioengine);
}

SPDK_LOG_REGISTER_COMPONENT(fio_bdev)
