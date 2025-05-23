/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2016 Intel Corporation.
 *   All rights reserved.
 */

#include "spdk/stdinc.h"

#include "spdk/init.h"
#include "spdk/log.h"
#include "spdk/queue.h"
#include "spdk/thread.h"

#include "spdk_internal/init.h"
#include "spdk/env.h"

#include "spdk/json.h"

#include "subsystem.h"

TAILQ_HEAD(spdk_subsystem_list, spdk_subsystem);
struct spdk_subsystem_list g_subsystems = TAILQ_HEAD_INITIALIZER(g_subsystems);

TAILQ_HEAD(spdk_subsystem_depend_list, spdk_subsystem_depend);
struct spdk_subsystem_depend_list g_subsystems_deps = TAILQ_HEAD_INITIALIZER(g_subsystems_deps);
static struct spdk_subsystem *g_next_subsystem;
static bool g_subsystems_initialized = false;
static bool g_subsystems_init_interrupted = false;
static spdk_subsystem_init_fn g_subsystem_start_fn = NULL;
static void *g_subsystem_start_arg = NULL;
static spdk_msg_fn g_subsystem_stop_fn = NULL;
static void *g_subsystem_stop_arg = NULL;
static struct spdk_thread *g_fini_thread = NULL;

void
spdk_add_subsystem(struct spdk_subsystem *subsystem)
{
	TAILQ_INSERT_TAIL(&g_subsystems, subsystem, tailq);
}

void
spdk_add_subsystem_depend(struct spdk_subsystem_depend *depend)
{
	TAILQ_INSERT_TAIL(&g_subsystems_deps, depend, tailq);
}

static struct spdk_subsystem *
_subsystem_find(struct spdk_subsystem_list *list, const char *name)
{
	struct spdk_subsystem *iter;

	TAILQ_FOREACH(iter, list, tailq) {
		if (strcmp(name, iter->name) == 0) {
			return iter;
		}
	}

	return NULL;
}

struct spdk_subsystem *
subsystem_find(const char *name)
{
	return _subsystem_find(&g_subsystems, name);
}

bool
spdk_subsystem_exists(const char *name)
{
	return subsystem_find(name) != NULL;
}

struct spdk_subsystem *
subsystem_get_first(void)
{
	return TAILQ_FIRST(&g_subsystems);
}

struct spdk_subsystem *
subsystem_get_next(struct spdk_subsystem *cur_subsystem)
{
	return TAILQ_NEXT(cur_subsystem, tailq);
}


struct spdk_subsystem_depend *
subsystem_get_first_depend(void)
{
	return TAILQ_FIRST(&g_subsystems_deps);
}

struct spdk_subsystem_depend *
subsystem_get_next_depend(struct spdk_subsystem_depend *cur_depend)
{
	return TAILQ_NEXT(cur_depend, tailq);
}

static void
subsystem_sort(void)
{
	bool has_dependency, all_dependencies_met;
	struct spdk_subsystem *subsystem, *subsystem_tmp;
	struct spdk_subsystem_depend *subsystem_dep;
	struct spdk_subsystem_list sorted_list;

	TAILQ_INIT(&sorted_list);
	/* We will move subsystems from the original g_subsystems TAILQ to the temporary
	 * sorted_list one at a time. We can only move a subsystem if it either (a) has no
	 * dependencies, or (b) all of its dependencies have already been moved to the
	 * sorted_list.
	 *
	 * Once all of the subsystems have been moved to the temporary list, we will move
	 * the list as-is back to the original g_subsystems TAILQ - they will now be sorted
	 * in the order which they must be initialized.
	 */
	while (!TAILQ_EMPTY(&g_subsystems)) {
		TAILQ_FOREACH_SAFE(subsystem, &g_subsystems, tailq, subsystem_tmp) {
			has_dependency = false;
			all_dependencies_met = true;
			TAILQ_FOREACH(subsystem_dep, &g_subsystems_deps, tailq) {
				if (strcmp(subsystem->name, subsystem_dep->name) == 0) {
					has_dependency = true;
					if (!_subsystem_find(&sorted_list, subsystem_dep->depends_on)) {
						/* We found a dependency that isn't in the sorted_list yet.
						 * Clear the flag and break from the inner loop, we know
						 * we can't move this subsystem to the sorted_list yet.
						 */
						all_dependencies_met = false;
						break;
					}
				}
			}

			if (!has_dependency || all_dependencies_met) {
				TAILQ_REMOVE(&g_subsystems, subsystem, tailq);
				TAILQ_INSERT_TAIL(&sorted_list, subsystem, tailq);
			}
		}
	}

	TAILQ_SWAP(&sorted_list, &g_subsystems, spdk_subsystem, tailq);
}

void
spdk_subsystem_init_next(int rc)
{
	assert(spdk_thread_is_app_thread(NULL));

	/* The initialization is interrupted by the spdk_subsystem_fini, so just return */
	if (g_subsystems_init_interrupted) {
		return;
	}

	if (rc) {
		SPDK_ERRLOG("Init subsystem %s failed\n", g_next_subsystem->name);
		g_subsystem_start_fn(rc, g_subsystem_start_arg);
		return;
	}

	if (!g_next_subsystem) {
		g_next_subsystem = TAILQ_FIRST(&g_subsystems);
	} else {
		g_next_subsystem = TAILQ_NEXT(g_next_subsystem, tailq);
	}

	if (!g_next_subsystem) {
		g_subsystems_initialized = true;
		g_subsystem_start_fn(0, g_subsystem_start_arg);
		return;
	}

	if (g_next_subsystem->init) {
		g_next_subsystem->init();
	} else {
		spdk_subsystem_init_next(0);
	}
}
/* 初始化所有子系统 */
void
spdk_subsystem_init(spdk_subsystem_init_fn cb_fn, void *cb_arg)
{
	struct spdk_subsystem_depend *dep;

	assert(spdk_thread_is_app_thread(NULL));

	g_subsystem_start_fn = cb_fn;
	g_subsystem_start_arg = cb_arg;

	/* Verify that all dependency name and depends_on subsystems are registered */
	TAILQ_FOREACH(dep, &g_subsystems_deps, tailq) {
		if (!subsystem_find(dep->name)) {
			SPDK_ERRLOG("subsystem %s is missing\n", dep->name);
			g_subsystem_start_fn(-1, g_subsystem_start_arg);
			return;
		}
		if (!subsystem_find(dep->depends_on)) {
			SPDK_ERRLOG("subsystem %s dependency %s is missing\n",
				    dep->name, dep->depends_on);
			g_subsystem_start_fn(-1, g_subsystem_start_arg);
			return;
		}
	}

	subsystem_sort(); // 拓扑排序

	spdk_subsystem_init_next(0);
}

static void
subsystem_fini_next(void *arg1)
{
	assert(g_fini_thread == spdk_get_thread());

	if (!g_next_subsystem) {
		/* If the initialized flag is false, then we've failed to initialize
		 * the very first subsystem and no de-init is needed
		 */
		if (g_subsystems_initialized) {
			g_next_subsystem = TAILQ_LAST(&g_subsystems, spdk_subsystem_list);
		}
	} else {
		if (g_subsystems_initialized || g_subsystems_init_interrupted) {
			g_next_subsystem = TAILQ_PREV(g_next_subsystem, spdk_subsystem_list, tailq);
		} else {
			g_subsystems_init_interrupted = true;
		}
	}

	while (g_next_subsystem) {
		if (g_next_subsystem->fini) {
			g_next_subsystem->fini();
			return;
		}
		g_next_subsystem = TAILQ_PREV(g_next_subsystem, spdk_subsystem_list, tailq);
	}

	g_subsystem_stop_fn(g_subsystem_stop_arg);
	return;
}

void
spdk_subsystem_fini_next(void)
{
	if (g_fini_thread != spdk_get_thread()) {
		spdk_thread_send_msg(g_fini_thread, subsystem_fini_next, NULL);
	} else {
		subsystem_fini_next(NULL);
	}
}

void
spdk_subsystem_fini(spdk_msg_fn cb_fn, void *cb_arg)
{
	g_subsystem_stop_fn = cb_fn;
	g_subsystem_stop_arg = cb_arg;

	g_fini_thread = spdk_get_thread();

	spdk_subsystem_fini_next();
}

void
subsystem_config_json(struct spdk_json_write_ctx *w, struct spdk_subsystem *subsystem)
{
	if (subsystem && subsystem->write_config_json) {
		subsystem->write_config_json(w);
	} else {
		spdk_json_write_null(w);
	}
}
