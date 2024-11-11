#include "spdk/stdinc.h"
#include "spdk/likely.h"
#include "spdk/event.h"
#include "spdk/log.h"
#include "spdk/env.h"

#include "spdk/thread.h"
#include "spdk_internal/event.h"
#include "spdk/scheduler.h"
#include "spdk_internal/usdt.h"

static uint32_t g_main_lcore;

struct core_stats {
	uint64_t busy;
	uint64_t idle;
	uint32_t thread_count;
};

struct AIControlState{
    bool isAIControl; // 是否启用AI控制
    bool interruptMode; // 是否中断模式
    bool intpollMode; // 是否中断轮询模式
    bool ssdPowerMode; // 是否SSD省电模式
    uint32_t maxActivatedCore; // 激活的核心数上限
    uint32_t minActivatedCore; // 激活的核心数下限，最少激活的核心数
    uint32_t maxCoreFreq; // 核心最大频率
    uint32_t minCoreFreq; // 核心最小频率
};

struct AIControlState g_aiControlState;

static bool* idleCore; // 激活的核心位图

static struct spdk_cpuset* int_core_map; // 中断核心位图

static struct core_stats *g_cores;

uint8_t g_scheduler_load_limit = 20;
uint8_t g_scheduler_core_limit = 80;
uint8_t g_scheduler_core_busy = 95;

static uint8_t
_busy_pct(uint64_t busy, uint64_t idle)
{
	if ((busy + idle) == 0) {
		return 0;
	}

	return busy * 100 / (busy + idle);
}

static uint8_t
_get_thread_load(struct spdk_scheduler_thread_info *thread_info)
{
	uint64_t busy, idle;

	busy = thread_info->current_stats.busy_tsc;
	idle = thread_info->current_stats.idle_tsc;

	/* return percentage of time thread was busy */
	return _busy_pct(busy, idle);
}

typedef void (*_foreach_fn)(struct spdk_scheduler_thread_info *thread_info);

static void
_foreach_thread(struct spdk_scheduler_core_info *cores_info, _foreach_fn fn)
{
	struct spdk_scheduler_core_info *core;
	uint32_t i, j;

	SPDK_ENV_FOREACH_CORE(i) {
		core = &cores_info[i];
		for (j = 0; j < core->threads_count; j++) {
			fn(&core->thread_infos[j]);
		}
	}
}

static void
prepare_to_sleep(uint32_t core)
{
	struct spdk_governor *governor = spdk_governor_get();
	int rc;

	if (governor == NULL) {
		return;
	}

	rc = governor->set_core_freq_min(core);
	if (rc < 0) {
		SPDK_ERRLOG("could not set_core_freq_min(%d)\n", core);
	}
}

static inline void
prepare_to_sleep_ai(uint32_t core)
{
	prepare_to_sleep(core);
}

static void
prepare_to_wake(uint32_t core)
{
	struct spdk_governor *governor = spdk_governor_get();
	int rc;

	if (governor == NULL) {
		return;
	}

	rc = governor->set_core_freq_max(core);
	if (rc < 0) {
		SPDK_ERRLOG("could not set_core_freq_max(%d)\n", core);
	}
}

static inline void
prepare_to_wake_ai(uint32_t core)
{
	prepare_to_wake(core);
}

static inline void
change_core_freq(uint32_t core)
{
    struct spdk_governor *governor = spdk_governor_get();
    uint32_t freq = 0;
    int rc;

    if (governor == NULL) {
        return;
    }

    freq = governor->get_core_curr_freq(core);
    if(freq < g_aiControlState.maxCoreFreq){
        rc = governor->core_freq_up(core);
    } else if(freq > g_aiControlState.minCoreFreq){
        rc = governor->core_freq_down(core);
    } else {
        SPDK_NOTICELOG("Core %d is already at the target frequency\n", core);
    }    
    if (rc < 0) {
        SPDK_ERRLOG("could not set_core_freq(%d, %d)\n", core, freq);
    }
}
/**
 * 这个函数 _move_thread 的作用是将一个线程 thread_info 从当前核心（src 核心）移动到目标核心（dst_core 核心）。
 */
static void
_move_thread(struct spdk_scheduler_thread_info *thread_info, uint32_t dst_core)
{
	struct core_stats *dst = &g_cores[dst_core];
	struct core_stats *src = &g_cores[thread_info->lcore];
	uint64_t busy_tsc = thread_info->current_stats.busy_tsc;
	uint8_t busy_pct = _busy_pct(src->busy, src->idle);
	uint64_t tsc;

	SPDK_DTRACE_PROBE2(dynsched_move, thread_info, dst_core);

	if (src == dst) {
		/* Don't modify stats if thread is already on that core. */
		return;
	}

	dst->busy += spdk_min(UINT64_MAX - dst->busy, busy_tsc);
	dst->idle -= spdk_min(dst->idle, busy_tsc);
	dst->thread_count++;

	/* Adjust busy/idle from core as if thread was not present on it.
	 * Core load will reflect the sum of all remaining threads on it. */
	src->busy -= spdk_min(src->busy, busy_tsc);
	src->idle += spdk_min(UINT64_MAX - src->idle, busy_tsc);

	if (busy_pct >= g_scheduler_core_busy &&
	    _busy_pct(src->busy, src->idle) < g_scheduler_core_limit) {
		/* This core was so busy that we cannot assume all of busy_tsc
		 * consumed by the moved thread will now be idle_tsc - it's
		 * very possible the remaining threads will use these cycles
		 * as busy_tsc.
		 *
		 * So make sure we don't drop the updated estimate below
		 * g_scheduler_core_limit, so that other cores can't
		 * move threads to this core during this scheduling
		 * period.
		 */
		tsc = src->busy + src->idle;
		src->busy = tsc * g_scheduler_core_limit / 100;
		src->idle = tsc - src->busy;
	}
	assert(src->thread_count > 0);
	src->thread_count--;

	thread_info->lcore = dst_core;
}

static bool
_is_core_at_limit(uint32_t core_id)
{
	struct core_stats *core = &g_cores[core_id];
	uint64_t busy, idle;

	/* Core with no or single thread cannot be over the limit. */
	if (core->thread_count <= 1) {
		return false;
	}

	busy = core->busy;
	idle = core->idle;

	/* No work was done, exit before possible division by 0. */
	if (busy == 0) {
		return false;
	}

	/* Work done was less than the limit */
	if (_busy_pct(busy, idle) < g_scheduler_core_limit) {
		return false;
	}

	return true;
}

static bool
_can_core_fit_thread(struct spdk_scheduler_thread_info *thread_info, uint32_t dst_core)
{
	struct core_stats *dst = &g_cores[dst_core];
	uint64_t new_busy_tsc, new_idle_tsc;

	/* Thread can always fit on the core it's currently on. */
	if (thread_info->lcore == dst_core) {
		return true;
	}

	/* Reactors in interrupt mode do not update stats,
	 * a thread can always fit into reactor in interrupt mode. */
	if (dst->busy + dst->idle == 0) {
		return true;
	}

	/* Core has no threads. */
	if (dst->thread_count == 0) {
		return true;
	}

	/* Core doesn't have enough idle_tsc to take this thread. */
	if (dst->idle < thread_info->current_stats.busy_tsc) {
		return false;
	}

	new_busy_tsc = dst->busy + thread_info->current_stats.busy_tsc;
	new_idle_tsc = dst->idle - thread_info->current_stats.busy_tsc;

	/* Core cannot fit this thread if it would put it over the
	 * g_scheduler_core_limit. */
	return _busy_pct(new_busy_tsc, new_idle_tsc) < g_scheduler_core_limit;
}

static bool
_can_core_fit_thread_ai(struct spdk_scheduler_thread_info *thread_info, uint32_t dst_core)
{
	struct core_stats *dst = &g_cores[dst_core];
	uint64_t new_busy_tsc, new_idle_tsc;

	/* Thread can always fit on the core it's currently on. */
	if (thread_info->lcore == dst_core) {
		return true;
	}

	/* Core doesn't have enough idle_tsc to take this thread. */
	if (dst->idle < thread_info->current_stats.busy_tsc) {
		return false;
	}

	new_busy_tsc = dst->busy + thread_info->current_stats.busy_tsc;
	new_idle_tsc = dst->idle - thread_info->current_stats.busy_tsc;

	/* Core cannot fit this thread if it would put it over the
	 * g_scheduler_core_limit. */
	return _busy_pct(new_busy_tsc, new_idle_tsc) < g_scheduler_core_limit;
}

static uint32_t
_find_optimal_core(struct spdk_scheduler_thread_info *thread_info)
{
	uint32_t i;
	uint32_t current_lcore = thread_info->lcore; // 当前核心
	uint32_t least_busy_lcore = thread_info->lcore; // 最不忙的核心
	struct spdk_thread *thread;
	struct spdk_cpuset *cpumask;
	bool core_at_limit = _is_core_at_limit(current_lcore); // 当前核心是否达到负载上限

	thread = spdk_thread_get_by_id(thread_info->thread_id); // 根据线程 ID 获取线程
	if (thread == NULL) {
		return current_lcore;
	}
	cpumask = spdk_thread_get_cpumask(thread); // 获取线程的 cpumask

	/* Find a core that can fit the thread. */
	SPDK_ENV_FOREACH_CORE(i) { // 遍历所有核心
		/* Ignore cores outside cpumask. */
		if (!spdk_cpuset_get_cpu(cpumask, i)) { // 如果 i 不在 cpumask 中，跳过
			continue;
		}

		/* Search for least busy core. */
		if (g_cores[i].busy < g_cores[least_busy_lcore].busy) { // 如果 i 核心的忙时间小于 least_busy_lcore 核心的忙时间
			least_busy_lcore = i; // 更新 least_busy_lcore
		}

		/* Skip cores that cannot fit the thread and current one. */
		if (!_can_core_fit_thread(thread_info, i) || i == current_lcore) { // 如果 i 核心不能容纳线程，或者 i 核心等于当前核心
			continue;
		}
		if (i == g_main_lcore) { // 如果 i 核心是主核心
			/* First consider g_main_lcore, consolidate threads on main lcore if possible. */
			return i;
		} else if (i < current_lcore && current_lcore != g_main_lcore) { // 如果 i 核心的 ID 小于当前核心的 ID，且当前核心不是主核心
			/* Lower core id was found, move to consolidate threads on lowest core ids. */
			return i;
		} else if (core_at_limit) { // 如果当前核心已经达到负载上限，任何核心都比当前核心好
			/* When core is over the limit, any core id is better than current one. */
			return i;
		}
	}

	/* For cores over the limit, place the thread on least busy core
	 * to balance threads. */ /* 如果当前核心超出负载限制，并且遍历过程没有找到更好的核心，返回least_busy_lcore，尽量平衡负载 */
	if (core_at_limit) {
		return least_busy_lcore;
	}

	/* If no better core is found, remain on the same one. */
	return current_lcore;
}

static uint32_t
_find_optimal_core_ai(struct spdk_scheduler_thread_info *thread_info, struct spdk_cpuset *temp_cpumask, struct spdk_cpuset *limited_cpumask)
{
	uint32_t i;
	uint32_t current_lcore = thread_info->lcore; // 当前核心
	uint32_t least_busy_lcore = thread_info->lcore; // 最不忙的核心
	struct spdk_thread *thread;
	struct spdk_cpuset *cpumask;
	struct spdk_cpuset *temp_cpumask;
	bool core_at_limit = _is_core_at_limit(current_lcore); // 当前核心是否达到负载上限

	thread = spdk_thread_get_by_id(thread_info->thread_id); // 根据线程 ID 获取线程
	if (thread == NULL) {
		return current_lcore;
	}
	cpumask = spdk_thread_get_cpumask(thread); // 获取线程的 cpumask
	spdk_cpuset_copy(temp_cpumask, cpumask); // 复制 cpumask
	spdk_cpuset_and(temp_cpumask, limited_cpumask); // cpumask 与 limited_cpumask 求交集

	/* Find a core that can fit the thread. */
	SPDK_ENV_FOREACH_CORE(i) { // 遍历所有核心
		/* Ignore cores outside cpumask. */
		if (!spdk_cpuset_get_cpu(temp_cpumask, i) || g_cores[i].thread_count == 0 || g_cores[i].busy + g_cores[i].idle == 0) { // 如果 i 不在 cpumask 中，跳过
			continue;
		}

		/* Search for least busy core. */
		if (g_cores[i].busy < g_cores[least_busy_lcore].busy) { // 如果 i 核心的忙时间小于 least_busy_lcore 核心的忙时间
			least_busy_lcore = i; // 更新 least_busy_lcore
		}

		/* Skip cores that cannot fit the thread and current one. */
		if (!_can_core_fit_thread_ai(thread_info, i) || i == current_lcore) { // 如果 i 核心不能容纳线程，或者 i 核心等于当前核心
			continue;
		}
		if (i == g_main_lcore) { // 如果 i 核心是主核心
			/* First consider g_main_lcore, consolidate threads on main lcore if possible. */
			return i;
		} else if (i < current_lcore && current_lcore != g_main_lcore) { // 如果 i 核心的 ID 小于当前核心的 ID，且当前核心不是主核心
			/* Lower core id was found, move to consolidate threads on lowest core ids. */
			return i;
		} else if (core_at_limit) { // 如果当前核心已经达到负载上限，任何核心都比当前核心好
			/* When core is over the limit, any core id is better than current one. */
			return i;
		}
	}

	/* For cores over the limit, place the thread on least busy core
	 * to balance threads. */ /* 如果当前核心超出负载限制，并且遍历过程没有找到更好的核心，返回least_busy_lcore，尽量平衡负载 */
	if (core_at_limit) {
		return least_busy_lcore;
	}

	/* If no better core is found, remain on the same one. */
	return current_lcore;
}

static int
init(void)
{
	g_main_lcore = spdk_env_get_current_core();

	if (spdk_governor_set("dpdk_governor") != 0) {
		SPDK_NOTICELOG("Unable to initialize dpdk governor\n");
	}

	g_cores = calloc(spdk_env_get_last_core() + 1, sizeof(struct core_stats));
	if (g_cores == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for dynamic scheduler core stats.\n");
		return -ENOMEM;
	}

    idleCore = calloc(spdk_env_get_last_core() + 1, sizeof(bool));
    if(idleCore == NULL){
        SPDK_ERRLOG("Failed to allocate memory for activated core map.\n");
        return -ENOMEM;
    }

	int_core_map = spdk_cpuset_alloc();
	if (int_core_map == NULL) {
		SPDK_ERRLOG("Failed to allocate memory for interrupt core map.\n");
		return -ENOMEM;
	}

	g_aiControlState.isAIControl = false;
	g_aiControlState.interruptMode = false;
	g_aiControlState.intpollMode = false;
	g_aiControlState.ssdPowerMode = false;
	g_aiControlState.maxActivatedCore = 0;
	g_aiControlState.minActivatedCore = 0;
	g_aiControlState.maxCoreFreq = 0;
	g_aiControlState.minCoreFreq = 0;

	return 0;
}

static void
deinit(void)
{
	free(g_cores);
	g_cores = NULL;
    free(idleCore);
    idleCore = NULL;
	spdk_governor_set(NULL);
	spdk_cpuset_free(int_core_map);
	int_core_map = NULL;
}

static void
_balance_idle(struct spdk_scheduler_thread_info *thread_info)
{
	if (_get_thread_load(thread_info) >= g_scheduler_load_limit) {
		return;
	}
	/* This thread is idle, move it to the main core. */
	_move_thread(thread_info, g_main_lcore);
}

static void
_balance_idle_ai(struct spdk_scheduler_thread_info *thread_info)
{
	if (_get_thread_load(thread_info) >= g_scheduler_load_limit) {
		return;
	}
	/* This thread is idle, move it to the main core. */
    idleCore[thread_info->lcore] = true;
	_move_thread(thread_info, g_main_lcore);
}

static void
_balance_active(struct spdk_scheduler_thread_info *thread_info)
{
	uint32_t target_lcore;

	if (_get_thread_load(thread_info) < g_scheduler_load_limit) {
		return;
	}

	/* This thread is active. */
	target_lcore = _find_optimal_core(thread_info);
	_move_thread(thread_info, target_lcore);
}


static int cmp(const void *a, const void *b){
    uint32_t *x = (uint32_t *)a;
    uint32_t *y = (uint32_t *)b;
    return g_cores[*x].thread_count - g_cores[*y].thread_count;
}

static inline void thread_reschedule(struct spdk_scheduler_core_info *cores_info){
    if(g_aiControlState.isAIControl){
        uint32_t coreNum = spdk_env_get_last_core() + 1;
        uint32_t activeCoreNum = 0;
        memset(idleCore, 0, sizeof(bool) * coreNum); // 将激活的核心位图清零
        _foreach_thread(cores_info, _balance_idle_ai); // 遍历所有线程，将空闲线程移动到主核心
        bool find_idle = false;
		for(uint32_t i = 0; i < coreNum; i++){
            if(!idleCore[i]){
                activeCoreNum++;
            }
			else{
				if(!find_idle){
					spdk_cpuset_set_cpu(int_core_map, i, true);
					find_idle = true;
				}
			}
        }
		find_idle = spdk_cpuset_count(int_core_map) != 0;
        if(spdk_get_int_thread() == NULL && g_aiControlState.interruptMode){
            if(find_idle)
				spdk_int_thread_create("intthread", int_core_map);
			else
			{
				uint32_t i = 0;
				struct spdk_cpuset *temp_cpumask;
				SPDK_ENV_FOREACH_CORE(i) {
					if(i != g_main_lcore){
						spdk_cpuset_set_cpu(int_core_map, i, true);
						break;
					}
				}
				temp_cpumask = spdk_cpuset_alloc(); // 分配一个 cpumask
				if (temp_cpumask == NULL) {
					SPDK_ERRLOG("Failed to allocate memory for temp cpumask.\n");
					_foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
					return;
				}
				struct spdk_scheduler_core_info *core = &cores_info[i];
				for(uint32_t j = 0; j < core->threads_count; j++){
                    // 将线程移动到其他核心，空出位置
                    struct spdk_scheduler_thread_info *thread_info = &core->thread_infos[j];
                    uint32_t target_lcore = _find_optimal_core_ai(thread_info, temp_cpumask, int_core_map);
                    _move_thread(thread_info, target_lcore);
                }
				spdk_int_thread_create("intthread", int_core_map);
				spdk_cpuset_free(temp_cpumask); // 释放 cpumask
			}
        }
		if(spdk_get_int_poll_thread() == NULL && g_aiControlState.intpollMode){
			if(find_idle)
				spdk_int_poll_thread_create("intpollthread", int_core_map);
			else
			{
				uint32_t i = 0;
				struct spdk_cpuset *temp_cpumask;
				SPDK_ENV_FOREACH_CORE(i) {
					if(i != g_main_lcore){
						spdk_cpuset_set_cpu(int_core_map, i, true);
						break;
					}
				}
				temp_cpumask = spdk_cpuset_alloc(); // 分配一个 cpumask
				if (temp_cpumask == NULL) {
					SPDK_ERRLOG("Failed to allocate memory for temp cpumask.\n");
					_foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
					return;
				}
				struct spdk_scheduler_core_info *core = &cores_info[i];
				for(uint32_t j = 0; j < core->threads_count; j++){
                    // 将线程移动到其他核心，空出位置
                    struct spdk_scheduler_thread_info *thread_info = &core->thread_infos[j];
                    uint32_t target_lcore = _find_optimal_core_ai(thread_info, temp_cpumask, int_core_map);
                    _move_thread(thread_info, target_lcore);
                }
				spdk_int_poll_thread_create("intpollthread", int_core_map);
				spdk_cpuset_free(temp_cpumask); // 释放 cpumask
			}
		}

        if(activeCoreNum > g_aiControlState.maxActivatedCore){
            uint32_t i = 0;
            uint32_t* core_id = calloc(activeCoreNum, sizeof(uint32_t));
			struct spdk_cpuset *temp_cpumask, *limited_cpumask;
            if(core_id == NULL){
                SPDK_ERRLOG("Failed to allocate memory for core id array.\n");
                _foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
                return;
            }
            uint32_t k = 0;
            SPDK_ENV_FOREACH_CORE(i){
                if(!idleCore[i]){
                    core_id[k++] = i;
                }
            }
            qsort(core_id, coreNum, sizeof(uint32_t), cmp);
			temp_cpumask = spdk_cpuset_alloc(); // 分配一个 cpumask
			if (temp_cpumask == NULL) {
				SPDK_ERRLOG("Failed to allocate memory for temp cpumask.\n");
				_foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
				return;
			}
			limited_cpumask = spdk_cpuset_alloc(); // 分配一个 cpumask
			if (limited_cpumask == NULL) {
				SPDK_ERRLOG("Failed to allocate memory for limited cpumask.\n");
				spdk_cpuset_free(temp_cpumask); // 释放 cpumask
				_foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
				return;
			}
            for(k = 0; k < activeCoreNum - g_aiControlState.maxActivatedCore; k++){
				if(core_id[k] == g_main_lcore){
					continue;
				}
                struct spdk_scheduler_core_info *core = &cores_info[core_id[k]];
				spdk_cpuset_set_cpu(limited_cpumask, core_id[k], true);
                for(uint32_t j = 0; j < core->threads_count; j++){
                    // 将线程移动到其他核心，空出位置
                    struct spdk_scheduler_thread_info *thread_info = &core->thread_infos[j];
                    uint32_t target_lcore = _find_optimal_core_ai(thread_info, temp_cpumask, limited_cpumask);
                    _move_thread(thread_info, target_lcore);
                }
            }
			spdk_cpuset_free(temp_cpumask); // 释放 cpumask
			spdk_cpuset_free(limited_cpumask);
        }
        else if(activeCoreNum < g_aiControlState.minActivatedCore){
            _foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
        }
    }
    else{
        /* Distribute threads in two passes, to make sure updated core stats are considered on each pass.
        * 1) Move all idle threads to main core. */
        _foreach_thread(cores_info, _balance_idle); // 遍历所有线程，将空闲线程移动到主核心
        /* 2) Distribute active threads across all cores. */
        _foreach_thread(cores_info, _balance_active); // 遍历所有线程，将活跃线程移动到最佳核心 (负载均衡)
    }
}

static inline void core_freq_control(struct spdk_scheduler_core_info *cores_info, struct core_stats *main_core){
    struct spdk_reactor *reactor;
    struct spdk_scheduler_core_info *core;
    uint32_t i;
    bool busy_threads_present = false;
    struct spdk_governor *governor;
    int rc = 0;
    
    if(g_aiControlState.isAIControl){
        /* Switch unused cores to interrupt mode and switch cores to polled mode
        * if they will be used after rebalancing */
        SPDK_ENV_FOREACH_CORE(i) { // 遍历所有核心
            reactor = spdk_reactor_get(i);
            assert(reactor != NULL);

            core = &cores_info[i];
            /* We can switch mode only if reactor already does not have any threads */
            if (g_cores[i].thread_count == 0 && TAILQ_EMPTY(&reactor->threads)) {
                core->interrupt_mode = true; // 如果该核心没有线程，将其设置为中断模式
                prepare_to_sleep(i); // 准备进入睡眠状态
            } else if (g_cores[i].thread_count != 0) { // 如果该核心有线程
                core->interrupt_mode = false; // 将其设置为非中断模式
                if (i != g_main_lcore) {
                    /* If a thread is present on non g_main_lcore,
                    * it has to be busy. */
                    busy_threads_present = true; // 如果该核心有线程，将 busy_threads_present 设置为 true
                    prepare_to_wake(i); // 准备唤醒该核心
                }
            } else if (i != g_main_lcore){
                change_core_freq(i);
            }
        }

        governor = spdk_governor_get(); // 获取调频管理器
        if (governor == NULL) {
            return;
        }
      
        uint32_t current_freq = governor->get_core_curr_freq(g_main_lcore); // 获取主核心的当前频率
        /* Change main core frequency if needed */
        if (busy_threads_present) { // 如果有线程
            if(current_freq < g_aiControlState.maxCoreFreq){
                rc = governor->set_core_freq_max(g_main_lcore); // 将主核心的频率设置为最大
                if (rc < 0) {
                    SPDK_ERRLOG("setting default frequency for core %u failed\n", g_main_lcore);
                }
            }
            else if(current_freq > g_aiControlState.maxCoreFreq){
                rc = governor->core_freq_down(g_main_lcore); // 将主核心的频率设置为最小
                if (rc < 0) {
                    SPDK_ERRLOG("setting default frequency for core %u failed\n", g_main_lcore);
                }
            }
        } else if (main_core->busy > main_core->idle && current_freq < g_aiControlState.maxCoreFreq) { // 如果主核心的忙时间大于空闲时间
            rc = governor->core_freq_up(g_main_lcore); // 将主核心的频率提高
            if (rc < 0) {
                SPDK_ERRLOG("increasing frequency for core %u failed\n", g_main_lcore);
            }
        } else if (main_core->busy > main_core->idle && current_freq == g_aiControlState.minCoreFreq) { // 如果主核心的忙时间大于空闲时间
            // 什么都不做
        } else {
            rc = governor->core_freq_down(g_main_lcore); // 将主核心的频率降低
            if (rc < 0) {
                SPDK_ERRLOG("lowering frequency for core %u failed\n", g_main_lcore);
            }
        }
    }
    else{
        /* Switch unused cores to interrupt mode and switch cores to polled mode
        * if they will be used after rebalancing */
        SPDK_ENV_FOREACH_CORE(i) { // 遍历所有核心
            reactor = spdk_reactor_get(i);
            assert(reactor != NULL);

            core = &cores_info[i];
            /* We can switch mode only if reactor already does not have any threads */
            if (g_cores[i].thread_count == 0 && TAILQ_EMPTY(&reactor->threads)) {
                core->interrupt_mode = true; // 如果该核心没有线程，将其设置为中断模式
                prepare_to_sleep(i); // 准备进入睡眠状态
            } else if (g_cores[i].thread_count != 0) { // 如果该核心有线程
                core->interrupt_mode = false; // 将其设置为非中断模式
                if (i != g_main_lcore) {
                    /* If a thread is present on non g_main_lcore,
                    * it has to be busy. */
                    busy_threads_present = true; // 如果该核心有线程，将 busy_threads_present 设置为 true
                    prepare_to_wake(i); // 准备唤醒该核心
                }
            }
        }

        governor = spdk_governor_get(); // 获取调频管理器
        if (governor == NULL) {
            return;
        }

        /* Change main core frequency if needed */
        if (busy_threads_present) { // 如果有线程
            rc = governor->set_core_freq_max(g_main_lcore); // 将主核心的频率设置为最大
            if (rc < 0) {
                SPDK_ERRLOG("setting default frequency for core %u failed\n", g_main_lcore);
            }
        } else if (main_core->busy > main_core->idle) { // 如果主核心的忙时间大于空闲时间
            rc = governor->core_freq_up(g_main_lcore); // 将主核心的频率提高
            if (rc < 0) {
                SPDK_ERRLOG("increasing frequency for core %u failed\n", g_main_lcore);
            }
        } else {
            rc = governor->core_freq_down(g_main_lcore); // 将主核心的频率降低
            if (rc < 0) {
                SPDK_ERRLOG("lowering frequency for core %u failed\n", g_main_lcore);
            }
        }
    }
}


static void
balance(struct spdk_scheduler_core_info *cores_info, uint32_t cores_count)
{
	struct spdk_scheduler_core_info *core;
	struct core_stats *main_core;
	uint32_t i;
	bool busy_threads_present = false;

	SPDK_DTRACE_PROBE1(dynsched_balance, cores_count);

	SPDK_ENV_FOREACH_CORE(i) {
		g_cores[i].thread_count = cores_info[i].threads_count;
		g_cores[i].busy = cores_info[i].current_busy_tsc;
		g_cores[i].idle = cores_info[i].current_idle_tsc;
		SPDK_DTRACE_PROBE2(dynsched_core_info, i, &cores_info[i]);
	} // 遍历所有核心，将核心的线程数、忙闲时间等信息保存到 g_cores 数组中
	main_core = &g_cores[g_main_lcore];

	thread_reschedule(cores_info); // 重新调度线程

	core_freq_control(cores_info, main_core); // 核心频率控制
}

struct json_scheduler_opts {
	uint8_t load_limit;
	uint8_t core_limit;
	uint8_t core_busy;
};

static const struct spdk_json_object_decoder sched_decoders[] = {
	{"load_limit", offsetof(struct json_scheduler_opts, load_limit), spdk_json_decode_uint8, true},
	{"core_limit", offsetof(struct json_scheduler_opts, core_limit), spdk_json_decode_uint8, true},
	{"core_busy", offsetof(struct json_scheduler_opts, core_busy), spdk_json_decode_uint8, true},
};

struct json_ai_opts {
    uint8_t isAIControl;
    uint8_t interruptMode;
    uint8_t intpollMode;
    uint8_t ssdPowerMode;
    uint32_t maxActivatedCore;
    uint32_t minActivatedCore;
    uint32_t maxCoreFreq;
    uint32_t minCoreFreq;
};

static const struct spdk_json_object_decoder ai_decoders[] = {
    {"isAIControl", offsetof(struct json_ai_opts, isAIControl), spdk_json_decode_uint8, true},
    {"interruptMode", offsetof(struct json_ai_opts, interruptMode), spdk_json_decode_uint8, true},
    {"intpollMode", offsetof(struct json_ai_opts, intpollMode), spdk_json_decode_uint8, true},
    {"ssdPowerMode", offsetof(struct json_ai_opts, ssdPowerMode), spdk_json_decode_uint8, true},
    {"maxActivatedCore", offsetof(struct json_ai_opts, maxActivatedCore), spdk_json_decode_uint32, true},
    {"minActivatedCore", offsetof(struct json_ai_opts, minActivatedCore), spdk_json_decode_uint32, true},
    {"maxCoreFreq", offsetof(struct json_ai_opts, maxCoreFreq), spdk_json_decode_uint32, true},
    {"minCoreFreq", offsetof(struct json_ai_opts, minCoreFreq), spdk_json_decode_uint32, true},
};

static int
set_opts(const struct spdk_json_val *opts)
{
	struct json_scheduler_opts scheduler_opts;

	scheduler_opts.load_limit = g_scheduler_load_limit;
	scheduler_opts.core_limit = g_scheduler_core_limit;
	scheduler_opts.core_busy = g_scheduler_core_busy;

	if (opts != NULL) {
		if (spdk_json_decode_object_relaxed(opts, sched_decoders,
						    SPDK_COUNTOF(sched_decoders), &scheduler_opts)) {
			SPDK_ERRLOG("Decoding scheduler opts JSON failed\n");
			return -1;
		}
	}

	SPDK_NOTICELOG("Setting scheduler load limit to %d\n", scheduler_opts.load_limit);
	g_scheduler_load_limit = scheduler_opts.load_limit;
	SPDK_NOTICELOG("Setting scheduler core limit to %d\n", scheduler_opts.core_limit);
	g_scheduler_core_limit = scheduler_opts.core_limit;
	SPDK_NOTICELOG("Setting scheduler core busy to %d\n", scheduler_opts.core_busy);
	g_scheduler_core_busy = scheduler_opts.core_busy;

	return 0;
}

static int
set_ai_opts(const struct spdk_json_val *opts)
{
	struct json_ai_opts ai_opts;

    ai_opts.isAIControl = g_aiControlState.isAIControl;
    ai_opts.interruptMode = g_aiControlState.interruptMode;
    ai_opts.intpollMode = g_aiControlState.intpollMode;
    ai_opts.ssdPowerMode = g_aiControlState.ssdPowerMode;
    ai_opts.maxActivatedCore = g_aiControlState.maxActivatedCore;
    ai_opts.minActivatedCore = g_aiControlState.minActivatedCore;
    ai_opts.maxCoreFreq = g_aiControlState.maxCoreFreq;
    ai_opts.minCoreFreq = g_aiControlState.minCoreFreq;

	if (opts != NULL) {
		if (spdk_json_decode_object_relaxed(opts, sched_decoders,
						    SPDK_COUNTOF(ai_decoders), &ai_opts)) {
			SPDK_ERRLOG("Decoding scheduler opts JSON failed\n");
			return -1;
		}
	}

	SPDK_NOTICELOG("Setting scheduler AI control to %d\n", ai_opts.isAIControl);
    g_aiControlState.isAIControl = ai_opts.isAIControl != 0;
    SPDK_NOTICELOG("Setting scheduler AI interrupt mode to %d\n", ai_opts.interruptMode);
    g_aiControlState.interruptMode = ai_opts.interruptMode != 0;
    SPDK_NOTICELOG("Setting scheduler AI intpoll mode to %d\n", ai_opts.intpollMode);
    g_aiControlState.intpollMode = ai_opts.intpollMode != 0;
    SPDK_NOTICELOG("Setting scheduler AI ssd power mode to %d\n", ai_opts.ssdPowerMode);
    g_aiControlState.ssdPowerMode = ai_opts.ssdPowerMode != 0;
    SPDK_NOTICELOG("Setting scheduler AI max activated core to %d\n", ai_opts.maxActivatedCore);
    g_aiControlState.maxActivatedCore = ai_opts.maxActivatedCore;
    SPDK_NOTICELOG("Setting scheduler AI min activated core to %d\n", ai_opts.minActivatedCore);
    g_aiControlState.minActivatedCore = ai_opts.minActivatedCore;
    SPDK_NOTICELOG("Setting scheduler AI max core freq to %d\n", ai_opts.maxCoreFreq);
    g_aiControlState.maxCoreFreq = ai_opts.maxCoreFreq;
    SPDK_NOTICELOG("Setting scheduler AI min core freq to %d\n", ai_opts.minCoreFreq);
    g_aiControlState.minCoreFreq = ai_opts.minCoreFreq;

	return 0;
}

static void
get_opts(struct spdk_json_write_ctx *ctx)
{
	spdk_json_write_named_uint8(ctx, "load_limit", g_scheduler_load_limit);
	spdk_json_write_named_uint8(ctx, "core_limit", g_scheduler_core_limit);
	spdk_json_write_named_uint8(ctx, "core_busy", g_scheduler_core_busy);
}

static void
get_ai_opts(struct spdk_json_write_ctx *ctx)
{
	spdk_json_write_named_uint8(ctx, "isAIControl", g_aiControlState.isAIControl);
    spdk_json_write_named_uint8(ctx, "interruptMode", g_aiControlState.interruptMode);
    spdk_json_write_named_uint8(ctx, "intpollMode", g_aiControlState.intpollMode);
    spdk_json_write_named_uint8(ctx, "ssdPowerMode", g_aiControlState.ssdPowerMode);
    spdk_json_write_named_uint32(ctx, "maxActivatedCore", g_aiControlState.maxActivatedCore);
    spdk_json_write_named_uint32(ctx, "minActivatedCore", g_aiControlState.minActivatedCore);
    spdk_json_write_named_uint32(ctx, "maxCoreFreq", g_aiControlState.maxCoreFreq);
    spdk_json_write_named_uint32(ctx, "minCoreFreq", g_aiControlState.minCoreFreq);
}

static struct spdk_scheduler efficient_scheduler = {
	.name = "efficient",
	.init = init,
	.deinit = deinit,
	.balance = balance,
	.set_opts = set_opts,
	.get_opts = get_opts,
    .set_ai_opts = set_ai_opts,
    .get_ai_opts = get_ai_opts,
};

SPDK_SCHEDULER_REGISTER(efficient_scheduler);
