#ifndef _RPCOOL_STATS_H
#define _RPCOOL_STATS_H

#include <linux/atomic.h>
#include <linux/ktime.h>
#include <linux/printk.h>

typedef struct syscall_time_stats {
	char *name;
	atomic_long_t count;
	atomic_long_t total_duration;
} syscall_time_stats_t;

static inline void init_syscall_time_stats(syscall_time_stats_t *stats,
					   const char *name)
{
	stats->name = name;
	atomic_long_set(&stats->count, 0);
	atomic_long_set(&stats->total_duration, 0);
}

ktime_t start_time_measure(void)
{
	return ktime_get_ns();
}

void end_time_measure(ktime_t start_time, syscall_time_stats_t *stats,
		      int frequency)
{
	ktime_t end_time = ktime_get_ns();
	ktime_t duration = end_time - start_time;
	long long temp_total_duration;
	int temp_count;

	temp_total_duration =
		atomic_long_add_return(duration, &stats->total_duration);
	temp_count = atomic_long_inc_return(&stats->count);

	if (temp_total_duration < 0 || temp_total_duration > LONG_MAX) {
		pr_err("[rpcool] Overflow detected in timer stats total_duration for %s\n",
		       stats->name);
		atomic_long_set(&stats->total_duration, 0); // Reset on overflow
	}

	if (temp_count < 0 || temp_count > LONG_MAX) {
		pr_err("[rpcool] Overflow detected in timer stats count for %s\n",
		       stats->name);
		atomic_long_set(&stats->count, 0); // Reset on overflow
	}

	if (temp_count % frequency == 0) {
		long long time = temp_total_duration / temp_count;
		if (time < 5000)
			printk("[rpcool] %s: Average execution time after %d calls: %lld ns\n",
			       stats->name, frequency, time);
		else
			printk("[rpcool] %s: Average execution time after %d calls: %lld micros\n",
			       stats->name, frequency, time / 1000);
		atomic_long_set(&stats->count, 0);
		atomic_long_set(&stats->total_duration, 0);
	}
}

#endif