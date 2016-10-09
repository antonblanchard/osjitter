/*
 * This kernel module uses static tracepoints to trace the latency
 * of interesting events such as context switches, external
 * interrupts, interrupt handlers, timer interrupts, softirqs
 * workqueues and tasklets.
 *
 * Copyright (C) 2009 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/relay.h>
#include <linux/sched.h>
#include <linux/interrupt.h>

#include <trace/events/irq.h>
#include <trace/events/timer.h>
struct pool_workqueue;
#include <trace/events/workqueue.h>
#include <trace/events/sched.h>
#ifdef CONFIG_PPC64
#include <asm/trace.h>
#endif

#include <asm/byteorder.h>

#define EVENT_CONTEXT_SWITCH		1

#define EVENT_LOST_SAMPLES		2

#define EVENT_INTERRUPT_ENTRY		10
#define EVENT_INTERRUPT_EXIT		11

#define EVENT_INTERRUPT_HANDLER_ENTRY	12
#define EVENT_INTERRUPT_HANDLER_EXIT	13

#define EVENT_TIMER_INTERRUPT_ENTRY	14
#define EVENT_TIMER_INTERRUPT_EXIT	15

#define EVENT_TIMER_ENTRY		16
#define EVENT_TIMER_EXIT		17

#define EVENT_SOFTIRQ_ENTRY		18
#define EVENT_SOFTIRQ_EXIT		19

#define EVENT_WORKQUEUE_ENTRY		20
#define EVENT_WORKQUEUE_EXIT		21

#define EVENT_TASKLET_ENTRY		22
#define EVENT_TASKLET_EXIT		23

#define EVENT_HCALL_ENTRY		24
#define EVENT_HCALL_EXIT		25

#define EVENT_OPAL_ENTRY		26
#define EVENT_OPAL_EXIT			27

#define SUBBUF_SIZE			131072
#define N_SUBBUFS			8

/*
 * Log entries consist of:
 *
 * u64 timebase (or TSC)
 *
 * u16 event
 * u16 cpu
 * u32 data
 *
 * A context switch entry also contains:
 * 
 * char comm[16]
 */
#define FORMAT_HEADER_0(TB) \
	cpu_to_be64(TB)

#define FORMAT_HEADER_1(EVENT, DATA) \
	cpu_to_be64((EVENT) | smp_processor_id() << 16 | \
	(((long long)DATA) << 32))

static struct rchan *log_chan;

static DEFINE_PER_CPU(unsigned long, lost_samples);

static void log_lost_samples(void)
{
	unsigned long long buf[2];
	unsigned long *lost = this_cpu_ptr(&lost_samples);

	if (*lost) {
		buf[0] = FORMAT_HEADER_0(get_cycles());
		buf[1] = FORMAT_HEADER_1(EVENT_LOST_SAMPLES, *lost);
		__relay_write(log_chan, buf, sizeof(buf));

		*lost = 0;
	}
}

static void lost_sample(void)
{
	unsigned long flags;

	local_irq_save(flags);
	__this_cpu_inc(lost_samples);
	local_irq_restore(flags);
}

static void logit(unsigned char event, unsigned int data)
{
	unsigned long flags;
	unsigned long long buf[2];

	/*
	 * We don't want to take any interrupts between when we sample
	 * the cycle counter and when relayfs writes it out. Otherwise
	 * time may appear to go backwards.
	 */
	local_irq_save(flags);

	log_lost_samples();

	buf[0] = FORMAT_HEADER_0(get_cycles());
	buf[1] = FORMAT_HEADER_1(event, data);
	__relay_write(log_chan, buf, sizeof(buf));

	local_irq_restore(flags);
}

static void logit_comm(unsigned char event, unsigned int data,
		       unsigned char *comm)
{
	unsigned long flags;
	unsigned long long header[2];
	char buf[sizeof(header) + TASK_COMM_LEN];

	/*
	 * We don't want to take any interrupts between when we sample
	 * the cycle counter and when relayfs writes it out. Otherwise
	 * time may appear to go backwards.
	 */
	local_irq_save(flags);

	log_lost_samples();

	header[0] = FORMAT_HEADER_0(get_cycles());
	header[1] = FORMAT_HEADER_1(event, data);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, header, sizeof(header));
	strncpy(buf + sizeof(header), comm, TASK_COMM_LEN);

	__relay_write(log_chan, buf, sizeof(buf));

	local_irq_restore(flags);
}

/*
 * To keep log entries small, we only log the bottom 32bits of
 * function pointers.
 */
#define TRUNCATE_FUNC(F) (((unsigned long)(F)) & 0xffffffff)

#ifdef CONFIG_PPC64
static void probe_irq_entry(void *ignore, struct pt_regs *regs)
{
	logit(EVENT_INTERRUPT_ENTRY, 0);
}

static void probe_irq_exit(void *ignore, struct pt_regs *regs)
{
	logit(EVENT_INTERRUPT_EXIT, 0);
}
#endif

static void probe_irq_handler_entry(void *ignore, int irq,
				    struct irqaction *action)
{
	logit(EVENT_INTERRUPT_HANDLER_ENTRY, irq);
}

static void probe_irq_handler_exit(void *ignore, int irq,
				   struct irqaction *action, int ret)
{
	logit(EVENT_INTERRUPT_HANDLER_EXIT, irq);
}

#ifdef CONFIG_PPC64
static void probe_timer_interrupt_entry(void *ignore, struct pt_regs *regs)
{
	logit(EVENT_TIMER_INTERRUPT_ENTRY, 0);
}

static void probe_timer_interrupt_exit(void *ignore, struct pt_regs *regs)
{
	logit(EVENT_TIMER_INTERRUPT_EXIT, 0);
}
#endif

static void probe_timer_expire_entry(void *ignore, struct timer_list *timer)
{
	logit(EVENT_TIMER_ENTRY, TRUNCATE_FUNC(timer->function));
}

static void probe_timer_expire_exit(void *ignore, struct timer_list *timer)
{
	logit(EVENT_TIMER_EXIT, TRUNCATE_FUNC(timer->function));
}

static void probe_hrtimer_expire_entry(void *ignore, struct hrtimer *timer,
				       ktime_t *now)
{
	logit(EVENT_TIMER_ENTRY, TRUNCATE_FUNC(timer->function));
}

static void probe_hrtimer_expire_exit(void *ignore, struct hrtimer *timer)
{
	logit(EVENT_TIMER_EXIT, TRUNCATE_FUNC(timer->function));
}

static void probe_softirq_entry(void *ignore, unsigned int vec_nr)
{
	logit(EVENT_SOFTIRQ_ENTRY, vec_nr);
}

static void probe_softirq_exit(void *ignore, unsigned int vec_nr)
{
	logit(EVENT_SOFTIRQ_EXIT, vec_nr);
}

static void probe_workqueue_execute_start(void *ignore,
					  struct work_struct *work)
{
	logit(EVENT_WORKQUEUE_ENTRY,  TRUNCATE_FUNC(work->func));
}

static void probe_workqueue_execute_end(void *ignore, struct work_struct *work)
{
	logit(EVENT_WORKQUEUE_EXIT, TRUNCATE_FUNC(work->func));
}

#ifndef NO_TASKLET_TRACEPOINTS
static void probe_tasklet_entry(void *ignore, struct tasklet_struct *t)
{
	logit(EVENT_TASKLET_ENTRY, TRUNCATE_FUNC(t->func));
}

static void probe_tasklet_exit(void *ignore, struct tasklet_struct *t)
{
	logit(EVENT_TASKLET_EXIT, TRUNCATE_FUNC(t->func));
}
#endif

#ifdef CONFIG_PPC64
static void probe_hcall_entry(void *ignore, unsigned long opcode,
			      unsigned long *args)
{
	/* Don't log H_CEDE */
	if (opcode != 224)
		logit(EVENT_HCALL_ENTRY, opcode);
}

static void probe_hcall_exit(void *ignore, unsigned long opcode,
			     unsigned long retval, unsigned long *retbuf)
{
	/* Don't log H_CEDE */
	if (opcode != 224)
		logit(EVENT_HCALL_EXIT, opcode);
}

static void probe_opal_entry(void *ignore, unsigned long opcode,
			     unsigned long *args)
{
	logit(EVENT_OPAL_ENTRY, opcode);
}

static void probe_opal_exit(void *ignore, unsigned long opcode,
			    unsigned long retval)
{
	logit(EVENT_OPAL_EXIT, opcode);
}

#endif

static void probe_sched_switch(void *ignore, bool preempt,
			       struct task_struct *prev,
			       struct task_struct *next)
{
	logit_comm(EVENT_CONTEXT_SWITCH, next->pid, next->comm);
}

static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
		&relay_file_operations);
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static int subbuf_start(struct rchan_buf *buf, void *subbuf, void *prev_subbuf,
			size_t prev_padding)
{
	if (relay_buf_full(buf)) {
		lost_sample();
		return 0;
	}

	return 1;
}

static struct rchan_callbacks relay_callbacks =
{
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
	.subbuf_start = subbuf_start,
};

static struct dentry *debugfs_root;

static int __init trace_init(void)
{
	debugfs_root = debugfs_create_dir("osjitter", NULL);

	if (debugfs_root == ERR_PTR(-ENODEV)) {
		printk("Debugfs not configured\n");
		return -ENODEV;
	}

	if (!debugfs_root) {
		printk("Could not create osjitter debugfs directory\n");
		return -ENODEV;
	}

	log_chan = relay_open("events-", debugfs_root, SUBBUF_SIZE,
			      N_SUBBUFS, &relay_callbacks, NULL);
	if (!log_chan) {
		printk("relay_open failed\n");
		debugfs_remove(debugfs_root);
		return -ENODEV;
	}

#ifdef CONFIG_PPC64
	WARN_ON(register_trace_irq_entry(probe_irq_entry, NULL));
	WARN_ON(register_trace_irq_exit(probe_irq_exit, NULL));
#endif

	WARN_ON(register_trace_irq_handler_entry(probe_irq_handler_entry, NULL));
	WARN_ON(register_trace_irq_handler_exit(probe_irq_handler_exit, NULL));

#ifdef CONFIG_PPC64
	WARN_ON(register_trace_timer_interrupt_entry(probe_timer_interrupt_entry, NULL));
	WARN_ON(register_trace_timer_interrupt_exit(probe_timer_interrupt_exit, NULL));
#endif

	WARN_ON(register_trace_timer_expire_entry(probe_timer_expire_entry, NULL));
	WARN_ON(register_trace_timer_expire_exit(probe_timer_expire_exit, NULL));

	WARN_ON(register_trace_hrtimer_expire_entry(probe_hrtimer_expire_entry, NULL));
	WARN_ON(register_trace_hrtimer_expire_exit(probe_hrtimer_expire_exit, NULL));

	WARN_ON(register_trace_softirq_entry(probe_softirq_entry, NULL));
	WARN_ON(register_trace_softirq_exit(probe_softirq_exit, NULL));

	WARN_ON(register_trace_workqueue_execute_start(probe_workqueue_execute_start, NULL));
	WARN_ON(register_trace_workqueue_execute_end(probe_workqueue_execute_end, NULL));

#ifndef NO_TASKLET_TRACEPOINTS
	WARN_ON(register_trace_tasklet_entry(probe_tasklet_entry, NULL));
	WARN_ON(register_trace_tasklet_exit(probe_tasklet_exit, NULL));
#endif

#ifdef CONFIG_PPC64
	WARN_ON(register_trace_hcall_entry(probe_hcall_entry, NULL));
	WARN_ON(register_trace_hcall_exit(probe_hcall_exit, NULL));

	WARN_ON(register_trace_opal_entry(probe_opal_entry, NULL));
	WARN_ON(register_trace_opal_exit(probe_opal_exit, NULL));
#endif

	WARN_ON(register_trace_sched_switch(probe_sched_switch, NULL));

	printk("osjitter static tracepoints tracing registered\n");
	return 0;
}

static void __exit trace_exit(void)
{
#ifdef CONFIG_PPC64
	unregister_trace_irq_entry(probe_irq_entry, NULL);
	unregister_trace_irq_exit(probe_irq_exit, NULL);
#endif

	unregister_trace_irq_handler_entry(probe_irq_handler_entry, NULL);
	unregister_trace_irq_handler_exit(probe_irq_handler_exit, NULL);

#ifdef CONFIG_PPC64
	unregister_trace_timer_interrupt_entry(probe_timer_interrupt_entry, NULL);
	unregister_trace_timer_interrupt_exit(probe_timer_interrupt_exit, NULL);
#endif

	unregister_trace_timer_expire_entry(probe_timer_expire_entry, NULL);
	unregister_trace_timer_expire_exit(probe_timer_expire_exit, NULL);

	unregister_trace_hrtimer_expire_entry(probe_hrtimer_expire_entry, NULL);
	unregister_trace_hrtimer_expire_exit(probe_hrtimer_expire_exit, NULL);

	unregister_trace_softirq_entry(probe_softirq_entry, NULL);
	unregister_trace_softirq_exit(probe_softirq_exit, NULL);

	unregister_trace_workqueue_execute_start(probe_workqueue_execute_start, NULL);
	unregister_trace_workqueue_execute_end(probe_workqueue_execute_end, NULL);

#ifndef NO_TASKLET_TRACEPOINTS
	unregister_trace_tasklet_entry(probe_tasklet_entry, NULL);
	unregister_trace_tasklet_exit(probe_tasklet_exit, NULL);
#endif

#ifdef CONFIG_PPC64
	unregister_trace_hcall_entry(probe_hcall_entry, NULL);
	unregister_trace_hcall_exit(probe_hcall_exit, NULL);

	unregister_trace_opal_entry(probe_opal_entry, NULL);
	unregister_trace_opal_exit(probe_opal_exit, NULL);
#endif

	unregister_trace_sched_switch(probe_sched_switch, NULL);

	tracepoint_synchronize_unregister();

	relay_close(log_chan);
	debugfs_remove(debugfs_root);

	printk("osjitter static tracepoints tracing unregistered\n");
}

module_init(trace_init)
module_exit(trace_exit)
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anton Blanchard");
