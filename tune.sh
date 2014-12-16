#!/bin/bash -e

# Example tuning script. Tries to mitigate jitter and affinitise anything
# else onto a support CPU

# Affinitise as much jitter as we can to this CPU
JITTER_CPU=0
JITTER_CPUMASK=1

grep -q isolcpus /proc/cmdline || \
	echo "Suggest booting with isolcpus to minimise kernel jitter (eg workqueue items)"

# disable SMT
if [ -x /usr/sbin/ppc64_cpu ]; then
	/usr/sbin/ppc64_cpu --smt=off
fi

# disable the software watchdog
echo 0 > /proc/sys/kernel/watchdog_thresh

# disable hung task detection
echo 0 > /proc/sys/kernel/hung_task_timeout_secs

# reduce the update rate of VM statistics
echo 60 > /proc/sys/vm/stat_interval

# disable irqbalance daemon
service irqbalance stop || true

# Affinitise interrupts
for IRQ in $(egrep '(XICS|OPAL|IO-APIC|PCI-MSI)' /proc/interrupts | grep -v IPI | cut -f1 -d:)
do
	echo $JITTER_CPUMASK > /proc/irq/${IRQ}/smp_affinity
done

# Affinitise kthreads
KTHREADD=`ps -C kthreadd -o pid=`
KTHREADS=`ps --ppid $KTHREADD -o pid=`

for PID in $KTHREADS
do
	taskset -c -p 0 $PID > /dev/null 2>&1
done
