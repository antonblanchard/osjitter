osjitter
========

Overview
--------

This tool uses static tracepoints to collect sources of jitter in the
Linux kernel. The following patches (found in patches/) need to be applied
first:

tasklet_tracepoints.patch
export_tracepoints.patch

Be sure CONFIG_RELAY and CONFIG_DEBUG_FS are enabled.

Example usage
-------------

- First build and insert the module:

```
make
insmod ./osjitter_tracepoints.ko
```

- Run a workload (here we just use sleep to log for 30 seconds):

```
./osjitter_log.py -o run1_stats sleep 30
```

- Get a summary of jitter:

```
./osjitter_summary.py run1_stats/*
```

- Get an event trace of everything:

```
./osjitter_trace.py run1_stats/*
```
