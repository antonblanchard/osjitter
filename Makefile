ifdef NO_TASKLET_TRACEPOINTS
	ccflags-y += -DNO_TASKLET_TRACEPOINTS
endif

ifdef NO_PHYP_TRACEPOINTS
	ccflags-y += -DNO_PHYP_TRACEPOINTS
endif

obj-m := osjitter_tracepoints.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf *.mod.c *.ko *.o .*.cmd .tmp_versions Module.markers modules.order Module.symvers *.pyc
