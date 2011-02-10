ccsecurity-objs := address_group.o audit.o autobind.o capability.o condition.o domain.o environ.o file.o gc.o maymount.o memory.o mount.o network.o number_group.o path_group.o policy_io.o proc_if.o realpath.o signal.o util.o

ifeq ($(PATCHLEVEL),4)

ifdef CONFIG_CCSECURITY
O_TARGET := ccsecurity.o
ifdef CONFIG_CCSECURITY_LKM
all_targets: load_policy.o
obj-m := ccsecurity.o
obj-y := $(ccsecurity-objs)
else
all_targets: ccsecurity.o
obj-y := load_policy.o $(ccsecurity-objs)
endif
export-objs := load_policy.o
endif
include $(TOPDIR)/Rules.make

else

obj-y += load_policy.o
ifdef CONFIG_CCSECURITY_LKM
obj-m += ccsecurity.o
else
obj-y += ccsecurity.o
endif

endif
