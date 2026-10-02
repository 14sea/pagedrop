P_PWD ?= $(shell pwd)
P_KVER ?= $(shell uname -r)

ccflags-y := \
	-std=gnu99 \
	-Werror \
	-Wno-declaration-after-statement \
	$(CCFLAGS)

obj-m += pagedrop.o

ifneq ($(KERNELRELEASE),)
ifeq ($(ARCH),arm64)
ccflags-y += -DPB_ARCH_ARM64
else ifeq ($(ARCH),x86)
ccflags-y += -DPB_ARCH_X86_64
else ifeq ($(ARCH),x86_64)
ccflags-y += -DPB_ARCH_X86_64
endif
else
KERNEL ?= /lib/modules/$(P_KVER)/build

all:
	$(MAKE) -C $(KERNEL) M=$(P_PWD) modules

clean:
	$(MAKE) -C $(KERNEL) M=$(P_PWD) clean

.PHONY: all clean
endif
