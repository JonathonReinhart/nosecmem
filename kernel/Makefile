# Build against running kernel
#KDIR := /lib/modules/$(shell uname -r)/build

# Build against a kernel repo
#KDIR := $(shell realpath ~/gitrepos/linux)

ifndef KDIR
  $(error KDIR is not set)
endif

obj-m := nosecmem.o

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
