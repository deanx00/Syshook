MODULE_NAME := syshook
SOURCE_DIR := src
BUILD_DIR := build
KDIR := /lib/modules/$(shell uname -r)/build

obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(SOURCE_DIR)/syshooks.o $(SOURCE_DIR)/hooks.o

all:
	@mkdir -p $(BUILD_DIR)
	make -C $(KDIR) M=$(PWD) modules
	@mv *.o *.mod *.mod.c *.order *.symvers $(BUILD_DIR)/ 2>/dev/null || true

clean:
	make -C $(KDIR) M=$(PWD) clean
	@rm -rf $(BUILD_DIR)
