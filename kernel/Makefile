APPS = hello

.PHONY: all
all: $(APPS)

KERN_SOURCES = ${APPS:=_kern.c}
USER_SOURCES = ${APPS:=_user.c}
USER_SOURCES += trace_helpers.c
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}
USER_LIBS += trace_helpers.o

KERNEL_SOURCE ?= /usr/src/$(shell uname -r)
KERNEL_INCLUDES := -I$(KERNEL_SOURCE)/tools/lib/
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include/generated/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include/generated
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/arch/x86/include/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include/generated/uapi
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include/linux/kconfig.h
KERNEL_INCLUDES += -I$(KERNEL_SOURCE)/include

LIBBPF = -L$(KERNEL_SOURCE)/tools/lib/bpf/

$(APPS): %: %_kern.o %_user.o $(USER_LIBS)
	clang -Wall -O2 -g $@_user.o $(USER_LIBS) -static $(LIBBPF) -lbpf -lelf -lz -o $@

$(USER_OBJECTS): %.o: %.c
	clang -g -O2 -Wall -I . -c $< -o $@

$(KERN_OBJECTS): %.o: %.c
	clang -g -O2 \
		-target bpf \
		-c $< -o $@ \
		-D__TARGET_ARCH_x86 \
		-D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option \
		$(KERNEL_INCLUDES)

format:
	VERSION_CONTROL=none indent -linux *.h *.c

clean:
	rm -rf $(APPS) *.o
