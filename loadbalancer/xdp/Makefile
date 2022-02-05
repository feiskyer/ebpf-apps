APPS= xdp-proxy xdp-proxy-v2
LIBBPF_SRC := $(abspath ../../libbpf/src)
LIBBPF_OBJ := $(abspath ../../bpf-apps/libbpf/libbpf.a)
INCLUDES := -Ilibbpf/usr/include -I../libbpf/include/uapi -I.

.PHONY: all
all: $(APPS)

$(APPS): %: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -I. -c $@.bpf.c -o $@.bpf.o
	bpftool gen skeleton $@.bpf.o > $@.skel.h
	clang -g -O2 -Wall $(INCLUDES) -c $@.c -o $@.o
	clang -Wall -O2 -g $@.o $(LIBBPF_OBJ) -static -lelf -lz -o $@

libbpf: $(LIBBPF_OBJ)
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile)
	make -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 OBJDIR=$(dir $@) DESTDIR=$(dir $@) install

clean:
	rm -rf $(APPS) *.o
