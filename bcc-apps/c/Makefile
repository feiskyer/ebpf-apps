APPS = hello_world

.PHONY: all
all: $(APPS)

$(APPS):
	clang -lbcc -lbcc_bpf $@.c -o $@

format:
	VERSION_CONTROL=none indent -linux *.c

clean:
	rm -rf $(APPS)
