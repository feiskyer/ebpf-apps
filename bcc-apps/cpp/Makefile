APPS = hello_world

.PHONY: all
all: $(APPS)

$(APPS):
	clang++ -I /usr/include/bcc/compat -lbcc --std=c++11 $@.cpp -o $@

clean:
	rm -rf $(APPS)
