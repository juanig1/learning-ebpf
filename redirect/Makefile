TARGETS = redirect

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o

redirect.bpf.o: redirect.bpf.c
	clang \
		-Wall \
		-Werror \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -O2 -o $@ -c $<

clean:
	- rm *.bpf.o
	- rm -f /sys/fs/bpf/redirect

