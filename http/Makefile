TARGETS = http

all: $(TARGETS)
.PHONY: all

$(TARGETS): %: %.bpf.o

http.bpf.o: http.bpf.c
	clang \
		-Wall \
		-Werror \
		-target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
		-O2 -o $@ -c $<

clean:
	- rm *.bpf.o
	- rm -f /sys/fs/bpf/http

load:
	bpftool prog load http/http.bpf.o  /sys/fs/bpf/http

attach:
	bpftool net attach xdp name http dev wlp4s0

detach:
	bpftool net detach xdp dev wlp4s0

logs:
	cat /sys/kernel/debug/tracing/trace_pipe


