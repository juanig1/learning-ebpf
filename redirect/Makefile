.PHONY: *
TARGETS = redirect

all: $(TARGETS)

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
	- tc qdisc del dev wlp4s0 clsact

load:
	- tc qdisc add dev wlp4s0 clsact
	-	tc filter add dev wlp4s0 ingress bpf direct-action obj redirect.bpf.o sec tc/ingress && \
		tc filter add dev wlp4s0 egress bpf direct-action obj redirect.bpf.o sec tc/egress

unload:
	tc qdisc del dev wlp4s0 clsact

logs:
	cat /sys/kernel/debug/tracing/trace_pipe


