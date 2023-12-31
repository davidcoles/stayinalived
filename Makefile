LIBBPF := $(PWD)/vc5

export CGO_CFLAGS  = -I$(LIBBPF)
export CGO_LDFLAGS = -L$(LIBBPF)/bpf

MAX_FLOWS ?= 100000

stayinalived: stayinalived.go balancer.go stats.go vc5/kernel/bpf/bpf.o static
	go build stayinalived.go balancer.go stats.go

static: vc5 vc5/cmd/static
	cp -r vc5/cmd/static ./

stats.go: vc5 vc5/cmd/stats.go
	cp vc5/cmd/stats.go $@

vc5/kernel/bpf/bpf.o: vc5
	cd vc5 && $(MAKE) kernel/bpf/bpf.o MAX_FLOWS=$(MAX_FLOWS)

vc5:
	#git clone --branch byob https://github.com/davidcoles/vc5.git
	git clone --branch ipvs https://github.com/davidcoles/vc5.git

clean:
	rm -f stayinalived

#distclean: clean
#	rm -rf vc5 static
