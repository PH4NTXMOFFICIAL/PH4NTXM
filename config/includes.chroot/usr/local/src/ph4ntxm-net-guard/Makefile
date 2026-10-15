CC ?= cc
CLANG ?= clang-19
MULTIARCH := $(shell $(CC) -print-multiarch)
CPPFLAGS ?=
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=3
LDFLAGS ?= -pie -Wl,-z,relro,-z,now,-z,noexecstack
LDLIBS ?= -lbpf

all: ph4ntxm-net-guard-native net-guard.bpf.o

ph4ntxm-net-guard-native: native.c guard.h
	$(CC) $(CPPFLAGS) $(CFLAGS) native.c $(LDFLAGS) $(LDLIBS) -o $@

net-guard.bpf.o: guard.bpf.c guard.h core_types.h
	$(CLANG) $(CPPFLAGS) -I/usr/include/$(MULTIARCH) -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Wextra -Werror -c guard.bpf.c -o $@

check: all
	./ph4ntxm-net-guard-native --self-test

clean:
	rm -f ph4ntxm-net-guard-native net-guard.bpf.o

.PHONY: all check clean
