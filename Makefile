CC	 = clang
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC
SECCOMP  = -lseccomp

all: mini-trace mini-trace-childs bpf-trace

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

mini-trace: mini-trace.o
	$(CC) $^ -o $@ $(CFLAGS)

mini-trace-childs: mini-trace-childs.o
	$(CC) $^ -o $@ $(CFLAGS)

bpf-trace: bpf-trace.o
	$(CC) $^ -o $@ $(CFLAGS) $(SECCOMP)

tests:
	$(MAKE) -C tests

clean:
	$(RM) $(OBJS) trace

.PHONY: all tests clean
