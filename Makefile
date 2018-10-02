CC	 = clang
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC

all: mini-trace

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

mini-trace: mini-trace.o
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	$(RM) $(OBJS) trace

