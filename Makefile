CC	 = clang
LD	 = lld

CFLAGS	 = -Wall -O2 -D_POSIX_C_SOURCE=20180920

all: trace

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@

trace: $(OBJS)
	$(CC) $^ -o $@

clean:
	$(RM) $(OBJS) trace

