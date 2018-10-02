CC	 = clang
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_POSIX_C_SOURCE=20180920 -fPIC -fPIE

all: trace

SRCS	 = $(shell ls *.c)
OBJS	 = $(patsubst %.c, %.o, ${SRCS})

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

trace: $(OBJS)
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	$(RM) $(OBJS) trace

