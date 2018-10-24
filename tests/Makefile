CC	 = clang
LD	 = lld

CFLAGS	 = -g -Wall -O2 -D_GNU_SOURCE=1 -D_POSIX_C_SOURCE=20180920 -fPIC

tests: traceMany forkMany
	./traceMany ./forkMany

all: traceMany forkMany

.c.o:
	$(CC) $< -c -o $@ $(CFLAGS)

traceMany: traceMany.o
	$(CC) $^ -o $@ $(CFLAGS)

forkMany: forkMany.o
	$(CC) $^ -o $@ $(CFLAGS)

clean:
	$(RM) *.o traceMany forkMany

