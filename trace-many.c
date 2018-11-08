/**
 * a mini tracer demonstrates ptrace api
 * single tracer with multiple (follow fork) tracees
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <stdatomic.h>

struct mmap_entry {
  unsigned long base;
  unsigned long size;
  unsigned int  prot;
  unsigned int  flags;
  unsigned long offset;
  char          file[96];
};

struct mmap_entry* populate_memory_map(pid_t pid, int* nmemb) {
  int i = 0, rc;
  int allocated = 128;
  size_t nb = 0;
  char proc[64], *line = NULL;
  char* p, *q;
  struct mmap_entry* map = calloc(allocated, sizeof(*map)), *e;
  FILE* fp;

  assert(map != NULL);
  snprintf(proc, 64, "/proc/%u/maps", pid);
  fp = fopen(proc, "rb");
  if (!fp) {
    fprintf(stderr, "unable to open file: %s, error: %s\n", proc, strerror(errno));
    exit(1);
  }

  while(!feof(fp)) {
    if (i >= (allocated-1)) {
      allocated += 128;
      map = realloc(map, allocated * sizeof(*map));
      assert(map != NULL);
    }
    
    rc = getline(&line, &nb, fp);
    if (rc <= 0) break;
    line[rc-1] = '\0';

    e = &map[i++];
    
    e->base = strtoul(line, &p, 16);
    e->size = strtoul(1+p, &q, 16) - e->base;
    p       = 1 + q;
    if (*p++ == 'r') e->prot  |= PROT_READ;
    if (*p++ == 'w') e->prot  |= PROT_WRITE;
    if (*p++ == 'x') e->prot  |= PROT_EXEC;
    if (*p == 'p') e->flags |= MAP_PRIVATE;
    if (*p++ == 's') e->flags |= MAP_SHARED;
    e->offset = strtoul(1+p, &q, 16);
    p = strpbrk(1+q, " ");
    assert(p != NULL);
    strtoul(1+p, &q, 10);
    p = strpbrk(1+q, "/[");
    if (p) strncpy(e->file, p, 95);
    else e->file[0] = 0;
  }

  free(line);
  fclose(fp);

  memset(&map[i], 0, sizeof(map[i]));

  if (nmemb) *nmemb = i;

  return map;
}

void free_mmap_entry(struct mmap_entry* map) {
  free(map);
}

static void usage(const char* prog) {
  fprintf(stderr, "%s <program> [program_arguments]\n", prog);
}

static void show_maps(pid_t pid) {
  char proc[256];
  char buff[1 + BUFSIZ];
  int fd, n;
  
  snprintf(proc, 256, "/proc/%d/maps", pid);

  /* use syscall to read procfs instead of stdio */
  fd = open(proc, O_RDONLY, 0);
  assert(fd >= 0);

  while (1) {
    n = read(fd, buff, BUFSIZ);
    if (n < 0) {
      if (errno == EINTR) { /* restart syscall */
	continue;
      } else {
	fprintf(stderr, "read failed for file: %s, error: %s\n", proc, strerror(errno));
	break;
      }
    } else if (n == 0) {
      break;
    } else {
      assert (n <= BUFSIZ);
      assert(fwrite(buff, 1, n, stdout) == n);
    }
  }

  close(fd);
  fflush(stdout);
}

/* now tracee is stopped and exec has replaced old 
   program with new program context */
static void tracee_preinit(pid_t pid) {
  show_maps(pid);
}

/* reached ptrace_event_exec, but the new progrma isn't actually running */
static void do_ptrace_exec(pid_t pid) {
  struct user_regs_struct regs;
  int status;
  
  assert(ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0);
  unsigned long saved_insn;

  /* rip must be word aligned */
  saved_insn = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0);
  assert(saved_insn != -1);

  /* break point, lsb first */
  assert(ptrace(PTRACE_POKETEXT, pid, regs.rip, (saved_insn & ~0xff) | 0xcc) == 0);
  assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);
  assert(waitpid(pid, &status, 0) == pid);

  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) { /* breakpoint hits */
    tracee_preinit(pid);
    assert(ptrace(PTRACE_POKETEXT, pid, regs.rip, saved_insn) == 0);
    /* now rewind pc prior to our bp */
    assert(ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0);
    regs.rip -= 1; /* 0xcc */
    assert(ptrace(PTRACE_SETREGS, pid, 0, &regs) == 0);
    assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);
  } else {
    fprintf(stderr, "expect breakpoint hits.\n");
    exit(1);
  }
}

static void init_sig_handlers(void)
{
  struct sigaction sa;
  sigset_t set;

  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_NOCLDWAIT | SA_RESTART;
  sigemptyset(&set);
  sa.sa_mask = set;
  sa.sa_handler = SIG_IGN;
  sigaction(SIGCHLD, &sa, NULL);
}

static int run_tracer(pid_t pid) {
  int status;
  pid_t newPid;

  assert(waitpid(pid, &status, 0) == pid);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) { /* intial sigstop */
    ;
  } else {
    fprintf(stderr, "expected SIGSTOP to be raised.\n");
    return -1;
  }
  
  assert(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) == 0);
  assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);

  while ((pid = waitpid(-1, &status, 0)) != -1) {
    printf("[pid %u] ", pid);
    /* wait for our expected PTRACE_EVENT_EXEC */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && (status >> 16 == PTRACE_EVENT_EXEC)) {
      do_ptrace_exec(pid);
      printf("exec event\n");
      ptrace(PTRACE_CONT, pid, 0, 0);
    } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && (status >> 16 == PTRACE_EVENT_FORK)) {
      assert(ptrace(PTRACE_GETEVENTMSG, pid, 0, &newPid) == 0);
      fprintf(stderr,"fork, newPid = %u\n", newPid);
      assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);
    } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && (status >> 16 == PTRACE_EVENT_VFORK)) {
      assert(ptrace(PTRACE_GETEVENTMSG, pid, 0, &newPid) == 0);
      printf("vfork, newPid = %u\n", newPid);
      assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);
    } else if (WIFEXITED(status)) {
      printf("%u exited.\n", pid);
    } else if (WIFSTOPPED(status)) {
      printf("received signal: %u\n", WSTOPSIG(status));
      assert(ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == 0);
    } else {
      fprintf(stderr, "unknown process status: %x\n", status);
      assert(ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)) == 0);
      break;
    }
  }
  return 0;
}

static int run_app(int argc, char* argv[])
{
  pid_t pid;
  int ret = -1;

  init_sig_handlers();

  pid = fork();
  
  if (pid > 0) {
    ret = run_tracer(pid);
  } else if (pid == 0) {
    assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
    raise(SIGSTOP);
    execvp(argv[0], argv);
    fprintf(stderr, "unable to run child: %s\n", argv[1]);
    abort();
  } else {
    fprintf(stderr, "fork failed: %s\n", strerror(errno));
    exit(1);
  }
  return ret;
}

int main(int argc, char* argv[])
{
  if (argc < 2) {
    usage(argv[0]);
    exit(1);
  }

  return run_app(argc-1, &argv[1]);
}
