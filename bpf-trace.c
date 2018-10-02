/**
 * a mini tracer demonstrates ptrace api
 * and how to insert breakpoint at program entry point
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <seccomp.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <limits.h>

static inline void throwIfMinus(int x, const char* expr, const char* file, int line)
{
  if (x < 0) {
    fprintf(stderr, "%s:%u: %s returned %d\n", file, line, expr, x);
    abort();
  }
}

static inline void throwErrnoIfMinus(int x, const char* expr, const char* file, int line)
{
  if (x < 0) {
    fprintf(stderr, "%s:%u: %s returned %d, error: %s\n", file, line, expr, x, strerror(errno));
    abort();
  }
}

#define ThrowIfMinus(expr) ( throwIfMinus(expr, #expr, __FILE__, __LINE__) )
#define ThrowErrnoIfMinus(expr) ( throwErrnoIfMinus(expr, #expr, __FILE__, __LINE__) )

static scmp_filter_ctx load_seccomp_rules(void)
{
  scmp_filter_ctx ctx;
  
  ctx = seccomp_init(SCMP_ACT_ALLOW);
  assert(ctx);

  ThrowErrnoIfMinus(seccomp_rule_add(ctx, SCMP_ACT_TRACE(SCMP_SYS(openat)), SCMP_SYS(openat), 0));
  ThrowErrnoIfMinus(seccomp_rule_add(ctx, SCMP_ACT_TRACE(SCMP_SYS(access)), SCMP_SYS(access), 0));
  ThrowErrnoIfMinus(seccomp_load(ctx));

  return ctx;
}

static int ptrace_peek_cstring(pid_t pid, char* buf, int n, const void* remotePtr)
{
  long data;
  int i = 0, k;
  bool null = 0;

  while (i < n && !null) {
    errno = 0;
    data = ptrace(PTRACE_PEEKDATA, pid, remotePtr, 0);
    if (data == -1 && errno != 0) {
      fprintf(stderr, "ptrace peekdata failed: %s\n", strerror(errno));
      exit(1);
    }
    remotePtr += sizeof(long);
    for(k = 0; k < sizeof(long) && i < n; i++, k++) {
      buf[i] = (data >> (8*k)) & 0xff;
      if (buf[i] == '\0') null = true;
    }
  }
  return i;
}

static bool openat_enter(int pid, struct user_regs_struct* regs)
{
  char path[1 + PATH_MAX];
  
  const void* remotePtr = (const void*)regs->rsi;
  ptrace_peek_cstring(pid, path, PATH_MAX, remotePtr);
  printf("openat file: %s\n", path);
  return true;
}

static void openat_exit(int pid, struct user_regs_struct* regs)
{
  int retval = (int)regs->rax;
  printf("openat returned: %d\n", retval);
}

static bool access_enter(int pid, struct user_regs_struct* regs)
{
  char path[1 + PATH_MAX];
  
  const void* remotePtr = (const void*)regs->rdi;
  ptrace_peek_cstring(pid, path, PATH_MAX, remotePtr);
  printf("access file: %s\n", path);
  return false;
}

static bool syscall_enter(int pid, int syscall, struct user_regs_struct* regs)
{
  switch(syscall) {
  case SCMP_SYS(openat):
    return openat_enter(pid, regs);
    break;
  case SCMP_SYS(access):
    return access_enter(pid, regs);
    break;
  default:
    fprintf(stderr, "unknown syscall: %u\n", syscall);
    exit(1);
    break;
  }
}

static void syscall_exit(int pid, int syscall, struct user_regs_struct* regs)
{
  switch(syscall) {
  case SCMP_SYS(openat):
    openat_exit(pid, regs);
    break;
  case SCMP_SYS(access):
    break;
  default:
    fprintf(stderr, "unknown syscall: %u\n", syscall);
    exit(1);
    break;
  }
}

static void do_ptrace_seccomp(pid_t pid)
{
  struct user_regs_struct regs;
  long msg;
  int status;
  int syscall;
  bool post;
  
  ThrowErrnoIfMinus(ptrace(PTRACE_GETEVENTMSG, pid, 0, &msg));
  ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
  
  if (msg == 0x7fff) {
    int unfiltered = regs.orig_rax;
    fprintf(stderr, "unfiltered syscall: %u\n", unfiltered);
    exit(1);
  }

  syscall = (int)msg;

  post = syscall_enter(pid, syscall, &regs);

  if (post) {
    ThrowErrnoIfMinus(ptrace(PTRACE_SYSCALL, pid, 0, 0) == 0);
    assert(waitpid(pid, &status, 0) == pid);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == (0x80 | SIGTRAP) && (status >> 16 == 0)) {
      ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
      syscall_exit(pid, syscall, &regs);
      ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, 0));
    } else {
      fprintf(stderr, "expect seccomp exit (SYSCALL_GOOD), but got %x\n", status);
      exit(1);
    }
  } else {
    ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, 0));
  }
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
  
  ThrowErrnoIfMinus(ptrace(PTRACE_GETREGS, pid, 0, &regs));
  unsigned long saved_insn;

  /* rip must be word aligned */
  assert((regs.rip & 0x7) == 0);
  saved_insn = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0);
  assert(saved_insn != -1);

  /* break point, lsb first */
  ThrowErrnoIfMinus(ptrace(PTRACE_POKETEXT, pid, regs.rip, (saved_insn & ~0xff) | 0xcc));
  ThrowErrnoIfMinus(ptrace(PTRACE_CONT, pid, 0, 0));
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

static int run_tracer(pid_t pid) {
  int status;
  
  assert(waitpid(pid, &status, 0) == pid);
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) { /* intial sigstop */
    ;
  } else {
    fprintf(stderr, "expected SIGSTOP to be raised.\n");
    return -1;
  }

  assert(ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD ) == 0);
  assert(ptrace(PTRACE_CONT, pid, 0, 0) == 0);

  while (1) {
    assert(waitpid(pid, &status, 0) == pid);
    /* wait for our expected PTRACE_EVENT_EXEC */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && (status >> 16 == PTRACE_EVENT_EXEC)) {
      do_ptrace_exec(pid);
    } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP && (status >> 16 == PTRACE_EVENT_SECCOMP)) {
      do_ptrace_seccomp(pid);
    } else if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    } else {
      fprintf(stderr, "expect ptrace exev event, got: %x\n", status);
      return -1;
    }
  }
}

static int run_app(int argc, char* argv[])
{
  pid_t pid;
  int ret = -1;
  
  pid = fork();
  
  if (pid > 0) {
    ret = run_tracer(pid);
  } else if (pid == 0) {
    load_seccomp_rules();
    assert(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0);
    raise(SIGSTOP);
    execvp(argv[0], argv);
    fprintf(stderr, "unable to run child: %s\n", argv[1]);
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
