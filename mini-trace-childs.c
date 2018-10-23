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
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

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
      printf("fork, newPid = %u\n", newPid);
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
  
  pid = fork();
  
  if (pid > 0) {
    ret = run_tracer(pid);
  } else if (pid == 0) {
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
