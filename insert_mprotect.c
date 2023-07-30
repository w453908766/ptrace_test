
#include <stdio.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void print_rip(pid_t child, const char* msg, int offset);
void print_reg(pid_t child, const char* msg);
void print_mem(pid_t child, const char* msg, void* addr);
void stepLoop(pid_t child);
void handleExit(pid_t child);

enum INT3_SIGNAL { PassInfo = 4444, Ret, RunFunction};
void* call_func;
void* open_write;
void* close_write;

struct user_regs_struct regs;

void handleInt3(pid_t child, int status);

void runFunc(pid_t child, int status){
  ptrace(PTRACE_POKEUSER, child, 8 * RIP, call_func);
  ptrace(PTRACE_CONT, child, NULL, NULL);

  while (1) {
    int status;
    wait(&status);
    if (WIFEXITED(status)) {
      printf("too early exit %d\n", WEXITSTATUS(status));
      break;
    } else if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP){
      long rip = ptrace(PTRACE_PEEKUSER, child, 8 * RIP, NULL);
      long cmd = ptrace(PTRACE_PEEKTEXT, child, rip-2, NULL) & 0xFFFF;
      if(cmd >> 8 == 0xCC){

        handleInt3(child, status);
        break;
      }
    }
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  }
}


void handleInt3(pid_t child, int status){
  long r15 = ptrace(PTRACE_PEEKUSER, child, 8 * R15, NULL);
  if(r15 == PassInfo){
    long r14 = ptrace(PTRACE_PEEKUSER, child, 8 * R14, NULL);
    call_func = (void*)ptrace(PTRACE_PEEKDATA, child, r14, NULL);
    open_write = (void*)ptrace(PTRACE_PEEKDATA, child, r14+8, NULL);
    close_write = (void*)ptrace(PTRACE_PEEKDATA, child, r14+16, NULL);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  } else if(r15 == Ret) {
    long ret = ptrace(PTRACE_PEEKUSER, child, 8 * R14, NULL);
    printf("ret %ld\n", ret);
    ptrace(PTRACE_SETREGS, child, NULL, &regs);
    // ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  } else if(r15 == RunFunction){
    runFunc(child, status);
  }
}

void handleSyscall(pid_t child, int status) {
  long orig_rax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, NULL);
  ptrace(PTRACE_SYSCALL, child, NULL, NULL);

  // if (orig_rax == SYS_exit || orig_rax == SYS_exit_group) {
  //   handleExit(child);
  // } else if(orig_rax == SYS_write){
  //   // handleWrite(child);
  //   ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  // } else if(orig_rax == SYS_time){
  //   handleTime(child);
  //   //ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  // } else {
  //   // printf("syscall %ld\n", orig_rax);
  //   ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  // }
}

void run_open_write(pid_t child, int status){
  siginfo_t si;
  ptrace(PTRACE_GETSIGINFO, child, 0, &si);

  ptrace(PTRACE_GETREGS, child, NULL, &regs);
  ptrace(PTRACE_POKEUSER, child, 8 * R14, open_write);
  ptrace(PTRACE_POKEUSER, child, 8 * RDI, si.si_addr);
  runFunc(child, status);

  ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
  wait(NULL);

  ptrace(PTRACE_GETREGS, child, NULL, &regs);
  ptrace(PTRACE_POKEUSER, child, 8 * R14, close_write);
  ptrace(PTRACE_POKEUSER, child, 8 * RDI, si.si_addr);
  runFunc(child, status);

  ptrace(PTRACE_CONT, child, NULL, NULL);
}

void handleSEGV(pid_t child, int status){
  run_open_write(child, status);
}

void handleSIGNALED(pid_t child, int status){
  printf("signal\n");
  siginfo_t si;
  ptrace(PTRACE_GETSIGINFO, child, 0, &si);
  printf("%p\n", si.si_addr);
  ptrace(PTRACE_KILL, child, NULL, NULL);
  exit(EXIT_SUCCESS);
}