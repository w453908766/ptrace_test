
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

void runChild(char **argv) {
  personality(ADDR_NO_RANDOMIZE);
  ptrace(PTRACE_TRACEME, 0, NULL, NULL);
  execv(argv[1], argv + 1);
}

void print_rip(pid_t child, const char* msg, int offset){
  long rip = ptrace(PTRACE_PEEKUSER, child, 8 * RIP, NULL);
  long cmd = ptrace(PTRACE_PEEKTEXT, child, rip + offset, NULL);
  printf("%s rip: %lX, cmd: %lX\n", msg, rip+offset, cmd);
}

void print_reg(pid_t child, const char* msg) {
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child, NULL, &regs);
  printf("%s\trip: %llX\trax: %llX\trbx: %llX\trcx: %llX\trdx: %llX\trsi: %llX\trdi: %llX\trbp: %llX\trsp: %llX\tr14: %llX\tr15: %llX\n", 
    msg, regs.rip, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.rsp, regs.r14, regs.r15);
}

void print_mem(pid_t child, const char* msg, void* addr){
  long data = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
  printf("%s %lX\n", msg, data);
}

void handleExit(pid_t child){
  long rdi = ptrace(PTRACE_PEEKUSER, child, 8 * RDI, NULL);
  printf("exit called with %ld\n", rdi);
  ptrace(PTRACE_SYSCALL, child, NULL, NULL);
}

void stepLoop(pid_t child){
  while(1){
    print_rip(child, "next", 0);
    print_reg(child, "reg");
    getchar();
    ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
    wait(NULL);
  }
}

void handleInt3(pid_t child, int status);
void handleSyscall(pid_t child, int status);
void handleSEGV(pid_t child, int status);
void handleSIGNALED(pid_t child, int status);

void handleTRAP(pid_t child, int status) {
  // TODO: execve will modify rip
  long rip = ptrace(PTRACE_PEEKUSER, child, 8 * RIP, NULL);
  long cmd = ptrace(PTRACE_PEEKTEXT, child, rip-2, NULL) & 0xFFFF;

  if(cmd >> 8 == 0xCC){
    handleInt3(child, status);
  } else if (cmd == 0x80CD){
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  } else if (cmd == 0x050F){
    handleSyscall(child, status);
  } else {
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  }
}

void handleSTOPPED(pid_t child, int status){
  int sig = WSTOPSIG(status);
  if(sig == SIGTRAP){
    handleTRAP(child, status);
  } else if (sig == SIGSEGV) {
    handleSEGV(child, status);
  } else if(sig == SIGSTOP){
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  } else {
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
  }
}

void runMonitor(pid_t child) {
  while (1) {
    int status;
    wait(&status);
    if (WIFEXITED(status)) {
      printf("exit %d\n", WEXITSTATUS(status));
      break;
    } else if (WIFSIGNALED(status)) {
      handleSIGNALED(child, status);
    } else if (WIFSTOPPED(status)) {
      handleSTOPPED(child, status);
    } else {
      printf("other %d\n", status);
      ptrace(PTRACE_CONT, child, NULL, NULL);
    }
  }
}

int main(int argc, char **argv) {
  pid_t child = fork();
  if (child == 0) {
    runChild(argv);
  } else {
    runMonitor(child);
  }
  return 0;
}