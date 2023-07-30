
#include <execinfo.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

void call_func();
void reg_info(void**);

int open_write(void* address) { 
  printf("open write address %p to %lx\n", address, *(long*)address);
  size_t page_size = sysconf(_SC_PAGE_SIZE);
  size_t page_address = (size_t)address & ~(page_size-1);
  mprotect((void*)page_address, page_size, PROT_READ | PROT_WRITE);
  return 111;
}

int close_write(void* address) { 
  printf("close write address %p to %lx\n", address, *(long*)address);

  size_t page_size = sysconf(_SC_PAGE_SIZE);
  size_t page_address = (size_t)address & ~(page_size-1);
  mprotect((void*)page_address, page_size, PROT_READ);
  return 222;
}

__attribute__((constructor))
void reg(){
  void* info[] = {call_func, open_write, close_write};
  reg_info(info);
}

int main() {

  long pagesize = sysconf(_SC_PAGE_SIZE);
  char* buffer = memalign(pagesize, 4 * pagesize);
  printf("buffer address %p\n", buffer);

  buffer[10] = 'a';

  mprotect(buffer, pagesize, PROT_READ);

  buffer[10] = 'b';
  buffer[10] = 'c';
 
  printf("char is %c\n", buffer[10]);
  return 0;
}
