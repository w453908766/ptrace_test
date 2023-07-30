
.text
.global call_func
.global reg_info

call_func:
  call *%r14
  mov $4445, %r15
  mov %rax, %r14
  int $3
 
reg_info:
  mov $4444, %r15
  mov %rdi, %r14
  int $3
  ret

# as int3.s -o int3.o
# ld int3.o -o int3
