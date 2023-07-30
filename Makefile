
all: insert_mprotect mprotect

mprotect: mprotect.c int3.s
	clang mprotect.c int3.s -o mprotect

insert_mprotect: insert_mprotect.c ptrace.c
	clang ptrace.c insert_mprotect.c -o insert_mprotect