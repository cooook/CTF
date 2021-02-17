#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <linux/filter.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <malloc.h>


char buf[0x200]; 


int main() {
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    puts("Welcome to NUAA CTF");
    puts("You can solve this ezez problem!");
    read(0, buf, 0x200);
    ((void (*)())buf)();
    return 0; 
}