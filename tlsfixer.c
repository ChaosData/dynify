/*
Copyright (c) 2022 NCC Group.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// //$ gcc -std=c11 -Wall -Wextra -pedantic -fPIC -pie -fno-stack-protector -o tlsfixer tlsfixer.c
// $ gcc -std=c11 -Wall -Wextra -pedantic -fPIC -pie -o tlsfixer tlsfixer.c
// $ sudo ./tlsfixer "$(pgrep hmm)"

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

char* _strbat(char* dst, char* src) {
  size_t len = strlen(src);
  memcpy(dst, src, len+1);
  return &dst[len];
}

void print_status(int status) {
  if (WIFEXITED(status)) {
    printf("exited, status=%d\n", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    printf("killed by signal %d\n", WTERMSIG(status));
  } else if (WIFSTOPPED(status)) {
    printf("stopped by signal %d\n", WSTOPSIG(status));
  } else if (WIFCONTINUED(status)) {
    printf("continued\n");
  }
}

/*
static inline long _s2(long n, long a1, long a2) {
  unsigned long ret;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
                                  : "rcx", "r11", "memory");
  return ret;
}
void init_tls_auto() {
  void** fs = NULL;
  _s2(__NR_arch_prctl, 0x1003, (long)&fs);
  if (fs[0] == NULL) {
    fs[0] = (void*)fs;
  }
  if (fs[2] == NULL) {
    fs[2] = (void*)fs;
  }
  __asm__ (
    "int3\n"
  );
}
*/

struct linux_dirent {
  long d_ino;
  off_t d_off;
  uint16_t d_reclen;
  char d_name[];
};

int run_command(char const* command, char* out, size_t* len) {
  FILE *fp;

  fp = popen(command, "r");
  if (fp == NULL) {
    return 0;
  }

  size_t read = 0;
  size_t l = *len;
  while (read < l-1) {
    int c = fgetc(fp);
    if (c == EOF) {
      pclose(fp);
      break;
    }
    out[read] = (char)c;
    read++;
  }
  for (size_t i=read; i < l; i++) {
    out[i] = '\0';
  }
  *len = read;
  return 1;
}

uint8_t unhexc(char c) {
  if (c >= 0x30 && c <= 0x39) {
    return c - 0x30;
  } else if (c >= 0x61 && c <= 0x66) {
    return c + 10 - 0x61;
  }
  return 0;
}

uintptr_t unhex(char const* c, size_t n) {
  uintptr_t ret = 0;
  for (size_t i=0; i<n; i++) {
    ret = ret << 4;
    ret |= unhexc(c[i]);
  }
  return ret;
}

int fixup_tls(int tid, uintptr_t addr);

int main(int argc, char** argv) {
  int r = 0;
  if (argc < 2) {
    printf("usage: %s <pid>\n", (argc == 0) ? "tlsfixer" : argv[0]);
    return 1;
  }
  int pid = atoi(argv[1]);
  if (pid < 0) {
    printf("error: bad pid: %s\n", argv[1]);
    return 1;
  }

  char exe_path[4096];
  snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);

  // "/bin/sh" "-c" "readelf -s '/proc/<pid>/exe' | grep 'init_tls_auto' | awk '{print $2}'"
  char readelf_command[8192];
  snprintf(readelf_command, sizeof(readelf_command), "readelf -s '%s' | grep 'init_tls_auto' | awk '{print $2}'", exe_path);
  char init_tls_auto_off_str[32];
  size_t init_tls_auto_off_str_len = sizeof(init_tls_auto_off_str);

  if (!run_command(readelf_command, init_tls_auto_off_str, &init_tls_auto_off_str_len)) {
    printf("command failed: popen(\"%s\")\n", readelf_command);
    return 1;
  }
  //printf("init_tls_auto_off_str: %s\n", init_tls_auto_off_str);
  uintptr_t init_tls_auto_off = unhex(init_tls_auto_off_str, init_tls_auto_off_str_len-1);
  printf("init_tls_auto_off: 0x%lx\n", init_tls_auto_off);


  // readlink /proc/<pid>/exe
  char real_path[4096];
  r = readlink(exe_path, real_path, sizeof(real_path)-1);
  if (r <= 0) {
    return 1;
  }
  real_path[r] = '\0';

  printf("real_path: %s\n", real_path);

  // open /proc/<pid>/maps

  // "/bin/sh" "-c" "cat '/proc/<pid>/maps' | grep '<readlink>' | head -n 1 | sed 's/\-.*//g'"
  // read /proc/<pid>/maps for first line matching readlink /proc/<pid>/exe
  char maps_command[8192];
  snprintf(maps_command, sizeof(maps_command), "cat '/proc/%d/maps' | grep '%s' | head -n 1 | sed 's/\\-.*//g'", pid, real_path);
  char exe_base_addr_str[32];
  size_t exe_base_addr_str_len = sizeof(exe_base_addr_str);
  if (!run_command(maps_command, exe_base_addr_str, &exe_base_addr_str_len)) {
    printf("command failed: popen(\"%s\")\n", maps_command);
    return 1;
  }
  //printf("exe_base_addr_str: %s\n", exe_base_addr_str);
  uintptr_t exe_base_addr = unhex(exe_base_addr_str, exe_base_addr_str_len-1);
  printf("exe_base_addr: 0x%lx\n", exe_base_addr);

  uintptr_t init_tls_auto_addr = exe_base_addr + init_tls_auto_off;
  printf("init_tls_auto_addr: 0x%lx\n", init_tls_auto_addr);

  /*
  printf("attaching to pid %d\n", pid);
  r = syscall(__NR_ptrace, PTRACE_ATTACH, pid, NULL, NULL);
  if (r < 0) {
    printf("attach failed for pid %d\n", pid);
    return r;
  }
  syscall(__NR_ptrace, PTRACE_DETACH, pid, NULL, NULL);
  */
  //int mytid = gettid();
  //init_tls_auto(); // for own thread
  char path[4096];
  snprintf(path, sizeof(path), "/proc/%d/task/", pid);
  int fd = syscall(__NR_open, (long)path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);

  char buf[1024];
  struct linux_dirent *d = NULL;
  for ( ; ; ) {
    r = syscall(__NR_getdents, fd, (long)buf, 1024);
    if (r == -1) {
      return 2;
    }

    if (r == 0) {
      break;
    }

    for (int bpos = 0; bpos < r;) {
      d = (struct linux_dirent *) (buf + bpos);
      //puts(d->d_name);
      if (d->d_name[0] != '.') {
        int tid = atoi(d->d_name);
        printf("attaching to tid %d\n", tid);
        int rr = syscall(__NR_ptrace, PTRACE_SEIZE, tid, NULL, NULL);
        //printf("r: %d\n", r);
        if (rr < 0) {
          printf("attach failed for tid %d\n", tid);
          perror("ptrace");
          return r;
        }
        syscall(__NR_ptrace, PTRACE_INTERRUPT, tid, NULL, NULL);
        int status = 0;
        rr = syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);
        print_status(status);
        if (WIFEXITED(status)) {
          int exit_code = WEXITSTATUS(status);
          printf("tid %d exitied with code: %d\n", tid, exit_code);
        } else if (WIFSTOPPED(status)) {
          int stopsig = WSTOPSIG(status);
          if (stopsig != SIGTRAP) {
            printf("[1] unexpected stop signal for tid %d: %d\n", tid, stopsig);
          } else {
            fixup_tls(tid, init_tls_auto_addr);
          }
        }
        syscall(__NR_ptrace, PTRACE_DETACH, tid, NULL, NULL);
      }
      bpos += d->d_reclen;
    }
    //puts("post");
  }
  //puts("end");
  return 0;
}

int fixup_tls(int tid, uintptr_t addr) {
  int status = 0;
  struct user_regs_struct regs = {0};
  struct user_regs_struct regs_saved = {0};
  int r = syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs);
  if (r != 0) {
    printf("could not get regs for tid %d (%d)\n", tid, r);
    return 0;
  }
  //puts("got regs");
  memcpy(&regs_saved, &regs, sizeof(regs));
  //printf("rip: 0x%llx\n", regs.rip);

  struct user_regs_struct regs2 = {0};

  regs.rip = addr;
  regs.rsp -= 128;
  regs.rsp -= regs.rsp % 16;
  regs.orig_rax = -1;
  regs.rsp -= 8;
  syscall(__NR_ptrace, PTRACE_POKEDATA, tid, regs.rsp, 0x0f00);

  syscall(__NR_ptrace, PTRACE_SETREGS, tid, NULL, &regs);
  syscall(__NR_ptrace, PTRACE_CONT, tid, NULL, NULL);
  syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);
  if (WIFSTOPPED(status)) {
    int stopsig = WSTOPSIG(status);
    if (stopsig != SIGSEGV) {
      print_status(status);
      printf("(not sigsegv)\n");
      return 1;
    }
  }
  syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs2);
  //uintptr_t ret = regs2.rax;
  //printf("retval: 0x%lx\n", ret);

  syscall(__NR_ptrace, PTRACE_SETREGS, tid, NULL, &regs_saved);
  syscall(__NR_ptrace, PTRACE_CONT, tid, NULL, NULL);

  return 0;

  //
  puts("3");
  syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs2);
  printf("rip: 0x%llx\n", regs.rip);

  puts("4");
  if (r != 0) {
    printf("could not set regs for tid %d (%d)\n", tid, r);
    return 0;
  }
  puts("5");
  //syscall(__NR_ptrace, PTRACE_INTERRUPT, tid, NULL, NULL);
  //syscall(__NR_ptrace, PTRACE_SINGLESTEP, tid, NULL, NULL);
  syscall(__NR_ptrace, PTRACE_CONT, tid, NULL, NULL);
  puts("5b");
  syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);
  print_status(status);
  syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs2);
  printf("rip: 0x%llx\n", regs2.rip);

  regs.rip = addr;
  syscall(__NR_ptrace, PTRACE_SETREGS, tid, NULL, &regs);
  syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs2);
  printf("rip: 0x%llx\n", regs2.rip);

  syscall(__NR_ptrace, PTRACE_CONT, tid, NULL, NULL);
  puts("5b2");
  syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);

  //syscall(__NR_ptrace, PTRACE_SINGLESTEP, tid, NULL, NULL);
  puts("5c");
  //syscall(__NR_ptrace, PTRACE_DETACH, tid, NULL, NULL);
  //syscall(__NR_ptrace, PTRACE_SEIZE, tid, NULL, NULL);
  //syscall(__NR_ptrace, PTRACE_INTERRUPT, tid, NULL, NULL);
  puts("5d");
  syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);
  print_status(status);
  syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs2);
  printf("rip: 0x%llx\n", regs2.rip);

  if (regs2.rip == addr) {
    printf("matching!\n");
    syscall(__NR_ptrace, PTRACE_SINGLESTEP, tid, NULL, NULL);
    syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);
    print_status(status);
    syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs2);
    printf("rip: 0x%llx\n", regs2.rip);
    return 0;
  }

  syscall(__NR_ptrace, PTRACE_CONT, tid, NULL, NULL);
  puts("6");

  puts("7");
  r = syscall(__NR_wait4, tid, (long)&status, 0, (long)NULL);
  print_status(status);
  puts("8");
  /*
  if (WIFEXITED(status)) {
    int exit_code = WEXITSTATUS(status);
    printf("tid %d exitied with code: %d\n", tid, exit_code);
    return 0;
  }
  if (WIFSTOPPED(status)) {
    int stopsig = WSTOPSIG(status);
    if (stopsig != SIGTRAP) {
      printf("[2] unexpected stop signal for tid %d: %d\n", tid, stopsig);
      return 0;
    }
  } else {
    printf("tid %d not stopped?\n", tid);
    return 0;
  }
  */
  syscall(__NR_ptrace, PTRACE_GETREGS, tid, NULL, &regs);
  printf("rip: 0x%llx\n", regs.rip);

  puts("9");
  r = syscall(__NR_ptrace, PTRACE_SETREGS, tid, NULL, &regs_saved);
  puts("10");
  if (r != 0) {
    printf("could not reset regs for tid %d (%d)\n", tid, r);
    return 0;
  }
  puts("11");
  syscall(__NR_ptrace, PTRACE_CONT, tid, NULL, NULL);
  puts("12");
  return 1;
}
