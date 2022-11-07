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

// //$ gcc -g -std=c11 -Wall -pie -fPIC -fno-stack-protector -Wl,-e_altstart -o hmm hmm.c -Wl,--no-as-needed -lpthread -Wl,--as-needed -DDEBUG
// $ gcc -g -std=c11 -Wall -pie -fPIC -fno-stack-protector -Wl,-e_altstart -o hmm hmm.c -pthread -DDEBUG
// //$ MALLOC_MMAP_THRESHOLD_=0 ./hmm ./static2 static2 aa bb
// $ ./hmm ./static2 static2 aa bb

// the forced -lpthread is for frida, which otherwise has an issue trying to
// load in libpthread itself, and ends up crashing the process

#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <pthread.h>

#include <sys/mman.h>

extern void _start(void* stack);
extern void _altsigreturn(void);

static void* entrypoint = NULL;
static size_t* raw_args = NULL;
#ifdef INPLACE_ARGV
static size_t* new_raw_args = NULL;
#endif

static void* stack_top = NULL;
static void* child_rsp = NULL;
static int proc_mem_fd = -1;
static void* init_stack_copy = NULL;
static size_t init_stack_size = 0;
static int child_pid = 0;
static void* last_segment = NULL;
static size_t last_segment_size = 0;

__asm__(
".text\n"
".global _altstart\n"
"_altstart:\n"
"	xor %rbp,%rbp\n"
"	push %rsp\n"
"	mov %rsp,%rdi\n"
"	push %rdx\n"
".weak _DYNAMIC\n"
".hidden _DYNAMIC\n"
//"	lea _DYNAMIC(%rip),%rdx\n"
//"	andq $-16,%rsp\n"
"	call _altstart_c\n"
//"	mov %rax, %rdi\n"
//"	lea _DYNAMIC(%rip),%rsi\n"
"	pop %rdx\n"
"	pop %rsp\n"
//"	addq 0x8, %rsp\n"
//"	jmp *%rax\n"
"	jmp _start\n"
"_altsigreturn:\n"
"	mov $15,%rax\n"
"	syscall\n"
);

static inline long _s0(long n) {
  unsigned long ret;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
  return ret;
}

static inline long _s1(long n, long a1) {
  unsigned long ret;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
  return ret;
}

static inline long _s2(long n, long a1, long a2) {
  unsigned long ret;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
                                  : "rcx", "r11", "memory");
  return ret;
}

static inline long _s3(long n, long a1, long a2, long a3) {
  unsigned long ret;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                                  : "rcx", "r11", "memory");
  return ret;
}

static inline long _s4(long n, long a1, long a2, long a3, long a4) {
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                                                "d"(a3), "r"(r10)
                                  : "rcx", "r11", "memory");
  return ret;
}

static inline long _s6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  unsigned long ret;
  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                                                "d"(a3), "r"(r10), "r"(r8), "r"(r9)
                                  : "rcx", "r11", "memory");
  return ret;
}

int _strlen(char const* s) {
  int r = 0;
  while (*s != '\0') {
    r++;
    s++;
  }
  return r;
}

void _print(int fd, char* s) {
  _s3(__NR_write, fd, (long)s, _strlen(s));
}

void _print2(int fd, char* s, size_t len) {
  _s3(__NR_write, fd, (long)s, len);
}

char const* _strchr(const char *s, int c) {
  if (c == '\0') {
    return &s[_strlen(s)];
  }
  while (*s != '\0') {
    if (*s == c) {
      return s;
    }
    s++;
  }
  return NULL;
}

void _memcpy(char* dst, char* src, size_t len) {
  for (size_t i=0; i<len; i++) {
    dst[i] = src[i];
  }
}

char* _strbat(char* dst, char* src) {
  size_t len = _strlen(src);
  _memcpy(dst, src, len+1);
  return &dst[len];
}

static int retval = 0;

uint8_t hn(uint8_t v) {
  if (v < 10) {
    return 0x30 + v; // 0-9
  } else if (v < 16) {
    return 0x41 - 10 + v; // A-F
  } else {
    return 0x3f; // ?
  }
}

uint8_t unhexc(char c) {
  //_print(1, "unhexc: ");
  //_print2(1, &c, 1);
  //_print(1, "\n");
  if (c >= 0x30 && c <= 0x39) {
    return c - 0x30;
  } else if (c >= 0x61 && c <= 0x66) {
    return c + 10 - 0x61;
  }
  _print(1, "wat\n");
  return 0;
}

uintptr_t unhex(char const* c, size_t n) {
  //_print(1, "unhex: ");
  //_print2(1, (char*)c, n);
  //_print(1, "\n");
  uintptr_t ret = 0;
  for (size_t i=0; i<n; i++) {
    ret = ret << 4;
    ret |= unhexc(c[i]);
  }
  return ret;
}

uintptr_t utos(uintptr_t val, int base, char* buf) {
  // min lengths:
  //  64 bit
  //   65 for binary incl NUL
  //   21 for decimal incl NUL
  //   17 for hex incl NUL
  //  32 bit
  //   33 for binary incl NUL
  //   11 for decimal incl NUL
  //   9 for hex incl NUL
  const char* space = "0123456789abcdef";
  char tmp[33];

  if (val == 0) {
    buf[0] = '0';
    buf[1] = '\0';
    return 1;
  }
  size_t i = 0;
  while (val > 0) {
    tmp[i] = space[val % base];
    val = val / base;
    i = i + 1;
  }
  for (size_t j=0; j <= i ; j++) {
    buf[j] = tmp[i-1-j];
  }
  buf[i+1] = '\0';
  return i+1;
}


int dupmapentry(int pid, char const* map_entry, int is_file) {
  //_print(1, "dupmapentry called\n");
  char const* e = map_entry;
  char const* hyphen = _strchr(e, '-');
  //uintptr_t start = unhex(e, 8);
  uintptr_t start = unhex(e, (uintptr_t)(hyphen-e));
  /*char buf[17];
  utos(start, 16, buf);
  _print(1, "start: 0x");
  _print(1, buf);
  _print(1, "\n");*/
  char const* space = _strchr(hyphen, ' ');
  uintptr_t end = unhex(&hyphen[1], (uintptr_t)(space-&hyphen[1]));
  /*utos(end, 16, buf);
  _print(1, "end: 0x");
  _print(1, buf);
  _print(1, "\n");*/

  int perms = 0x2; // 0;
  char const* perms_str = _strchr(map_entry, ' ');
  if (perms_str == NULL) {
    return 1;
  }
  perms_str = &perms_str[1];
  if (perms_str[0] == 'r') {
    perms |= 0x1; // PROT_READ
  }
  if (perms_str[1] == 'w') {
    perms |= 0x2; // PROT_WRITE
  }
  if (perms_str[2] == 'x') {
    perms |= 0x4; // PROT_EXEC
  }

  int fd = -1;
  off_t offset = 0;
  int flags = 0x2|0x10|0x100000; // MAP_PRIVATE|MAP_FIXED|MAP_FIXED_NOREPLACE

  if (is_file) {
    last_segment = (void*)start;
    last_segment_size = end-start;

    char const* off_str = _strchr(perms_str, ' ');
    if (off_str == NULL) {
      return 1;
    }
    off_str = &off_str[1];
    char const* off_end = _strchr(off_str, ' ');
    if (off_end == NULL) {
      return 1;
    }
    offset = unhex(off_str, (uintptr_t)(off_end-off_str));

    char const* filename = _strchr(e, '/');
    if (filename == NULL) {
      return 1;
    }
    fd = _s3(__NR_open, (long)filename, 0x00 /*O_RDONLY*/, 0);
    if (fd < 0) {
      return 1;
    }
  } else {
    flags |= 0x20; // MAP_ANONYMOUS
  }

  void* nentry = (void*)_s6(__NR_mmap, (long)start, (long)(end-start),
                            0x1|0x2, // PROT_READ|PROT_WRITE initially
                            flags, fd, offset);
  if (nentry != (void*)start) {
    if ((long)nentry < 0) {
      char buf[17];
      _print(2, "mmap failed: 0x");
      utos((uintptr_t)nentry, 16, buf);
      _print(2, buf);
      _print(2, "\n");
    } else {
      _print(2, "mmap didn't match\n");
    }
    return 1;
  }

  off_t r = _s3(__NR_lseek, proc_mem_fd, (long)start, 0 /*SEEK_SET*/);
  if (r < 0) {
    _print(2, "proc_mem_fd lseek failed\n");
    return 1;
  }
  long rr = _s3(__NR_read, proc_mem_fd, (long)nentry, (long)(end-start));
  if (rr < 0) {
    _print(2, "proc_mem_fd read failed\n");
    return 1;
  }
  rr = _s3(__NR_mprotect, (long)nentry, (long)(end-start), perms);
  if (rr < 0) {
    _print(2, "nentry mprotect failed\n");
    return 1;
  }

  return 0;
}

void doppel(char* exe, char** argv, char** envp) {
  int pid = _s0(__NR_fork);
  int r = 0;
  if (pid == 0) {
    //char const buf1[] = "pid == 0\n";
    //_s3(__NR_write, 1, (long)buf1, sizeof(buf1)-1);

    if (_s4(__NR_ptrace, PTRACE_TRACEME, 0, (long)NULL, (long)NULL) < 0) {
      char const buf[] = "error: failed to ptrace(PTRACE_TRACEME) in child\n";
      _s3(__NR_write, 2, (long)buf, sizeof(buf)-1);
      _s1(__NR_exit, 1);
    }

    _s3(__NR_execve, (long)exe, (long)argv, (long)envp);
    char const buf[] = "error: execve failed\n";
    _s3(__NR_write, 2, (long)buf, sizeof(buf)-1);
    _s1(__NR_exit, 1);
    return;
  } else {
    //_print(2, "pid != 0\n");

    if (pid == -1) {
      _print(2, "fork() failed\n");
      _s1(__NR_exit, 1);
    }

    int status = 0;
    //int r = syscall(__NR_wait4, -1, [{WIFSTOPPED(s) && WSTOPSIG(s) == SIGTRAP}], WNOHANG|__WALL, NULL) = 601813
    //int r = waitpid(pid, &status, 0);
    r = _s4(__NR_wait4, pid, (long)&status, 0, (long)NULL);
    (void)r;
    retval = status;

    if (WIFEXITED(status)) {
      _print(2, "error: doppel process exited 0x");
      int exit_code = WEXITSTATUS(status);
      uint8_t low = hn(exit_code & 0xf);
      uint8_t high = hn((exit_code & 0xf0) >> 4);
      _print2(2, (char*)&high, 1);
      _print2(2, (char*)&low, 1);
      _print(2, "\n");
      _s1(__NR_exit, 1);
    }
    if (WIFSTOPPED(status)) {
      int stopsig = WSTOPSIG(status);
      if (stopsig != SIGTRAP) {
        _print(2, "status: stopped from unknown signal 0x");
        uint8_t low = hn(stopsig & 0xf);
        uint8_t high = hn((stopsig & 0xf0) >> 4);
        _print2(2, (char*)&high, 1);
        _print2(2, (char*)&low, 1);
        _print(2, "\n");
        _s2(__NR_kill, pid, SIGKILL);
        _s1(__NR_exit, 1);
      }
    }

    //_print(1, "child pid: ");
    char n[9];
    utos(pid, 10, n);
    //_print(1, n);
    //_print(1, "\n");
    char path[32];
    _strbat(_strbat(_strbat(path, "/proc/"), n), "/maps");
    //_print(1, "path: ");
    //_print(1, path);
    //_print(1, "\n");

    int maps_fd = _s3(__NR_open, (long)path, O_RDONLY, 0);
    //utos(maps_fd, 16, n);
    //_print(1, "maps_fd: 0x");
    //_print(1, n);
    //_print(1, "\n");
    if (maps_fd < 0) {
      _print(2, "error processing ");
      _print(2, path);
      _print(2, ": failed to open\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    char maps[10000] = {0}; // 1000 seems like a good. a closer limit would be 1010 on x86_64, but 1000 is fine
    size_t line_count = 0;
    r = _s3(__NR_read, maps_fd, (long)maps, sizeof(maps)-1);
    maps[r] = '\0';
    int error = 0;
    if (r > 0 && r < sizeof(maps)-1) {
      char b = '\0';
      int r2 = _s3(__NR_read, maps_fd, (long)&b, 1);
      if (r2 != 0) {
        error = 2;
      }
    } else {
      error = 1;
    }
    if (error > 0) {
      _print(2, "error processing ");
      _print(2, path);
      if (error == 1) {
        _print(2, ": too large (likely not statically linked)\n");
      } else {
        _print(2, ": unknown\n");
      }
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    struct user_regs_struct regs = {0};
    if (_s4(__NR_ptrace, PTRACE_GETREGS, pid, (long)NULL, (long)&regs) < 0) {
      _print(2, "ptrace getregs failed\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }
    child_rsp = (void*)regs.rsp;

    char const* m = maps;
    char* clobber = NULL;
    while ((m = _strchr(m, '\n')) != NULL) {
      line_count++;
      clobber = &maps[m-maps];
      *clobber = '\0';
      m = &m[1];
    }
    if (line_count > 12) {
      _print(2, "error processing ");
      _print(2, path);
      _print(2, ": too many lines\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }
    /*_print(1, maps);
    _print(1, "\n");
    char nn[32];
    utos(_strlen(maps), 10, nn);
    _print(1, "maps len: ");
    _print(1, nn);
    _print(1, "\n");*/
    /*char nn[32];
    utos(line_count, 10, nn);
    _print(1, "maps line count: ");
    _print(1, nn);
    _print(1, "\n");*/

    utos(pid, 10, n);
    _strbat(_strbat(_strbat(path, "/proc/"), n), "/mem");
    proc_mem_fd = _s3(__NR_open, (long)path, O_RDONLY, 0);
    if (proc_mem_fd < 0) {
      _print(2, "error processing ");
      _print(2, path);
      _print(2, ": failed to open\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    m = maps;
    int heap_hit = 0;
    do {
      //_print(1, "line: ");
      //_print(1, (char*)m);
      //_print(1, "\n");
      if (_strchr(m, '/') == NULL) {
        //note: what we previously thought was an unlabeled spot we needed to
        //      copy was actually [heap]. it seems it just doesn't show up as
        //      such initially, though it is listed as [heap] when gdb is used
        //      to start the harness (but not other things like strace). this
        //      raises the question of what gdb is doing and how the kernel
        //      handles labeling of the [heap] mapping. if i had to guess,
        //      until a page is actually accessed in the range, the kernel
        //      hasn't really attempted to allocate anything and so it hasn't
        //      been initialzed and doesn't have a label yet. gdb is probably
        //      greedily attaching to fork children even if it's not set to
        //      follow the child and then accessing its memory. in doing so, it
        //      probably touches the heap and triggers its initialization by
        //      the kernel.
        //
        //      looking at the ptrace syscalls gdb makes, this is likely
        //      exactly what is happening (and even happens w/ `--nh`). so this
        //      could be an interesting sort of debugger detection, whereby you
        //      create a child, ptrace it, stop it right after execve, and
        //      check if its [heap] entry has been initialized. if it has been,
        //      then you're not alone.
        /*
        ptrace(PTRACE_PEEKTEXT, 91461, 0x7ffff7fd37b0, [0x95e8cc0000da2be8]) = 0
        ptrace(PTRACE_POKEDATA, 91461, 0x7ffff7fd37b0, 0x95e8900000da2be8) = 0
        ptrace(PTRACE_PEEKTEXT, 91461, 0x7ffff7fe5098, [0x8bcc0174ed854500]) = 0
        ptrace(PTRACE_POKEDATA, 91461, 0x7ffff7fe5098, 0x8b900174ed854500) = 0
        ptrace(PTRACE_PEEKTEXT, 91461, 0x7ffff7fe63f0, [0xc43d83ccffffadec]) = 0
        ptrace(PTRACE_POKEDATA, 91461, 0x7ffff7fe63f0, 0xc43d8390ffffadec) = 0
        [Detaching after fork from child process 91461]
        ptrace(PTRACE_POKEUSER, 91461, offsetof(struct user, u_debugreg) + 56, NULL) = 0
        ptrace(PTRACE_SETOPTIONS, 91461, NULL, 0) = 0
        ptrace(PTRACE_SINGLESTEP, 91461, NULL, 0) = 0
        --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=91461, si_uid=1000, si_status=SIGTRAP, si_utime=0, si_stime=0} ---
        ptrace(PTRACE_DETACH, 91461, NULL, 0)   = 0
        pid == 0
        ptrace(PTRACE_CONT, 91457, 0x1, 0)      = 0
        pid != 0
        --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_TRAPPED, si_pid=91457, si_uid=1000, si_status=SIGCHLD, si_utime=0, si_stime=0} ---
        ptrace(PTRACE_CONT, 91457, 0x1, SIGCHLD) = 0
        child pid: 91461
        */
        if (heap_hit) {
          break;
        }
        heap_hit = 1;
      }
      //_print(1, (char*)m);
      //_print(1, "\n");
      if (dupmapentry(pid, m, !heap_hit)) {
        _print(2, "dupmapentry failed\n");
        _s2(__NR_kill, pid, SIGKILL);
        _s1(__NR_exit, 1);
      }
    } while ((m = _strchr(m, '\0')) != NULL && (m = &m[1]));

    //_print(1, "post dupmapentry loop\n");
    do {
      //then we need to get the [stack] addresses
      //_print(1, "?: ");
      //_print(1, m);
      //_print(1, "\n");
      char const* label = _strchr(m, '[');
      if (label == NULL) {
        continue;
      }
      if ((label[1] != 's' && label[2] != 't')
          /*&& (label[1] != 'v' && label[2] != 'd')*/) {
        continue;
      }
      //_print(1, "stack_top_raw_str: ");
      //_print2(1, &m[9], 8);
      //_print(1, "\n");
      //stack_top = (void*)unhex(&m[9], 8);

      char const* hyphen = _strchr(m, '-');
      char const* space = _strchr(hyphen, ' ');
      //_print(1, "&hyphen[1]: ");
      //_print(1, &hyphen[1]);
      //_print(1, "\n");
      stack_top = (void*)unhex(&hyphen[1], (uintptr_t)(space-&hyphen[1]));
      break;
    } while ((m = _strchr(m, '\0')) != NULL && (m = &m[1]));

    if (stack_top == NULL) {
      _print(2, "stack_top was not set\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    // we need to make space to copy rsp->stack_top into the harness stack
    // then we need to update the pointers.
    // the end of the auxvex is 0x0000000000000000 0x0000000000000000.
    // we therefore iterate each 64-bit value from rsp up to stack_top,
    // stopping at the first such sequence to get the start of the
    // argv/envp/auxvec data. for each value in the range of rsp to AEA data,
    // we check if the value exists in the range of AEA data to stack_top and
    // offset them accordingly to their new location.
    // but the main problem is that we can't do proper stack manipulation from
    // inside c code using the stack. the "proper" way to do this would be to
    // mmap the allocation in c, then copy that to a local c stack post from
    // main+ after libc has fully init'd, and then set rsp with it.

    // nooooope: , and then copy it into the stack from asm after
    // _altstart_c returns. or to try to memmove it from the location on the c
    // stack after the frame returns. but as the latter already risks
    // optimizations causing problems and lots of undefined behavior, we might
    // as well do it the yolo way: copy to the local c stack, save a pointer to
    // global storage, and then use asm to move rsp after _altstack_c returns.
    // the problem with this is we'd need to do it dead last in _altstart_c
    // so that the post-doppel call code from _altstart_c doesn't clobber it.
    // ^ too much work to deal w/ also having _our_ libc init properly.

    /*char buf3[128];
    _print(1, "stack_top: 0x");
    utos((uintptr_t)stack_top, 16, buf3);
    _print(1, buf3);
    _print(1, "\nchild_rsp: 0x");
    utos((uintptr_t)child_rsp, 16, buf3);
    _print(1, buf3);
    _print(1, "\n");*/
    init_stack_size = stack_top - child_rsp;
    /*_print(1, "init_stack_size: 0x");
    utos(init_stack_size, 16, buf3);
    _print(1, buf3);
    _print(1, "\n");*/

    init_stack_copy = (void*)_s6(__NR_mmap, (long)NULL, (long)init_stack_size,
                            0x1|0x2, // PROT_READ|PROT_WRITE
                            0x2|0x20 /*MAP_SHARED|MAP_ANONYMOUS*/,
                            -1, 0);
    if ((uintptr_t)init_stack_copy > -4096UL) {
      _print(2, "init stack copy mmap failed\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    off_t r = _s3(__NR_lseek, proc_mem_fd, (long)child_rsp, 0 /*SEEK_SET*/);
    if (r < 0) {
      _print(2, "proc_mem_fd lseek failed\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    long rr = _s3(__NR_read, proc_mem_fd, (long)init_stack_copy, (long)init_stack_size);
    if (rr < 0) {
      _print(2, "proc_mem_fd read failed\n");
      _s2(__NR_kill, pid, SIGKILL);
      _s1(__NR_exit, 1);
    }

    uintptr_t copy_off = (uintptr_t)init_stack_copy - (uintptr_t)child_rsp;
    void** cursor = &(((void**)init_stack_copy)[1]);
    void* init_stack_copy_data_start = NULL;
    void* init_stack_copy_data_end = init_stack_copy + init_stack_size;
    while (1) {
      if (cursor[0] == NULL && cursor[1] == NULL) {
        init_stack_copy_data_start = &cursor[2];
        break;
      }
      cursor = &cursor[1];
    }

    void* init_stack_data_start = init_stack_copy_data_start - copy_off;
    void* init_stack_data_end = init_stack_copy_data_end - copy_off;

    // child: [0x1005] 0x1080 , ... , [0x1080] 'f', [0x1081] 'o', [0x1082] 'o', [0x1083] '\0'
    // host0: [0x12005] 0x1080 , ... , [0x12080] 'f', [0x12081] 'o', [0x12082] 'o', [0x12083] '\0'
    // host1: [0x12005] 0x12080 , ... , [0x12080] 'f', [0x12081] 'o', [0x12082] 'o', [0x12083] '\0'
    // val + (host_base - child_base)
    /*
    char str[128];
    _print(1, ">>>>\ninit_stack_copy: 0x");
    utos((uintptr_t)init_stack_copy, 16, str);
    _print(1, str);
    _print(1, "\n");
    _print(1, "child_rsp: 0x");
    utos((uintptr_t)child_rsp, 16, str);
    _print(1, str);
    _print(1, "\n");
    _print(1, "copy_off: 0x");
    utos((uintptr_t)copy_off, 16, str);
    _print(1, str);
    _print(1, "\n");

    _print(1, "init_stack_copy_data_start: 0x");
    utos((uintptr_t)init_stack_copy_data_start, 16, str);
    _print(1, str);
    _print(1, "\n");
    _print(1, "init_stack_copy_data_end: 0x");
    utos((uintptr_t)init_stack_copy_data_end, 16, str);
    _print(1, str);
    _print(1, "\n");

    _print(1, "init_stack_data_start: 0x");
    utos((uintptr_t)init_stack_data_start, 16, str);
    _print(1, str);
    _print(1, "\n");
    _print(1, "init_stack_data_end: 0x");
    utos((uintptr_t)init_stack_data_end, 16, str);
    _print(1, str);
    _print(1, "\n");
    */
    for (cursor = init_stack_copy;
         (uintptr_t)cursor < (uintptr_t)init_stack_copy_data_start;
         cursor = &cursor[1]) {
      /*_print(1, "cursor: 0x");
      utos((uintptr_t)cursor, 16, str);
      _print(1, str);
      _print(1, "\n");
      _print(1, "*cursor: 0x");
      utos((uintptr_t)*cursor, 16, str);
      _print(1, str);
      _print(1, "\n");*/
      if (*cursor > init_stack_data_start
          && *cursor < init_stack_data_end) {
        *cursor = *cursor + copy_off;
        //_print(1, "test: ");
        //_print(1, *cursor);
        //_print(1, "\n");
      }
    }

    void* init_stack_copy_auxvec_start = NULL;
    cursor = init_stack_copy + sizeof(void*);
    for (int count = 0;
         (uintptr_t)cursor < (uintptr_t)init_stack_copy_data_start;
         cursor = &cursor[1]) {
      if (*cursor == NULL) {
        count++;
        if (count == 2) {
          init_stack_copy_auxvec_start = &cursor[1];
          break;
        }
      }
    }

    void* my_auxvec_start = NULL;
    cursor = (void**)&raw_args[1];
    for (int count = 0; cursor[0] != NULL || cursor[1] != NULL; cursor = &cursor[1]) {
      if (*cursor == NULL) {
        count++;
        if (count == 2) {
          my_auxvec_start = &cursor[1];
          break;
        }
      }
    }

    //we also need to correct a few auxvec values manually
    // 33 (0x21): AT_SYSINFO_EHDR (vdso location)
    // 25 (0x19): AT_RANDOM
    // 31 (0x1f): AT_EXECFN
    // 15 (0x0f): AT_PLATFORM
    void* vdso = NULL;
    void* at_random = NULL;
    char const* at_execfn = (char const*)raw_args[1];
    char const* at_platform = "x86_64";

    for (cursor = my_auxvec_start; cursor[0] != NULL || cursor[1] != NULL; cursor = &cursor[2]) {
      if ((uintptr_t)cursor[0] == 33) {
        vdso = cursor[1];
      } else if ((uintptr_t)cursor[0] == 25) {
        at_random = cursor[1];
      }
    }
    if (vdso == NULL) {
      _print(2, "vdso == NULL\n");
    }
    if (at_random == NULL) {
      _print(2, "at_random == NULL\n");
    }
    //if (vdso != NULL && at_random != NULL) {
    //  _print(1, "vdso and at_random != NULL\n");
    //}

    cursor = init_stack_copy + sizeof(void*);
    for (cursor = init_stack_copy_auxvec_start;
         (uintptr_t)cursor < (uintptr_t)init_stack_copy_data_start;
         cursor = &cursor[2]) {
      switch ((uintptr_t)cursor[0]) {
        case 33:
          cursor[1] = vdso;
          break;
        case 25:
          cursor[1] = at_random;
          break;
        case 31:
          cursor[1] = (void*)at_execfn;
          break;
        case 15:
          cursor[1] = (void*)at_platform;
          break;
      }
    }


    //_print(1, "wat\n");

    child_pid = pid;
    entrypoint = (void*)regs.rip;
// starti: rsp: 0x00007FFFFFFFE060
// _altsc: rsp: 0x00007FFFFFFFE048
//   main: rsp: 0x00007FFFFFFFDF88
  }
}

/*
#define SA_RESTORER 0x04000000
struct real_sigaction {
  void (*_sa_sigaction)(int,siginfo_t*,void*);
  unsigned long _sa_flags;
  void (*_sa_restorer)(void);
  sigset_t _sa_mask;
};

void signal_handler(int sig, siginfo_t *info, void *ucontext);
*/

int _memcmp(char const* a, char const* b, size_t n) {
  if ((a == NULL && b != NULL)
      || (a != NULL && b == NULL)) {
    return 0;
  }
  for (size_t i=0; i < n; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

int _strncmp(char const* needle, char const* haystack, size_t _n) {
  if (needle == NULL || haystack == NULL) {
    return 0;
  }
  size_t n = _strlen(needle);
  if (n > _n) {
    n = _n;
  }
  if (n > _strlen(haystack)) {
    return 0;
  }
  return _memcmp(needle, haystack, n);
}

int _strcmp(char const* needle, char const* haystack) {
  return _strncmp(needle, haystack, (size_t)-1);
}

void* _altstart_c(size_t** _raw_args) {
  //_s1(__NR_exit, 2);
  /* size_t* */ raw_args = *_raw_args;
  int argc = (int)raw_args[0];
  char** argv = (char**)&raw_args[1];
  char** envp = (char**)&raw_args[1+argc+1];

  if (argc == 0) {
    _print(2, "error: argc == 0?\n");
    _s1(__NR_exit, 1);
  } else if (argc < 2) {
    _print(2, "usage: ");
    _print(2, argv[0]);
    _print(2, " <exe_path> [argv...]\n");
    _s1(__NR_exit, 1);
  }

  // add MALLOC_MMAP_THRESHOLD_=0 so our (g)libc doesn't use the [heap]
  int has_malloc_mmap_threshold_zero = 0;
  for (char** e = envp; *e != NULL; e++) {
    //_print(1, *e);
    //_print(1, "\n");
    if (_strncmp("MALLOC_MMAP_THRESHOLD_=0", *e, 25)) { //include NUL
      //_print(1, "found!\n");
      has_malloc_mmap_threshold_zero = 1;
      break;
    }
    has_malloc_mmap_threshold_zero--;
  }
  if (has_malloc_mmap_threshold_zero <= 0) {
    //_print(1, "re-execing w/ MALLOC_MMAP_THRESHOLD_=0\n");
    int envps = -has_malloc_mmap_threshold_zero;
    envp[envps] = "MALLOC_MMAP_THRESHOLD_=0";
    envp[envps+1] = NULL;
    _s3(__NR_execve, (long)argv[0], (long)argv, (long)envp);
  }

  //syscall(__NR_exit, 0);

  // patch up
  char* exe = argv[1];
  char** nargv = &argv[2];
  #ifdef INPLACE_ARGV
  int nargc = argc - 2;
  raw_args[0] = nargc;
  raw_args[1] = (size_t)(void*)nargv;
  #endif

  /*
  char buf[8] = {'a','r','g','c',':',' ',0,'\n'};
  buf[6] = 0x30 + argc;
  _print2(1, buf, 8);

  for (size_t i=0; i<argc; i++) {
    char buf2[9] = {'a','r','g','v','[',0,']',':',' '};
    buf2[5] = 0x30 + i;
    _print2(1, buf2, 9);

    _print(1, argv[i]);
    _print(1, "\n");
  }
  */

  doppel(exe, nargv, envp);

  //can't just patch up existing one, need to copy full args/env/auxvec
  #ifdef INPLACE_ARGV
  *_raw_args = &raw_args[2];
  (*_raw_args)[0] = nargc;
  new_raw_args = *_raw_args;
  #endif

  #ifdef DEBUG
  _print(1, "[debug] waiting for input...\n");
  char c;
  int r = -4; // EINTR
  while (r == -4 || r == 0) {
    r = _s3(__NR_read, 0, (long)&c, 1);
    char rrr[64];
    utos(r, 8, rrr);
    _print(1, "read: 0x");
    _print(1, rrr);
    _print(1, "\n");
  }
  _print(1, "continuing...\n");
  #endif

  int status = 0;
  _s2(__NR_kill, child_pid, SIGKILL);
  syscall(__NR_ptrace, PTRACE_DETACH, child_pid, NULL, NULL);
  _s4(__NR_wait4, child_pid, (long)&status, 0, (long)NULL);


  //syscall(60, 0);
  //_s1(__NR_exit, 45);
  return entrypoint; //raw_args;
}

/*
void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    char const buf[] = "signal_handler called\n";
    syscall(__NR_write, 1, buf, sizeof(buf)-1);
}*/

#define PR_SET_SYSCALL_USER_DISPATCH 59
#define PR_SYS_DISPATCH_OFF 0
#define PR_SYS_DISPATCH_ON 1
#define SYSCALL_DISPATCH_FILTER_ALLOW 0
#define SYSCALL_DISPATCH_FILTER_BLOCK 1

static /*const*/ uint8_t selector = SYSCALL_DISPATCH_FILTER_BLOCK;

typedef struct pages {
  uint8_t guard1[4096];
  struct {
    uint8_t syscall[4096];
    uint8_t syscall_clone[4096];
    uint8_t syscall4[4096];
    uint8_t rt_sigreturn[4096];
  } syscalls;
  uint8_t guard2[4096];
} pages_t;

#define SA_RESTORER 0x04000000
struct real_sigaction {
  void (*_sa_sigaction)(int,siginfo_t*,void*);
  unsigned long _sa_flags;
  void (*_sa_restorer)(void);
  sigset_t _sa_mask;
};

static pages_t* pages = NULL;
long syscall4_wrapper(long n, long a1, long a2, long a3, long a4) {
  long(*_syscall)(long,long,long,long,long) = (long(*)(long,long,long,long,long))&pages->syscalls.syscall4;
  return (*_syscall)(a1,a2,a3,a4,n);
}

void stdout_print(char const* str) {
  syscall4_wrapper(__NR_write, 1, (long)str, _strlen(str), 0);
}

void exit_wrapper(int code, void* _arg) {
  syscall4_wrapper(__NR_exit, code, 0, 0, 0);
}

static void* hmm_tls = NULL;
static void* static_tls = NULL;
//static int arch_prctl_archsetfs_hit = 0;
static void* syscall_addr = NULL;
static void* syscall_clone_addr = NULL;

uintptr_t forward_syscall(greg_t *regs, void* _syscall_addr) {
  uintptr_t rax = regs[REG_RAX];
  uintptr_t rdi = regs[REG_RDI];
  uintptr_t rsi = regs[REG_RSI];
  uintptr_t rdx = regs[REG_RDX];
  uintptr_t r10 = regs[REG_R10];
  uintptr_t r8 = regs[REG_R8];
  uintptr_t r9 = regs[REG_R9];
  if (rax == __NR_clone) {
    //rdi |= 0x00002000;
    uintptr_t* stack = (uintptr_t*)rsi;
    if (*stack == 0) {
      stack -= 0x8;
      *stack = regs[REG_RIP];
      rsi = (uintptr_t)stack;
    }
  }
  uintptr_t ret = 0;
  __asm__ (
    "mov %0, %%rax\n"
    "mov %1, %%rdi\n"
    "mov %2, %%rsi\n"
    "mov %3, %%rdx\n"
    "mov %4, %%r10\n"
    "mov %5, %%r8\n"
    "mov %6, %%r9\n"
    "mov %7, %%rcx\n"
    "call *%%rcx\n"
    "mov %%rax, %8\n"
    :
    : "memory"(rax), "memory"(rdi), "memory"(rsi), "memory"(rdx),
      "memory"(r10), "memory"(r8), "memory"(r9),
      "memory"(_syscall_addr), "memory"(ret)
    : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx"
  );
  return ret;
}


void init_tls(void** fs) {
  if (fs[0] == NULL) {
    fs[0] = (void*)fs;
  }
  if (fs[2] == NULL) {
    fs[2] = (void*)fs;
  }
}

uint64_t init_tls_auto() {
  _print(1, "init_tls_auto() called\n");
  void** r = NULL;
  _s2(__NR_arch_prctl, 0x1003, (long)&r);
  init_tls(r);
  return 0x41424344;
}

struct linux_dirent {
  long d_ino;
  off_t d_off;
  uint16_t d_reclen;
  char d_name[];
};

/*
int init_tls_all() {
  int mypid = getpid();
  int r = 0;
  r = _s4(__NR_ptrace, PTRACE_ATTACH, mypid, (long)NULL, (long)NULL);
  if (r < 0) {
    return r;
  }
  //int mytid = gettid();
  init_tls_auto(); // for own thread
  char path[4096];
  char n[128];
  utos(mypid, 10, n);
  _strbat(_strbat(_strbat(path, "/proc/"), n), "/task/");
  int fd = _s2(__NR_open, (long)path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);

  char buf[1024];
  struct linux_dirent *d = NULL;
  for ( ; ; ) {
    r = _s3(__NR_getdents, fd, (long)buf, 1024);
    if (r == -1) {
      return 2;
    }

    if (r == 0) {
      break;
    }

    for (int bpos = 0; bpos < r;) {
      d = (struct linux_dirent *) (buf + bpos);
      printf("%s\n", d->d_name);
      bpos += d->d_reclen;
    }
  }

  syscall(__NR_ptrace, PTRACE_DETACH, mypid, NULL, NULL);
  return 0;
}
*/

//not used
static void syscall_handler(int sig, siginfo_t *info, void *ucontext) {
  //volatile int foo = 0;
  //stdout_print("got a syscall\n");

  ucontext_t *context = (ucontext_t *)ucontext;
  greg_t *regs = context->uc_mcontext.gregs;
  //void* fpregs = context->uc_mcontext.fpregs;

  char buf[256];
  //snprintf(buf, sizeof(buf), "fpregs: %p, foo: %p\n", fpregs, &foo);
  //stdout_print(buf);

  uint64_t rip = regs[REG_RIP];

  uint64_t rax = regs[REG_RAX];
  uint64_t rdi = regs[REG_RDI];
  uint64_t rsi = regs[REG_RSI];
  uint64_t rdx = regs[REG_RDX];
  uint64_t r10 = regs[REG_R10];
  uint64_t r8 = regs[REG_R8];
  uint64_t r9 = regs[REG_R9];
  uint64_t *rsp = (uint64_t *)regs[REG_RSP];

  //stdout_print("syscall: \n");
  //print_syscall(rax, &stdout_print);
  snprintf(buf, sizeof(buf), "rip: 0x%lx, rax: 0x%lx, rdi: 0x%lx, rsi: 0x%lx, rdx: 0x%lx, \n"
                             "r10: 0x%lx, r8: 0x%lx, r9: 0x%lx, rsp: %p\n",
           rip, rax, rdi, rsi, rdx, r10, r8, r9, rsp);
  //stdout_print(buf);
  if (rax == __NR_arch_prctl && rdi == 0x1002) {
    stdout_print("got arch_prctl(ARCH_SET_FS)\n");
    static_tls = (void*)rsi;
    //init_tls(static_tls);
  } else if (rax == __NR_vfork) {
    stdout_print("vfork!\n");
  } else if (rax == __NR_clone) {
    stdout_print("clone!\n");
    //regs[REG_R9] = regs[REG_RIP];
    regs[REG_RAX] = forward_syscall(regs, syscall_clone_addr);
    regs[REG_EFL] = 0;
    return;
  } else if (rax == __NR_rt_sigaction && rdi == SIGSYS && rsi != 0) {
    stdout_print("(ignoring) rt_sigaction(SIGSYS, !null)!\n");
    regs[REG_EFL] = 0;
    regs[REG_RAX] = 0;
    return;
  }
  regs[REG_RAX] = forward_syscall(regs, syscall_addr);
  regs[REG_EFL] = 0;
  //snprintf(buf, sizeof(buf), "-> 0x%lx\n", (uint64_t)regs[REG_RAX]);
  //stdout_print(buf);

/*
  if (!arch_prctl_archsetfs_hit) {
    if (rax == __NR_arch_prctl && rdi == 0x1002) { // ARCH_SET_FS
      stdout_print("got arch_prctl(ARCH_SET_FS)\n");
      static_tls = (void*)rsi;
      ((void**)static_tls)[0] = static_tls;
      ((void**)static_tls)[2] = static_tls;
      arch_prctl_archsetfs_hit = 1;
      //regs[REG_RAX] = (uint64_t)0; // we need to let it go through
      //return;
    }
  } else {
    snprintf(buf, sizeof(buf), "(not) overriding tls. hmm_tls: %p\n", hmm_tls);
    stdout_print(buf);
    selector = SYSCALL_DISPATCH_FILTER_ALLOW;
    //syscall4_wrapper(__NR_arch_prctl, 0x1002, (long)hmm_tls, 0, 0);
    //prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_OFF, NULL, 0, NULL);
  }
  regs[REG_RAX] = syscall4_wrapper(rax, rdi, rsi, rdx, r10);
  snprintf(buf, sizeof(buf), "-> 0x%lx\n", (uint64_t)regs[REG_RAX]);
  stdout_print(buf);
*/
}
void setup_syscall_harness() {
  pages = (pages_t*)mmap(NULL, sizeof(pages_t), PROT_NONE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
  if (pages == (void*)-1) {
    perror("mmap");
    exit(1);
  }

  if(mprotect(&pages->syscalls, sizeof(pages->syscalls), PROT_READ|PROT_WRITE) != 0) {
    perror("mprotect1");
    exit(1);
  }

  //note: this is not a sandbox, code could just jump to the syscall instruction w/ arbitrary values
  char const syscall_shellcode[] = ""
    "\x0f\x05" // syscall
    "\xc3" // ret
  ;
  memset(&pages->syscalls.syscall, '\xf4', 4096);
  memcpy(&pages->syscalls.syscall, syscall_shellcode, sizeof(syscall_shellcode)-1);
  syscall_addr = &pages->syscalls.syscall;

  /*char const syscall_clone_shellcode_[] = ""
    "\x0f\x05" // syscall
    "\x48\x85\xc0" // test rax, rax
    "\xeb\xfe" // loop
    // jmp skip to child code
    "\x74\x01" // jz 3
    // parent code
    "\xc3" // ret
    // child code
    "\x4c\x89\xcf" // mov rdi, r9
    "\xff\xe7" // jmp rdi
  ;*/
  char const syscall_clone_shellcode[] = ""
    "\x0f\x05" // syscall
    "\xc3" // ret
    "\x48\x85\xc0" // test rax, rax
    // jmp skip to child code
    "\x74\x01" // jz 3
    // parent code
    "\xc3" // ret
    // child code
    "\xeb\xfe" // loop
    "\xc3" // ret
    //"\x4c\x89\xcf" // mov rdi, r9
    //"\xff\xe7" // jmp rdi
  ;

  memset(&pages->syscalls.syscall_clone, '\xf4', 4096);
  memcpy(&pages->syscalls.syscall_clone, syscall_clone_shellcode, sizeof(syscall_clone_shellcode)-1);
  syscall_clone_addr = &pages->syscalls.syscall_clone;

  char const syscall4_shellcode[] = ""
    "\x49\x89\xca" // mov r10, rcx
    "\x4c\x89\xc0" // mov rax, r8
    "\x48\x31\xc9" // xor rcx, rcx
    "\x4d\x31\xc0" // xor r8, r8
    "\x0f\x05" // syscall
    "\xc3" // ret
  ;
  memset(&pages->syscalls.syscall4, '\xf4', 4096);
  memcpy(&pages->syscalls.syscall4, syscall4_shellcode, sizeof(syscall4_shellcode)-1);

  char const rt_sigreturn_shellcode[] = ""
    "\x48\xc7\xc0\x0f\x00\x00\x00" // mov rax, 0xf
    "\x0f\x05" // syscall
  ;
  memset(&pages->syscalls.rt_sigreturn, '\xf4', 4096);
  memcpy(&pages->syscalls.rt_sigreturn, rt_sigreturn_shellcode, sizeof(rt_sigreturn_shellcode)-1);

  if(mprotect(&pages->syscalls, sizeof(pages->syscalls), PROT_READ|PROT_EXEC|PROT_WRITE) != 0) {
    perror("mprotect2");
    exit(1);
  }

  // we can't use the glibc sigaction b/c it injects its own garbage
  // rt_sigreturn syscall that we can't trust

  struct real_sigaction rs = {0};
  sigset_t mask;
  sigemptyset(&mask);

  rs._sa_sigaction = syscall_handler;
  rs._sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTORER;
  rs._sa_mask = mask;
  rs._sa_restorer = (void(*)(void))&pages->syscalls.rt_sigreturn;

  if (syscall(__NR_rt_sigaction, SIGSYS, &rs, NULL, 8) != 0) {
    perror("sigaction");
    exit(1);
  }

  on_exit(exit_wrapper, NULL);

  //printf("sizeof(sigset_t): %lu\n", sizeof(sigset_t));
  //printf("sizeof(__sigset_t): %lu\n", sizeof(__sigset_t));
  //printf("__NSIG_BYTES: %lu\n", __NSIG_BYTES);

  //uint8_t selector = SYSCALL_DISPATCH_FILTER_BLOCK;
  prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, &pages->syscalls, sizeof(pages->syscalls), &selector);
}

void enter(void* stack_slot) {
  __asm__ (
    "	mov %0, %%rsp\n"
    "	mov %1, %%rax\n"
    "   push %%rax\n"
    "   xor %%rax, %%rax\n"
    "   xor %%rbx, %%rbx\n"
    "   xor %%rbp, %%rbp\n"
    "   xor %%rdi, %%rdi\n"
    "   xor %%rsi, %%rsi\n"
    "   xor %%rdx, %%rdx\n"
    "   xor %%rcx, %%rcx\n"
    "   xor %%r8, %%r8\n"
    "   xor %%r9, %%r9\n"
    "   xor %%r10, %%r10\n"
    "   xor %%r11, %%r11\n"
    "   xor %%r12, %%r12\n"
    "   xor %%r13, %%r13\n"
    "   xor %%r14, %%r14\n"
    "   xor %%r15, %%r15\n"
    "	ret\n"
    :
    : "r"(stack_slot), "r"(entrypoint)
    : "%rax"
  );
}

void inner() {
  void* stack_slot = alloca(init_stack_size);
  memcpy(stack_slot, init_stack_copy, init_stack_size);
  char** envp = NULL;
  for (envp = &((char**)stack_slot)[1]; *envp != NULL; envp++) { }
  envp = &envp[1];
  for (char** e = envp; *e != NULL; e++) {
    // we just lazily clobber our MALLOC_MMAP_THRESHOLD_=0 instead of shifting
    // everything around. if you actually want something equivalent to be
    // processed by the static bin, just add MALLOC_MMAP_THRESHOLD_=1
    if(_strncmp("MALLOC_MMAP_THRESHOLD_=0", *e, 25)) {
      _memcpy(*e, "______________________", 22);
      break;
    }
  }

  //(void)_s3(__NR_mprotect, (long)last_segment, (long)last_segment_size, 0x1|0x2);

  //memset((void*)0x402717, 0x90, 5);

  // rbx, r9, r10, r12, r13 need to be 0 but aren't
  // clearing them manually doesn't fix r9 which is set from rdx
  // clearing rdx makes it work

  // technically working
  /*
  __asm__ (
    "	mov %0, %%rax\n"
    "	mov %1, %%rsp\n"
    "   xor %%rbx, %%rbx\n"
    "   xor %%rdx, %%rdx\n"
    "   xor %%r9, %%r9\n"
    "   xor %%r10, %%r10\n"
    "   xor %%r12, %%r12\n"
    "   xor %%r13, %%r13\n"
    "	jmp *%%rax\n"
    :
    : "r"(entrypoint), "r"(stack_slot)
    : "%rax"
  );
  */

  // too many issues w/ golang and how it handles clone/signal handlers
  // will attempt to muck aroud w/ this later.
  //setup_syscall_harness();

  enter(stack_slot);
}

pthread_key_t glob_var_key;
int* foo_p = NULL;

void* thread1(void* arg) {
  printf("thread1: arg=%s\n", (char*)arg);
  pthread_setspecific(glob_var_key, foo_p);
  int* glob_spec_var = pthread_getspecific(glob_var_key);
  printf("Thread %d before mod value is %d\n", (unsigned int) pthread_self(), *glob_spec_var);
  *glob_spec_var += 1;
  printf("Thread %d after mod value is %d\n", (unsigned int) pthread_self(), *glob_spec_var);
  return NULL;
}

void* test1() {
  return (void*)pthread_self();
}

void* test2() {
  void* r = NULL;
  _s2(__NR_arch_prctl, 0x1003, (long)&r);
  return r;
}

void* test3() {
  void* r = NULL;
  __asm__ (
    "mov %%fs, %0\n"
    :
    : "memory"(r)
    :
  );
  return r;
}

void* test4() {
  void* r = NULL;
  __asm__ (
    "mov %%fs:0x0, %%rax\n"
    "mov %%rax, %0\n"
    :
    : "memory"(r)
    : "rax"
  );
  return r;
}

void* test5(size_t i) {
  void* r = NULL;
  __asm__ (
    "mov %1, %%rax\n"
    "mov %%fs:(%%rax), %%rax\n"
    "mov %%rax, %0\n"
    :
    : "memory"(r), "r"(i)
    : "rax"
  );
  return r;
}

void* test6() {
  void** r = NULL;
  _s2(__NR_arch_prctl, 0x1003, (long)&r);
  if (r[0] == NULL) {
    r[0] = (void*)r;
  }
  if (r[2] == NULL) {
    r[2] = (void*)r;
  }
  return r;
}


int main(int argc, char** argv, char** envp) {
  //pthread_t t1;
  //char *message1 = "Thread 1";
  //int aaa = 40;
  //foo_p = &aaa;
  //pthread_key_create(&glob_var_key,NULL);
  //pthread_setspecific(glob_var_key, &aaa);

  //int iret1 = pthread_create(&t1, NULL, thread1, (void*) message1);
  //pthread_join(t1, NULL);
  //printf("Thread 1 returns: %d\n", iret1);
  //printf("aaa: %d\n", aaa);
  //printf("main(%d, ..., ...)\n", argc);
  /*
  int rargc = (int)new_raw_args[0];
  char** rargv = (char**)&new_raw_args[1];
  char** renvp = (char**)&new_raw_args[1+rargc+1];
  printf("raw_args:argc: %d\n", rargc);
  printf("raw_args:argv[0]: %s\n", rargv[0]);
  printf("raw_args:argv[1]: %s\n", rargv[1]);
  printf("raw_args:envp[0]: %s\n", renvp[0]);
  printf("raw_args:envp[1]: %s\n", renvp[1]);
  */
  //printf("entrypoint: %p\n", entrypoint);
  //printf("new_raw_args: %p\n", new_raw_args);

  // equivalent to the earlier jmp
  // crashes in the same place. ...fs:[rax]
  /*
000000000045c4e0 <__current_locale_name>:
  45c4e0:       f3 0f 1e fa             endbr64
  45c4e4:       48 c7 c0 a8 ff ff ff    mov    rax,0xffffffffffffffa8
  45c4eb:       48 63 ff                movsxd rdi,edi
  45c4ee:       64 48 8b 00             mov    rax,QWORD PTR fs:[rax]
> 45c4f2:       48 8b 84 f8 80 00 00    mov    rax,QWORD PTR [rax+rdi*8+0x80]
  45c4f9:       00
  45c4fa:       c3                      ret
  45c4fb:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
  */
  hmm_tls = (void*)pthread_self();
  (void)test1();
  (void)test2();
  (void)test3();
  (void)test4();

  inner();

  _s1(__NR_exit, 42);
  //for (size_t i=0; i<argc; i++) {
  //  puts(argv[i]);
  //}
  //puts("----");
  /*for (size_t i=0; envp[i] != NULL; i++) {
    puts(envp[i]);
  }*/
  //system("id");
  //sleep(2);
  //printf("retval: %d\n", retval);
  return 0;
}
