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

// $ gcc -g -std=c11 -Wall -pie -fPIC -fno-stack-protector -Wl,-e_altstart -static -o static2 static2.c

#define _DEFAULT_SOURCE
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
#include <elf.h>
#include <link.h>

extern void _start(void* stack);
extern void _altsigreturn(void);

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


void _altstart_c(size_t** _raw_args) {
  _print(1, "static2\n");
  //size_t* raw_args = *_raw_args;
  //int argc = (int)raw_args[0];
  //char** argv = (char**)&raw_args[1];
  //char** envp = (char**)&raw_args[1+argc+1];

  extern const Elf64_Ehdr __ehdr_start;
  char buf[128];
  _print(1, "&__ehdr_start: 0x");
  utos((uintptr_t)&__ehdr_start, 16, buf);
  _print(1, buf);
  _print(1, "\n");

  _print(1, "__ehdr_start.e_phentsize: 0x");
  utos((uintptr_t)__ehdr_start.e_phentsize, 16, buf);
  _print(1, buf);
  _print(1, "\n");

  _print(1, "__ehdr_start.e_phoff: 0x");
  utos((uintptr_t)__ehdr_start.e_phoff, 16, buf);
  _print(1, buf);
  _print(1, "\n");

  _print(1, "__ehdr_start.e_phnum: 0x");
  utos((uintptr_t)__ehdr_start.e_phnum, 16, buf);
  _print(1, buf);
  _print(1, "\n");

  //GL(dl_phdr) = (const void *) &__ehdr_start + __ehdr_start.e_phoff;
  _print(1, "(const void *) &__ehdr_start + __ehdr_start.e_phoff: ");
  utos((uintptr_t)(&__ehdr_start + __ehdr_start.e_phoff), 16, buf);
  _print(1, buf);
  _print(1, "\n");

  extern const void* _dl_phdr;
  _print(1, "&_dl_phdr: 0x");
  utos((uintptr_t)&_dl_phdr, 16, buf);
  _print(1, buf);
  _print(1, "\n");
  _print(1, "_dl_phdr: 0x");
  utos((uintptr_t)_dl_phdr, 16, buf);
  _print(1, buf);
  _print(1, "\n");

  void* dl_phdr_ = (void*)&__ehdr_start;
  /*
  for (const ElfW(Phdr) *ph = &__ehdr_start; ph < &_dl_phdr[_dl_phnum]; ++ph) {
      switch (ph->p_type)
        {
        case PT_GNU_STACK:
          _dl_stack_flags = ph->p_flags;
          break;

        case PT_GNU_RELRO:
          _dl_main_map.l_relro_addr = ph->p_vaddr;
          _dl_main_map.l_relro_size = ph->p_memsz;
          break;
        }
  }
  */
  //_s1(__NR_exit, 0);
}

int main(int argc, char** argv, char** envp) {
  printf("static2:main(%d, ..., ...)\n", argc);
  (void)getchar();

  system("id");
  return 0;
}
