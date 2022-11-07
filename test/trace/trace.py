#!/usr/bin/python3

# Copyright (c) 2022 NCC Group.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import json
import subprocess

syscalls = sys.argv[1]
pid = sys.argv[2]
if pid == "":
  print("usage: python3 {} <pid>".format(sys.argv[0]))
  sys.exit(1)
print(pid)
# sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter/pid=='"$(ps aux | grep hmm | grep -v nano | grep -v grep | awk '{print $2}')"'/ { if (args->id != 2) { printf("NR %ld (%lx, %lx, %lx, %lx, %lx, ...)\n", args->id, args->args[0], args->args[1], args->args[2], args->args[3], args->args[4]); } else { printf("NR %ld (%s, %lx, %lx, %lx, %lx, ...)\n", args->id, str(args->args[0]), args->args[1], args->args[2], args->args[3], args->args[4]); } }' | python3 -c 'import sys,subprocess; f=(lambda x: [x[0], x[1], "["+subprocess.run(["jq", "-r", ".[\"" + x[1] + "\"]", "syscalls.json"],capture_output=True).stdout.decode().strip()+"]",*x[2:]]); [print(" ".join(f(line.strip().split(" ")))) for line in sys.stdin]'

# '"$(ps aux | grep hmm | grep -v nano | grep -v grep | awk '{print $2}')"'

template = """\
tracepoint:raw_syscalls:sys_enter/pid=={pid}/ {{
  if (args->id == 2 || args->id == 257) {{
    if (args->id == 2) {{
      printf("NR %ld (%s, %lx, %lx, %lx, %lx, ...)\\n",
        args->id, str(args->args[0]), args->args[1],
        args->args[2], args->args[3], args->args[4]);
    }}
    if (args->id == 257) {{
      printf("NR %ld (%lx, %s, %lx, %lx, %lx, ...)\\n",
        args->id, args->args[0], str(args->args[1]),
        args->args[2], args->args[3], args->args[4]);
    }}
  }} else {{
    printf("NR %ld (%lx, %lx, %lx, %lx, %lx, ...)\\n",
           args->id, args->args[0], args->args[1],
           args->args[2], args->args[3], args->args[4]
    );
  }}
}}
tracepoint:raw_syscalls:sys_exit/pid=={pid}/ {{
  printf("-> %lx\\n", args->ret);
}}
"""

script = template.format(pid=pid).replace("\n", "")

syscalls = json.loads(open(syscalls, 'r').read())
#print(syscalls)

bpftrace = subprocess.Popen(['bpftrace', '-e', script], stdout=subprocess.PIPE)

while bpftrace.poll() is None:
  try:
    line = bpftrace.stdout.readline().decode('utf-8')
    if line.startswith('NR '):
      pieces = line.split(' ')
      id = pieces[1]
      name = syscalls.get(id, "unknown")
      line = ' '.join(pieces[:2] + ["[" + name + "]"] + pieces[2:])
    sys.stdout.write(line)
  except subprocess.TimeoutExpired:
    pass
  except Exception as e:
    print(e)
    break

#import sys,subprocess;
#f=(lambda x: [x[0], x[1], "["+subprocess.run(["jq", "-r", ".[\"" + x[1] + "\"]", "syscalls.json"],capture_output=True).stdout.decode().strip()+"]",*x[2:]]);
#[print(" ".join(f(line.strip().split(" ")))) for line in sys.stdin]


# python3 -c 'import sys,subprocess; f=(lambda x: [x[0], x[1], "["+subprocess.run(["jq", "-r", ".[\"" + x[1] + "\"]", "syscalls.json"],capture_output=True).stdout.decode().strip()+"]",*x[2:]]); [print(" ".join(f(line.strip().split(" ")))) for line in sys.stdin]'
