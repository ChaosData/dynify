# "dynify" (tentative name)

"dynify"/`hmm` (hacky machine monitor) is a PoC for enabling Frida and tools
like it to be able to handle attaching and hooking statically-linked binaries.
It works by starting a statically linked binary as a paused ptraced child
process and then copying the whole thing over (statically-linked ET_EXEC files
are loaded at a fixed address w/o ASLR by the kernel) into the parent and then
jumping into it. There's a bit more magic involved:

* dealing w/ multiple libcs vying for power in the same process
* legacy heap usage (avoided by forcing the "host" libc to use mmap for malloc)
* patching up auxvec
* bypassing frida's hacky attempt to inject libpthread that crashes everything
* thread local storage init

But the main point was to get it working enough to enable Frida to hook
statically-linked Go binaries on linux.

Currently, b/c of the way that Frida looks up "modules" in a process, it
completely misses the statically-linked code loaded in. However, since the
statically-linked code is copied 1-to-1 into the process, and there is no ASLR
applied to it, you can just dump symbols out of the binaries w/
`readelf`/`nm`/etc. and use them directly in Frida for now.

# Building/Usage

```
$ gcc -g -std=c11 -Wall -pie -fPIC -fno-stack-protector -Wl,-e_altstart -o hmm hmm.c -pthread
$ ./hmm <path/to/static-bin> <argv0> [argv1...]
...
$ sudo frida -p "$(pgrep hmm)"
```

# Go binaries and Frida

Frida doesn't know how to deal with static binaries (hence this PoC),
and this especially flares up with statically-linked Go binaries as they don't
behave like normal Linux programs and are more freestanding. For starters,
Frida has a lot of issues attaching to Go processes once the Go runtime has
been setup and straight up crashes the process when attempting to inject
itself/set up the process for itself. So instead, we currently use `-DDEBUG` in
the build to pause before entering the static code. This provides a hacky
window in which to attach Frida.

However, Go's static link init C code does not properly set up thread local
storage (TLS) sufficiently for Frida, resulting in crashes the moment Frida's
inner working for hooks attempt to access it. The `tlsfixer` binary does some
ptrace(2) magic to invoke a function within `hmm` in each thread that fixes up the
TLS data (fyi, it can get a bit crashy with Go binaries over time, but does
prove the behavior).

So to use Frida with statically-linked Go binaries, you have to do the
following:

1. build w/ `-DDEBUG` (for now, there are no cli flags for this, I'm rushing
   this at the tail end of my sabbatical)
2. run `hmm` such that it pauses for input on stdin
3. attach `frida` (but don't do anything else)
4. send some stdin input to `hmm` (such as hitting enter)
5. run `tlsfixer <hmm pid>`
6. do whatever Frida stuff you were going to do

```
$ gcc -g -std=c11 -Wall -pie -fPIC -fno-stack-protector -Wl,-e_altstart -o hmm hmm.c -pthread -DDEBUG
$ gcc -std=c11 -Wall -Wextra -pedantic -fPIC -pie -o tlsfixer tlsfixer.c
$ ./hmm <path/to/static-go-bin> <argv0> [argv1...]
...
#(attach frida: sudo frida -p "$(pgrep hmm)")
<enter>
#(run tlsfixer: sudo ./tlsfixer "$(pgrep hmm)")
#(use frida)
```

# Caddy Example

```
$ sudo frida -p "$(pgrep hmm)" # echo-static: <main.handleConn>
[Local::PID::XXXX]-> Interceptor.attach(ptr(0x4c9ae0), function(args){try{console.log("4c9ae0 called!");} catch (e) {console.log("exception!")}})
...
$ nc 127.0.0.1 9999
```

```
$ sudo frida -p "$(pgrep hmm)" # caddy-static: <github.com/caddyserver/caddy/v2/modules/caddyhttp.(*StaticResponse).ServeHTTP>
[Local::PID::XXXX]-> Interceptor.attach(ptr(0x11d4b40), function(args){console.log("11d4b40 called! args[0]: " + args[0])})
...
$ curl -v http://127.0.0.1:2015
```

# Future Work

* Cleaning up the codebase / making a non-PoC version
* CLI flags
* Figuring out a way to have Frida recognize the static binary sections
    * this may involve faking dl structures in the host process
