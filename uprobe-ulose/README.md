# Linux perf_event_open(2) uprobe wrapper

This code is a very small wrapper around `perf_event_open(2)` that sets uprobes
from pairs of file paths and file offsets (in hex).

# Building

``` console
$ gcc -std=c11 -Wall -Wextra -pedantic -o uprobe uprobe.c
```

# Running

***Note:*** Be extremely careful with uprobes. If not confined to a specific
PID (which requires more than just CAP_PERFMON on Linux 5.8+), they will be
applied to all existing processes, not just new ones. If you select an offset
that is not the start of an intended instruction, you may bring down the whole
system (i.e. if you uprobed libc.so at an offset that made `free(3)` not
ignore NULL pointers, or that caused the stack pointer to become misaligned
during process initialization, etc.) ...or worse. Additionally, be careful
about the ordering of multiple such "offset-offset" uprobes as they are applied
serially.

```
# ./uprobe [pid] /path/to/exe/or/so 0x0ff5e7 /path/to/exe/or/so2 0x0ff5e72 ...
```

For example, one such example on Ubuntu 20.04 with the below su and libc.so
binaries causes invocations of `su` to skip password checks >50% of the time.

```
$ shasum -a 256 /usr/bin/su /usr/lib/x86_64-linux-gnu/libc.so.6 
9d1fda070610581427db17af53c510ae515df64427dab9a43f04e30606153d03  /usr/bin/su
4db473e38da06f7b1ad54ef117a184e08ffda27bbbb5329d03831186e3e533c8  /usr/lib/x86_64-linux-gnu/libc.so.6
# ./uprobe /bin/su 0x5c51 /usr/lib/x86_64-linux-gnu/libc.so.6 0x8502d
```
