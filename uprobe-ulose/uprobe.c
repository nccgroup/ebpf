/*
Copyright (c) 2021 NCC Group Security Services, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

// $ gcc -std=c11 -Wall -Wextra -pedantic -o uprobe uprobe.c
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>

int main(int argc, char** argv) {
  int pid = -1;
  int off = 1;

  if ((argc & 1) == 0) {
    off += 1;
    pid = atoi(argv[1]);
  }

  if (argc < 3 || pid == 0 || ((argc - off) & 1) != 0) {
    printf("usage: %s [pid] <<path> <offset>..>\n", argv[0]);
    return 1;
  }

  for (int i = off; i < argc; i+=2) {
    const char* path = argv[i];
    const char* off_str = argv[i+1];
    printf("attempting to hook %s @ %s\n", path, off_str);

    struct perf_event_attr attr = { 0 };

    attr.size = sizeof(attr);
    attr.type = 7; // uprobe
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.namespaces = 1;
    attr.exclude_kernel = 1;
    attr.config = 0;
    attr.uprobe_path = (uintptr_t)(void *)path;
    attr.probe_offset = strtoull(off_str, NULL, 16);

    int cpu = 0;
    int fd = syscall(__NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
      perror("perf_event_open(...)");
      return 1;
    }

    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
      perror("ioctl(fd, PERF_EVENT_IOC_ENABLE, 0)");
      return 1;
    }
  }
  puts("uprobes applied...");

  while (1) {
    sleep(5);
  }

  return 0;
}
