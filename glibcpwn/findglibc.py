# Copyright (c) 2018 NCC Group Security Services, Inc. All rights reserved.
# Licensed under Dual BSD/GPLv2 per the repo LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals
from bcc import BPF
import argparse
import ctypes
import sys
import time

from base64 import b64decode
from binascii import hexlify

from subprocess import check_output, CalledProcessError
import os
import multiprocessing


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
  /*
  notify_t n;
  #pragma unroll
  for (size_t i = 0; i < sizeof(n.data); i++) {
    n.data[i] = 0;
  }
  notify(&n, ctx);
  */

const size_t syscall_setup = 0x0000011eb8ca8949;
inline static size_t get_timerfd_settime_addr(size_t ret_addr) {
//00000000001225d0 <timerfd_settime@@GLIBC_2.8>:
//  1225d0:       49 89 ca                mov    r10,rcx
//  1225d3:       b8 1e 01 00 00          mov    eax,0x11e
//  1225d8:       0f 05                   syscall

  uint8_t* call = (uint8_t*)(ret_addr - 0x5); // relative offset call - e8 XX XX XX XX
  uint8_t opcodes[2];
  bpf_probe_read(&opcodes, 1, call);
  if (opcodes[0] != 0xe8) {
    return 0;
  }
  int call_off;
  bpf_probe_read(&call_off, sizeof(call_off), &call[1]);

  uint8_t* call_addr = (uint8_t*)((size_t)call + call_off + 5);
  size_t bytes; // = ((size_t*)call_addr)[0];
  bpf_probe_read(&bytes, sizeof(bytes), call_addr);

  if (bytes == syscall_setup) { // direct
    return (size_t)call_addr;
  }
  // check for plt
  bpf_probe_read(&opcodes, 2, call_addr);
  if (opcodes[0] != 0xff || opcodes[1] != 0x25) {
    return 0;
  }
  int jmp_off;
  bpf_probe_read(&jmp_off, sizeof(jmp_off), &call_addr[2]);
  size_t* jmp_addr_addr = (size_t*)((size_t)call_addr + jmp_off + 6);
  uint8_t* jmp_addr;
  bpf_probe_read(&jmp_addr, sizeof(jmp_addr), jmp_addr_addr);
  bpf_probe_read(&bytes, sizeof(bytes), jmp_addr);

  if (bytes == syscall_setup) {
    return (size_t)jmp_addr;
  }
  return 0;
}

int kprobe__sys_timerfd_settime(
    struct pt_regs *ctx,
    int fd, int flags,
    //struct itimerspec __user const* new_value,
    size_t new_value,
    struct itimerspec __user * old_value) {

  size_t pid_tgid = bpf_get_current_pid_tgid();
  size_t pid = (u32)(pid_tgid >> 32);

  if (pid != """ + sys.argv[1] + """) {
    return 0;
  }

  struct itimerspec __user const* nv = (struct itimerspec __user const*)new_value;

  size_t* scanner = (size_t*)new_value;
  size_t stack = 0;
  size_t timerfd_settime_addr = 0;
  size_t stack_ret_addr = 0;

  #pragma unroll
  for (size_t i=0; i < 14; i++) {
    bpf_probe_read(&stack, sizeof(size_t), scanner - i);
    //bpf_trace_printk("stack: %lx!\\n", stack);
    timerfd_settime_addr = get_timerfd_settime_addr(stack);
    if (timerfd_settime_addr != 0) {
      stack_ret_addr = (size_t)(uintptr_t)(scanner - i);
      bpf_trace_printk("match: %d!\\n", i);
      break;
    }
  }

  if (timerfd_settime_addr == 0) {
    bpf_trace_printk("failed to find timerfd_settimer\\n");
    return 0;
  }

  //bpf_trace_printk("timerfd_settime: 0x%lx!\\n", timerfd_settime_addr);
  bpf_trace_printk("stack_ret_addr: 0x%lx!\\n", stack_ret_addr);

  //binary specific
  size_t __libc_start_main = timerfd_settime_addr - 0x100b20;
  bpf_trace_printk("__libc_start_main: 0x%lx!\\n", __libc_start_main);
  size_t __libc_system = __libc_start_main + 0x2d990;
  //bpf_trace_printk("__libc_system: 0x%lx!\\n", __libc_system);

  uint8_t instbuf[16];
  bpf_probe_read(&instbuf, sizeof(instbuf), (void*)__libc_system);

  /*
  #pragma unroll
  for (size_t i=0; i < sizeof(instbuf); i++) {
    bpf_trace_printk("inst: %x!\\n", (uint8_t)instbuf[i]);
  }
  */


  //int r = bpf_probe_write_user(addr, buf, 5);
  //bpf_trace_printk("write: %d\\n", r);

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

#print("Listening...")
#while True:
#  try:
#    b.kprobe_poll()
#  except KeyboardInterrupt:
#    sys.exit(0)


