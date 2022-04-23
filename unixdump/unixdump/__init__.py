# Copyright (c) 2018 NCC Group Security Services, Inc. All rights reserved.
# Licensed under Dual BSD/GPLv2 per the repo LICENSE file.

# known to work with bcc @ dccc4f28b7404b2f77f8ad8c7ad1ea741db589f2
#                and Linux ubuntu 4.15.0-42-generic

from __future__ import absolute_import, division, print_function, unicode_literals
from bcc import BPF
from .screen import is_in_screen
from .session import get_session_type
from .term_screen_x11 import get_screen_x11_current_terminal_pid
from .term_screen_wayland import get_screen_wayland_current_terminal_pid
from .term_tmux_x11 import get_tmux_x11_current_terminal_pid
from .term_tmux_wayland import get_tmux_wayland_current_terminal_pid
from .term_wayland import get_wayland_current_terminal_pid
from .term_x11 import get_x11_current_terminal_pid
from .tmux import is_in_tmux
from .ud2b import extract_buffer
import argparse
import ctypes
import hexdump
import sys
import time

from base64 import b64decode
from binascii import hexlify

from subprocess import check_output, CalledProcessError
import os
import select
import multiprocessing


errors = {
  'SK_NOT_UNIX': 1,
  'SK_PEER_NOT_UNIX': 2,
  'SUN_PATH_LEN_TOO_BIG': 3,
  'SUN_PATH_LEN_TOO_SMALL': 4,
  'IOVEC_BASE_NULL': 5,
  'RINGBUF_ENTRY_NULL': 6,
  'SIGNED_LEN_NEGATIVE': 7,
  'NO_SLOTS_AVAILABLE': 8,
  'CMSG_NOT_OK': 9,
  'CMSG_BAD': 10,
  'CMSG_WRONG_TYPE': 11,
  'CMSG_BAD_LEN': 12,
  'CMSG_CRED_ZERO_PID': 13,
  'SK_PEER_NULL' : 14,
  'SK_NULL' : 15,
}
errors_rev = {v: k for k, v in errors.items()}

error_defines = "\n"

for k,v in errors.items():
  error_defines += "#define {} ((size_t){})\n".format(k, v)
error_defines += "\n"

class bcolors:
  BLUE = ''
  RED = ''
  ENDC = ''

pid_map = {}
fd_map = {}
pid_pair_map = {}

def parse_args():
  parser = argparse.ArgumentParser(description="Snoop on Unix Domain Sockets.")
  parser.add_argument("-r", "--ringsize", type=int, default=20, help="ring buffer size")
  parser.add_argument("-a", "--ancillarycount", type=int, default=2, help="max ancillary CMSG blocks to handle")
  parser.add_argument("-m", "--scmrightscount", type=int, default=4, help="max FDs in SCM_RIGHTS CMSG block to handle")
  parser.add_argument("-e", "--pageexponent", type=int, default=3, help="perf ring buffer size: 2^[pageexponent]")
  parser.add_argument("-p", "--pids", nargs='+', default=[], help="trace only these pids")
  parser.add_argument("-x", "--exclude", nargs='+', default=[], help="exclude these pids")
  parser.add_argument("-P", "--pair", nargs='+', default=[], help="trace only this pid:pair")
  parser.add_argument("-s", "--socket", type=str, help="trace only this unix socket path")
  parser.add_argument("-b", "--beginswith", action='store_true', help="--socket will match starting sequences")
  parser.add_argument("-@", "--base64", action='store_true', help="--socket will be parsed as base64 for binary paths (assumes abstract namespace)")
  parser.add_argument("-c", "--color", action='store_true', help="output files with color")
  cwd = check_output(['pwd'], shell=False).strip()
  parser.add_argument("-o", "--dir", nargs='?',
                      help="save output to files. defaults to $PWD", default=None, const=cwd)
  parser.add_argument("-v", "--verbose", action='store_true', help="disables metadata elision")
  parser.add_argument("-z", "--stats", action='store_true', help="debug stats output")
  parser.add_argument("-d", "--debug", action='store_true', help="debug output")
  parser.add_argument("-y", "--retry", type=int, default=5, help="number of retry attempts for incomplete events")
  parser.add_argument("-l", "--ancillarydata", action='store_true', help="filter for ancillary data")
  parser.add_argument("-E", "--preprocessonly", action='store_true', help="output bcc C code and exit")
  parser.add_argument("-t", "--excludeownterminal", action='store_true', help="best effort to exclude terminal process from capture")
  parser.add_argument("-B", "--extract", type=str, help="extract buffer from file output to binary files")

  args = parser.parse_args()

  if args.extract is not None:
    if len(sys.argv) > 3:
      parser.error("extract is mutually exclusive")
      sys.exit(1)
    extract_buffer(args.extract)
    sys.exit(0)
  if args.dir is not None and not os.path.isdir(args.dir):
    parser.error("{} is not a directory.".format(args.dir))
  if args.color and not args.dir:
    parser.error("color requires file output")
  if args.dir:
    start_ts = int(time.time())
  if len(args.pids) > 0:
    try:
      args.pids = [int(x) for x in args.pids]
    except ValueError:
      parser.error("invalid PID in --pids: {}".format(repr(args.pids)))

    for pid in args.pids:
      pid_map[pid] = check_output(['ps', '-q', str(pid), '-o', 'args='],
                                 shell=False).strip()
  if len(args.exclude) > 0:
    try:
      args.exclude = [int(x) for x in args.exclude]
    except ValueError:
      parser.error("invalid PID in --exclude: {}".format(repr(args.exclude)))
  if len(args.pair) > 0:
    if len(args.pids) > 0:
      parser.error("--pids and --pair are mutually exclusive")
    if len(args.exclude) > 0:
      parser.error("--exclude and --pair are mutually exclusive")
    if len(args.pair) > 1:
      parser.error("--pair currently supports only one pair")
    pairs = []
    for pair in args.pair:
      pieces = pair.split(':')
      if len(pieces) != 2:
        parser.error("invalid pair in --pair: {}".format(repr(pair)))
      if not unicode.isdigit(pieces[0]) or not unicode.isdigit(pieces[1]):
        parser.error("invalid pair in --pair: {}".format(repr(pair)))
      pairs.append([int(pieces[0]), int(pieces[1])])
    args.pairs = pairs

    for pair in args.pairs:
      pid_map[pair[0]] = check_output(['ps', '-q', str(pair[0]), '-o', 'args='],
                                 shell=False).strip()
      pid_map[pair[1]] = check_output(['ps', '-q', str(pair[1]), '-o', 'args='],
                                 shell=False).strip()
  else:
    args.pairs = []

  if args.beginswith and not args.socket:
    parser.error("beginswith requires socket")

  if args.color:
    class bcolors:
      # HEADER = '\033[95m'
      BLUE = '\033[94m'
      # GREEN = '\033[92m'
      # YELLOW = '\033[93m'
      RED = '\033[91m'
      ENDC = '\033[0m'
      # BOLD = '\033[1m'
      # UNDERLINE = '\033[4m'

  return args


def gen_pid_in_list(name, lst):
  import pybst.avltree
  at = pybst.avltree.AVLTree()
  for e in lst:
    at.insert(int(e), int(e))
  preamble = '''\
static inline bool %s(u32 needle) {
''' % name
  out = ""
  out += preamble
  out += node_to_c(at.Root)
  out += '''\
}

static inline bool not_%s(u32 needle) {
  return !%s(needle);
}
''' % (name, name)
  return out

def node_to_c(node, nest = 0):
  out = '''\
%s  if (needle == %u) {
%s    return true;
%s  }
''' % (nest*"  ", node.value, nest*"  ", nest*"  ")

  if node.left == None and node.right == None:
    out += '''\
%s  return false;
''' % (nest*"  ")
  else:
    out += '''\
%s  if (needle < %u) {
''' % (nest*"  ", node.value)
    if node.left != None:
      out += node_to_c(node.left, nest+1)
    else:
      out += '''\
%s    return false;
''' % (nest*"  ")

    out += '''\
%s  } else {
''' % (nest*"  ")
    if node.right != None:
      out += node_to_c(node.right, nest+1)
    else:
      out += '''\
%s    return false;
''' % (nest*"  ")
    out += '''\
%s  }
''' % (nest*"  ")
  return out

#print(gen_pid_in_list("pid_in_lst",[5, 20, 2,3, 50, 60, 44, 52]))
#sys.exit(1)

def gen_ratchet_switch(sz):
  preamble = '''switch (sync->next) {
  '''
  entry_template = '''
    case {}: {{
      nxt = {};
      sync->next = {};
      break;
    }};
  '''
  end = '''
    default: {
      nxt = 0;
      sync->next = 1;
    }
  }
  '''
  out = ""
  out += preamble
  for i in range(sz):
    out += entry_template.format(i, i, i+1)
  out += end
  return out

def render_code(template, format_args):
  return template.replace(
    "{", "{{"
  ).replace(
    "}", "}}"
  ).replace(
    "{{{{", "{"
  ).replace(
    "}}}}", "}"
  ).format(**format_args)

events_count = 0
used_zero_count = 0
used_zero_queue = []
dropped_used_zero_count = 0
no_slots_count = 0

notify_memset = '''
  #pragma unroll
  for (size_t i=0; i < sizeof(n); i++) {
    ((char*)&n)[i] = 0;
  }
'''

def main():
  args = parse_args()

  if args.excludeownterminal:
    session = get_session_type()
    tmux = is_in_tmux()
    screen = is_in_screen()
    if session == 'x11':
      if tmux:
        tpid = get_tmux_x11_current_terminal_pid()
      elif screen:
        tpid = get_screen_x11_current_terminal_pid()
      else:
        tpid = get_x11_current_terminal_pid()
    elif session == 'wayland':
      if tmux:
        tpid = get_tmux_wayland_current_terminal_pid()
      elif screen:
        sys.stderr.write('screen on terminals on wayland is not currently supported.\n')
        sys.exit(1)
        #tpid = get_screen_wayland_current_terminal_pid()
      else:
        tpid = get_wayland_current_terminal_pid()
    else:
      sys.stderr.write('XDG_SESSION_TYPE not supported\n')
      sys.exit(1)
    args.exclude.extend(tpid)

  RING_SIZE = args.ringsize
  PAGECNT = 2 ** args.pageexponent

  filter_pid = ""
  filter_unix = ""
  exclude_pids = ""

  defines = ""

  if len(args.pids) == 1:
    defines += "#define FILTER_PID %d\n" % args.pids[0]
  if len(args.pairs) == 1:
    defines += "#define FILTER_PAIR\n"
    defines += "#define FILTER_PAIR_1 %d\n" % args.pairs[0][0]
    defines += "#define FILTER_PAIR_2 %d\n" % args.pairs[0][1]
  if args.socket is not None:
    sockkey = args.socket
    if args.base64:
      sockkey = '@' + ''.join(['\\x' + xx for xx in map(''.join, zip(*[iter(hexlify(b64decode(sockkey)).decode('utf-8'))]*2))])
    defines += "#define FILTER_UNIX \"%s\"\n" % sockkey

  if len(args.pids) > 1:
    defines += "#define INCLUDE_PIDS\n"
  if len(args.exclude) > 0:
    defines += "#define EXCLUDE_PIDS\n"
  if args.beginswith:
    defines += "#define BEGINS_WITH\n"

  if args.ancillarydata:
    defines += "#define ANCILLARY\n"

  #if args.ancillarycount < 2:
  #  args.ancillarycount = 2
  defines += "#define ANCILLARY_COUNT ((size_t)%d)\n" % args.ancillarycount
  #if args.scmrightscount < 4:
  #  args.scmrightscount = 4
  defines += "#define SCM_RIGHTS_COUNT ((size_t)%d)\n" % args.scmrightscount

  format_args = {
    'defines': defines,
    'error_defines': error_defines,
    'RING_SIZE': RING_SIZE,
    'ratchet_switch': gen_ratchet_switch(RING_SIZE),
    'cores': multiprocessing.cpu_count(),
    'is_included_pid': '',
    'is_excluded_pid': '',
    'notify_memset': '',
  }

  if len(args.pids) > 1:
    format_args['is_included_pid'] = gen_pid_in_list("is_included_pid", args.pids)

  if len(args.exclude) > 0:
    format_args['is_excluded_pid'] = gen_pid_in_list("is_excluded_pid", args.exclude)

  code_template = """
{{defines}}
{{error_defines}}

#include <bcc/proto.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/skbuff.h>
#include <linux/pid.h>
#include <net/af_unix.h>

#define UINT8_MAX (255)
#define UINT32_MAX (4294967295UL)

#define RING_SIZE ((size_t){{RING_SIZE}})
#define NUM_CPU ((size_t){{cores}})

typedef struct data {
  volatile size_t used;
  //volatile size_t len;
  uint8_t buffer[4096];
} data_t;
#define BUFFER_SIZE (sizeof(((data_t*)NULL)->buffer))
BPF_PERCPU_ARRAY(ring_buf, data_t, RING_SIZE);
//BPF_ARRAY(ring_buf, data_t, RING_SIZE);

struct sync_t {
  size_t next;
};
BPF_PERCPU_ARRAY(sync_buf, struct sync_t, 1);

struct scm_rights {
  int fds[SCM_RIGHTS_COUNT];
  int pad[SCM_RIGHTS_COUNT % 2];
};

struct scm_credentials {
  u32 pid;
  u32 uid;
  u32 gid;
  u32 pad;
};

#define SCM_DATA_PAD_COUNT (CMSG_ALIGN(\
  sizeof(struct scm_rights) > sizeof(struct scm_credentials) ?\
    sizeof(struct scm_rights) :\
    sizeof(struct scm_credentials)\
  ) / sizeof(u64)\
)
struct scm_data {
  // enumify later: pad = 0, rights = 1, creds = 2; high bit (last) = truncated
  u32 type;
  u32 num;
  union {
    struct scm_rights rights;
    struct scm_credentials creds;
    u64 fill[SCM_DATA_PAD_COUNT];
  } content;
};

typedef struct notify {
  u16 cpu;
  u16 type; // SOCK_STREAM, SOCK_DGRAM
  u32 index;
  size_t sk_file;
  size_t peer_file;
  u32 pid;
  u32 peer_pid;
  u8 is_bound;
  u8 is_truncated;
  u8 sun_path_len;
  u8 error_code;
  u32 len;
  size_t error_msg;
  struct scm_data scm[ANCILLARY_COUNT];
  #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
  union {
    uint8_t sun_path[UNIX_PATH_MAX+1];
    size_t fill[14];
  } u;
  #endif
} notify_t;
BPF_PERF_OUTPUT(output);

// note: yet another hack to bypass some weird condition where the validator prefers
//       is_bound to be a size_t vs bool depending on the ifdefs in place...
#ifdef FILTER_UNIX
#define BOOL_TYPE bool
#else
#define BOOL_TYPE size_t
#endif

inline static void clear_scm(notify_t* n, size_t _i) {
  /*#pragma unroll
  for (size_t i = 0; i < ANCILLARY_COUNT; i++) {
    if (i >= _i) {
      n->scm[i].type = 0;
      n->scm[i].len = 0;
      #pragma unroll
      for (size_t j=0; j < SCM_DATA_PAD_COUNT; j++) {
        n->scm[i].content.fill[j] = 0;
      }
    }
  }*/

  #pragma unroll
  for (size_t i = 0; i < ANCILLARY_COUNT; i++) {
    if (i >= _i) {
      char* scm = (char*)&n->scm[i];
      #pragma unroll
      for (size_t j=0; j < sizeof(struct scm_data); j++) {
        scm[j] = 0;
      }
    }
  }
}

inline static void clear_scm_index(notify_t* n, size_t i) {
  char* scm = (char*)&n->scm[i];
  #pragma unroll
  for (size_t j=0; j < sizeof(struct scm_data); j++) {
    scm[j] = 0;
  }
}

inline static void notify(notify_t* n,
                          struct pt_regs* ctx) {
  output.perf_submit(ctx, n, sizeof(notify_t));
}

// magic to trick the validator
inline static struct unix_sock* pick_sock(struct unix_sock* u, struct unix_sock* up, struct unix_sock** other) {
  struct unix_address* addr = u->addr;
  if (addr != NULL && addr->len != 0) {
    *other = up;
    return u;
  }
  *other = u;
  return up;
}

#ifdef FILTER_UNIX
static inline bool cmp_sun_path(char* str, size_t len) {
  char needle[] = FILTER_UNIX;

  if (sizeof(needle) == 1 && 0 == len) {
    return true;
  }

  #ifndef BEGINS_WITH
  if (sizeof(needle)-1 != len) {
    return false;
  }
  #endif

  char haystack[sizeof(needle)];
  if (str == NULL) {
    return false;
  }
  bpf_probe_read(&haystack, sizeof(haystack), (void *)str);
  #ifdef BEGINS_WITH
  size_t const stop = sizeof(needle)-2;
  #else
  size_t const stop = sizeof(needle)-1;
  #endif

  #pragma unroll
  for (int i = 0; i < stop; ++i) {
    if (needle[i] != haystack[i]) {
      return false;
    }
  }
  return true;
}
#endif

#ifdef INCLUDE_PIDS
{{is_included_pid}}
#endif

#ifdef EXCLUDE_PIDS
{{is_excluded_pid}}
#endif

inline static void copy_into_entry_buffer(data_t* entry, size_t const len, char* base, u8 volatile* trunc) {
  int l = (int)len;
  if (l < 0) {
    l = 0;
  }
  if (l >= BUFFER_SIZE) {
    *trunc = 1;
  }
  if (l >= BUFFER_SIZE) {
    l = BUFFER_SIZE - 1;
  }
  bpf_probe_read(entry->buffer, l, base);
}

static inline struct cmsghdr* cmsg_firsthdr_x(struct msghdr* msg) {
  void* msg_control = msg->msg_control;
  size_t msg_controllen = msg->msg_controllen;
  return __CMSG_FIRSTHDR(msg_control, msg_controllen);
}

static inline struct cmsghdr* cmsg_nxthdr_x(struct msghdr* msg, struct cmsghdr* cmsg) {
  void* msg_control = msg->msg_control;
  size_t msg_controllen = msg->msg_controllen;

  return __cmsg_nxthdr(msg_control, msg_controllen, cmsg);
}

static inline int process_cmsg(struct cmsghdr* real_cmsg,
                               struct cmsghdr* stack_cmsg,
                               size_t i, notify_t* n) {
  //clear_scm_index(n, i);
  if (stack_cmsg->cmsg_level == SOL_SOCKET) {
    n->scm[i].type = stack_cmsg->cmsg_type;
    switch (stack_cmsg->cmsg_type) {
      case SCM_RIGHTS: {
        int *fdp = (int*)CMSG_DATA(real_cmsg);
        u32 num = (stack_cmsg->cmsg_len-sizeof(struct cmsghdr)) / sizeof(int);
        n->scm[i].num = num;
        #pragma unroll
        for (size_t j = 0; j < SCM_RIGHTS_COUNT; j++) {
          if (j < num) {
            //n->scm[i].content.rights.fds[j] = fdp[j];
            bpf_probe_read(&n->scm[i].content.rights.fds[j], sizeof(int), &fdp[j]);
          } else {
            n->scm[i].content.rights.fds[j] = -1;
          }
        }
        break;
      }
      case SCM_CREDENTIALS: {
        if (stack_cmsg->cmsg_len != CMSG_LEN(sizeof(struct ucred))) {
          n->error_code = CMSG_BAD_LEN;
          n->error_msg = stack_cmsg->cmsg_len;
          return -1;
        }
        struct ucred* ucp = (struct ucred*)CMSG_DATA(real_cmsg);
        if (ucp == NULL){
          return -1;
        }
        //u32 ppp;
        //bpf_probe_read(&ppp, sizeof(u32), ucp);
        //if (ppp == 0){
        //  n->error_code = CMSG_CRED_ZERO_PID;
        //  n->error_msg = ppp;
        //  return -1;
        //}
        bpf_probe_read(&n->scm[i].content.creds, sizeof(struct ucred), ucp);
        //n->scm[i].content.creds.pad = 0;
        break;
      }
      default: {
        n->error_code = CMSG_WRONG_TYPE;
        n->error_msg = 0;
        return -1;
      }
    }
  }
  return 0;
}

int kprobe__unix_stream_sendmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg){
  notify_t n;
  {{notify_memset}}
  /*#pragma unroll
  for (size_t i=0; i < (sizeof(n)); i++) {
    ((char*)&n)[i] = 0;
  }*/
  n.cpu = bpf_get_smp_processor_id();
  n.type = SOCK_STREAM;

  u32 nxt = UINT32_MAX;

  char* sun_path_ptr = NULL;

  {
    size_t pid_tgid = bpf_get_current_pid_tgid();

    n.pid = (u32)(pid_tgid >> 32);
    n.peer_pid = 0xffffffff;
  }
  #ifdef EXCLUDE_PIDS
  if (is_excluded_pid(n.pid)) {
    return 0;
  }
  #endif

  struct sock* sk = sock->sk;

  if (sk->sk_family != AF_UNIX) {
    n.error_code = SK_NOT_UNIX;
    n.error_msg = 0;
    goto pre_is_bound_error;
  }

  struct unix_sock* us = unix_sk(sk);
  struct sock* peer = us->peer;

  if (peer->sk_family != AF_UNIX) {
    n.error_code = SK_PEER_NOT_UNIX;
    n.error_msg = peer->sk_family;
    goto pre_is_bound_error;
  }

  struct pid* peer_pid = sk->sk_peer_pid;
  if (peer_pid != NULL) {
    //n.peer_pid = pid_nr(peer_pid);
    n.peer_pid = peer_pid->numbers[0].nr;
  }

  #ifdef EXCLUDE_PIDS
  if (is_excluded_pid(n.peer_pid)) {
    return 0;
  }
  #endif

  #ifdef FILTER_PID
  if (n.pid != FILTER_PID && n.peer_pid != FILTER_PID) {
    return 0;
  }
  #elif defined FILTER_PAIR
  if (!(
    (n.pid == FILTER_PAIR_1 && n.peer_pid == FILTER_PAIR_2) ||
    (n.pid == FILTER_PAIR_2 && n.peer_pid == FILTER_PAIR_1)
  )) {
    return 0;
  }
  #elif defined INCLUDE_PIDS
  if (!is_included_pid(n.pid) && !is_included_pid(n.peer_pid)) {
    return 0;
  }
  #endif


  struct socket* sk_socket = sk->sk_socket;
  if (sk_socket) {
    n.sk_file = (uintptr_t) sk_socket->file;
  } else {
    n.sk_file = SIZE_MAX;
  }
  sk_socket = peer->sk_socket;
  if (sk_socket) {
    n.peer_file = (uintptr_t) sk_socket->file;
  } else {
    n.peer_file = SIZE_MAX;
  }

  struct unix_sock* up = unix_sk(peer);

  struct unix_sock* other = NULL;
  struct unix_sock* u = pick_sock(us, up, &other);
  n.is_bound = (uintptr_t)us == (uintptr_t)u;
  struct unix_address* addr = u->addr;

  n.sun_path_len = addr->len;

  if (n.sun_path_len > UNIX_PATH_MAX + sizeof(short)) {
    n.error_code = SUN_PATH_LEN_TOO_BIG;
    n.error_msg = 0;
    goto pre_path_error;
  } else if (n.sun_path_len < sizeof(short)) {
    //pass
  } else {
    n.sun_path_len -= sizeof(short);
  }
  #if defined(FILTER_UNIX) && !defined(BEGINS_WITH)
    char sun_path[UNIX_PATH_MAX+1];
    sun_path_ptr = sun_path;
  #else
    sun_path_ptr = n.u.sun_path;
  #endif

  //note: it's a bit of a waste to always copy the path to the stack, even if
  //      we aren't actually filtering on it. i've tried a few different ways
  //      to split up this logic across the ifdefs, but the main buffer copy
  //      always flags a `min value is negative, either use unsigned or 'var &= const'`
  //      check that has no basis in reality if we try to do a copy after
  //      the ring buffer entry checks, regardless of whether we copy the path
  //      onto the stack or directly into the entry.

  if (n.sun_path_len > 0) {
    #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
    n.u.fill[13] = 0;
    #endif
    if (addr->hash < UNIX_HASH_SIZE) {
      bpf_probe_read(sun_path_ptr, UNIX_PATH_MAX, addr->name->sun_path);
      sun_path_ptr[0] = '@';
    } else {
      if (n.sun_path_len > 0) {
        n.sun_path_len -= 1;
      }
      bpf_probe_read(sun_path_ptr, UNIX_PATH_MAX, addr->name->sun_path);
    }
    sun_path_ptr[UNIX_PATH_MAX] = '\\0';
  } else {
    #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
    #pragma unroll
    for (size_t i=0; i < 14; i++) {
      n.u.fill[i] = 0;
    }
    #endif
  }

  #ifdef FILTER_UNIX
  if (!cmp_sun_path(sun_path_ptr, n.sun_path_len)) {
    return 0;
  }
  #endif

  //note: while it would be preferable to just null out the sections we don't
  //      use, the bpf validator is throwing a tantrum when we tried to do
  //      that. for now, we waste a bunch of extra writes to appease it.
  clear_scm(&n, 0);
  if (msg != NULL) {
    struct msghdr mhdr;
    bpf_probe_read((void*)&mhdr, sizeof(mhdr), (void*)msg);
    struct cmsghdr *_cmsg = NULL;
    _cmsg = cmsg_firsthdr_x((struct msghdr*)&mhdr);

    struct cmsghdr cmsg;

    #ifdef ANCILLARY
    if (_cmsg == NULL){
      return 0;
    }
    #endif

    //size_t _i = SIZE_MAX;
    #pragma unroll
    for (size_t i = 0; i < ANCILLARY_COUNT; i++) {
      if (_cmsg) {
        bpf_probe_read(&cmsg, sizeof(struct cmsghdr), _cmsg);

        //note: we expand out the macro as such because we are not actually
        //      making full copies, but some of the math is done on the actual
        //      addresses.
        // if (!CMSG_OK(...) {
        if (!(cmsg.cmsg_len >= sizeof(struct cmsghdr)
            && cmsg.cmsg_len <= (mhdr.msg_controllen - ((void*)_cmsg - mhdr.msg_control))
          )) {
          if (cmsg.cmsg_len < sizeof(struct cmsghdr)) {
            n.error_code = CMSG_NOT_OK;
            n.error_msg = cmsg.cmsg_len;
          } else {
            n.error_code = CMSG_NOT_OK;
            n.error_msg = (mhdr.msg_controllen - ((void*)_cmsg - mhdr.msg_control)) - cmsg.cmsg_len;
          }

          goto pre_index_error;
        }

        if (process_cmsg(_cmsg, &cmsg, i, &n) != 0) {
          n.error_code = CMSG_BAD;
          n.error_msg = i;
          goto pre_index_error;
        }

        //note: when copying msghdr to stack, CMSG_NXTHDR doesn't directly trip
        //      the validator, but the resulting cmsghdr* cannot meaningfully
        //      be used w/o tripping the validator, even if you copy it to the
        //      stack. the thing that seems to have really made the change is
        //      using the cmsg_len from the cmsghdr copy on the stack.
        //_cmsg = CMSG_NXTHDR(&mhdr, _cmsg);
        _cmsg = (struct cmsghdr*)((void*)_cmsg + CMSG_ALIGN(cmsg.cmsg_len));

        if ( (((void*)_cmsg)+1 - mhdr.msg_control) > mhdr.msg_controllen) {
          _cmsg = NULL;
        }
      } else {

        //if (_i == SIZE_MAX) {
        //  _i = i;
        //}
        //break;
      }
    }

    //note: if there was another message when we stopped iterating,
    //      mark it using the high bit of the type
    if (_cmsg != NULL) {
      u32 t = 0x80000000 | n.scm[ANCILLARY_COUNT-1].type;
      n.scm[ANCILLARY_COUNT-1].type = t;
    }
    //clear_scm(&n, _i);
  }


  size_t len = msg->msg_iter.iov->iov_len;
  void* base = msg->msg_iter.iov->iov_base;

  //note: reporting 0 length writes may identify ancillary data
  /*if (len == 0) {
    return 0;
  }*/

  if (base == NULL) {
    n.error_code = IOVEC_BASE_NULL;
    n.error_msg = 0;
    goto pre_index_error;
  }

  size_t orig_len = len;

  if (len > BUFFER_SIZE) {
    //note: cannot be the same b/c of yet another incorrect validation check
    len = BUFFER_SIZE - 1;
    //len = BUFFER_SIZE; // works, but not chancing it
  }

  struct sync_t* sync = NULL;

  int key = 0;
  sync = sync_buf.lookup(&key);
  if (!sync) {
    return 0;
  }

  //note: we do this to force the compiler to generate a specific bytecode
  //      implementation (short/fixed-size) that is accepted by the validator.
  //      ideomatic code optimizes differently and is rejected.
  // 79 01 00 00 00 00 00 00    r1 = *(u64 *)(r0 + 0)
  // bf 13 00 00 00 00 00 00    r3 = r1
  // 07 03 00 00 01 00 00 00    r3 += 1
  // b7 02 00 00 XX XX XX XX    r2 = N
  // 2d 12 01 00 00 00 00 00    if r2 > r1 goto +1
  // b7 03 00 00 01 00 00 00    r3 = 1
  // 7b 30 00 00 00 00 00 00    *(u64 *)(r0 + 0) = r3
  // 2d 12 01 00 00 00 00 00    if r2 > r1 goto +1
  // b7 01 00 00 00 00 00 00    r1 = 0

  nxt = 0;
  {{ratchet_switch}}
  n.index = nxt;

  data_t* entry = NULL;
  int _n = (int)nxt;
  entry = ring_buf.lookup(&_n); \
  if (entry == NULL) {
    n.error_code = RINGBUF_ENTRY_NULL;
    n.error_msg = 0;
    goto pre_is_truncated_error;
  }
  if (entry->used) {
    n.error_code = NO_SLOTS_AVAILABLE;
    n.error_msg = _n;
    goto pre_is_truncated_error;
  }

  n.is_truncated = orig_len > len ? 1 : 0;
  int l = (int)len;
  if (l > 0) {
    entry->used = 1;
    copy_into_entry_buffer(entry, len, base, &n.is_truncated);
  } else {
    n.error_code = SIGNED_LEN_NEGATIVE;
    n.error_msg = 0;
    goto no_buffer_error;
  }

  n.len = len;
  n.error_code = 0;
  n.error_msg = 0;
  notify(&n, ctx);
  return 0;
  //goto end;

pre_is_bound_error:
  n.is_bound = 0;

pre_path_error:
  n.sun_path_len = 0;
  #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
  #pragma unroll
  for (size_t i=0; i < 14; i++) {
    n.u.fill[i] = 0;
  }
  #endif
pre_file_error:
  n.sk_file = SIZE_MAX;
  n.peer_file = SIZE_MAX;

  clear_scm(&n, 0);
pre_index_error:
  n.index = UINT32_MAX;
pre_is_truncated_error:
  n.is_truncated = 0;
no_buffer_error:
  n.len = UINT32_MAX;
  notify(&n, ctx);
end:
  return 0;
}

int kprobe__unix_dgram_sendmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg){
  notify_t n;
  {{notify_memset}}
  /*#pragma unroll
  for (size_t i=0; i < sizeof(n); i++) {
    ((char*)&n)[i] = 0;
  }*/
  n.cpu = bpf_get_smp_processor_id();
  n.type = SOCK_DGRAM;

  u32 nxt = UINT32_MAX;

  char* sun_path_ptr = NULL;

  {
    size_t pid_tgid = bpf_get_current_pid_tgid();

    n.pid = (u32)(pid_tgid >> 32);
    n.peer_pid = 0xffffffff;
  }
  #ifdef EXCLUDE_PIDS
  if (is_excluded_pid(n.pid)) {
    return 0;
  }
  #endif

  struct sock* sk = sock->sk;

  if (sk == NULL){
    n.error_code = SK_NULL;
    n.error_msg = 0;
    goto pre_is_bound_error;
  }

  if (sk->sk_family != AF_UNIX) {
    n.error_code = SK_NOT_UNIX;
    n.error_msg = 0;
    goto pre_is_bound_error;
  }

  struct unix_sock* us = unix_sk(sk);

  if (us == NULL){
    n.error_code = SK_NULL;
    n.error_msg = 0;
    goto pre_is_bound_error;
  }

  struct sock* peer = us->peer;

  /*if (peer == NULL){
    n.error_code = SK_PEER_NULL;
    n.error_msg = 0;
    goto pre_is_bound_error;
  }

  if (peer->sk_family != AF_UNIX) {
    n.error_code = SK_PEER_NOT_UNIX;
    n.error_msg = peer->sk_family;
    goto pre_is_bound_error;
  }*/

  struct pid* peer_pid = sk->sk_peer_pid;
  if (peer_pid != NULL) {
    //n.peer_pid = pid_nr(peer_pid);
    n.peer_pid = peer_pid->numbers[0].nr;
  }

  #ifdef EXCLUDE_PIDS
  if (is_excluded_pid(n.peer_pid)) {
    return 0;
  }
  #endif

  #ifdef FILTER_PID
  if (n.pid != FILTER_PID && n.peer_pid != FILTER_PID) {
    return 0;
  }
  #elif defined INCLUDE_PIDS
  if (!is_included_pid(n.pid) && !is_included_pid(n.peer_pid)) {
    return 0;
  }
  #endif

  #if defined(FILTER_UNIX) && !defined(BEGINS_WITH)
    char sun_path[UNIX_PATH_MAX+1];
    sun_path_ptr = sun_path;
  #else
    sun_path_ptr = n.u.sun_path;
  #endif

  struct socket* sk_socket = sk->sk_socket;
  if (sk_socket) {
    n.sk_file = (uintptr_t) sk_socket->file;
  } else {
    n.sk_file = SIZE_MAX;
  }

  sk_socket = peer->sk_socket;
  if (sk_socket) {
    n.peer_file = (uintptr_t) sk_socket->file;
  } else {
    n.peer_file = SIZE_MAX;
  }

  //note: here there be dragons.
  //      beware "connected" dgrams,
  //      and their tricksy ways.
  //
  //      the "normal" path here is that msg_namelen will contain a value.
  //      this is because for unconnected sockets, the default for datagrams,
  //      the data structure layout containing the sockaddr metadata is in
  //      the msghdr, which is the same for connect syscalls. the idea being
  //      that the first thing in the kernel to see sockaddr metadata in
  //      msghdr needs to add it to the socket itself. however, datagrams
  //      _can_ be connected, so that one could simply read/write the socket
  //      fd. basically nothing does this other than socketpair(2), which
  //      has blank a sun_path anyway. however, if one wants to send file
  //      descriptors over a datagram unix socket, the socket will need to
  //      be connected. this is arguably a limitation in the unix apis, as
  //      fds can only be send/received through sendmsg/recvmsg, which take
  //      a file descriptor and do not have a sendto/recvfrom-alike. in this
  //      case, one of the sockets may well have been bound to a path/abstract
  //      namespace key, and so we would then need to fetch the sockaddr
  //      metadata from the sockets themselves.

  int msg_namelen = msg->msg_namelen;

  char* orig_sun_path = NULL;
  bool connected = msg_namelen == 0;

  if (!connected) {
    n.is_bound = false;

    //note: There is something screwy about how this copy is done.
    //      If this assignment happens after orig_sun_path is set,
    //      orig_sun_path will be corrupted.
    n.sun_path_len = msg->msg_namelen;

    void* msg_name = msg->msg_name;
    struct sockaddr_un* sunaddr = (struct sockaddr_un*)msg_name;
    orig_sun_path = &sunaddr->sun_path[0];

  } else {
    struct unix_sock* up = unix_sk(peer);

    struct unix_sock* other = NULL;
    struct unix_sock* u = pick_sock(us, up, &other);
    n.is_bound = (uintptr_t)us == (uintptr_t)u;

    //note: for whatever reason, in this if/else context, bcc has no idea how
    //      to handle dereferences, so we need to manually do _all_ of the
    //      bpf_probe_read calls ourselves.

    struct unix_address* addr = NULL;
    bpf_probe_read(&addr,
                   sizeof(struct unix_address*),
                   (void*)u + offsetof(struct unix_sock, addr)
    );


    int al = 0;
    bpf_probe_read(&al,
                   sizeof(int),
                   (void*)addr + offsetof(struct unix_address, len)
    );
    n.sun_path_len = al;

    size_t off1 = offsetof(struct unix_address, name);
    size_t off2 = offsetof(struct sockaddr_un, sun_path);
    char* nn = ((char*)addr) + off1 + off2;
    orig_sun_path = nn;
  }

  if (n.sun_path_len > UNIX_PATH_MAX + sizeof(short)) {
    n.error_code = SUN_PATH_LEN_TOO_BIG;
    n.error_msg = 0;
    goto pre_path_error;
  } else if (n.sun_path_len < sizeof(short)) {
    //pass
  } else {
    n.sun_path_len -= sizeof(short);
  }


  //note: it's a bit of a waste to always copy the path to the stack, even if
  //      we aren't actually filtering on it. i've tried a few different ways
  //      to split up this logic across the ifdefs, but the main buffer copy
  //      always flags a `min value is negative, either use unsigned or 'var &= const'`
  //      check that has no basis in reality if we try to do a copy after
  //      the ring buffer entry checks, regardless of whether we copy the path
  //      onto the stack or directly into the entry.

  if (n.sun_path_len > 0) {
    #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
    n.u.fill[13] = 0;
    #endif

    //note: assuming the common sendto flow, the hash has not actually been
    //      calculated by the kernel yet, so we can't rely on that and just
    //      check if the sun_path starts w/ a NUL. it's worth noting that
    //      right now, we may well receive garbage that the kernel would end
    //      up rejecting for various reasons. it also means that the sun_path
    //      length value from msghdr is not of the processed form it would be
    //      for a connected socket (where we usually discount 1 byte for
    //      path-based sockets).
    char fst = *orig_sun_path;
    bool abstract = fst == '\\0';
    if (connected && !abstract) {
      if (n.sun_path_len > 0) {
        n.sun_path_len -= 1;
      }
    }
    bpf_probe_read(sun_path_ptr, UNIX_PATH_MAX, orig_sun_path);

    if (abstract) {
      sun_path_ptr[0] = '@';
    }
    sun_path_ptr[UNIX_PATH_MAX] = '\\0';
  } else {
    #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
    #pragma unroll
    for (size_t i=0; i < 14; i++) {
      n.u.fill[i] = 0;
    }
    #endif
  }

  #ifdef FILTER_UNIX
  if (!cmp_sun_path(sun_path_ptr, n.sun_path_len)) {
    return 0;
  }
  #endif


  //note: while it would be preferable to just null out the sections we don't
  //      use, the bpf validator is throwing a tantrum when we tried to do
  //      that. for now, we waste a bunch of extra writes to appease it.
  clear_scm(&n, 0);
  if (msg != NULL) {
    struct msghdr mhdr;
    bpf_probe_read((void*)&mhdr, sizeof(mhdr), (void*)msg);
    struct cmsghdr *_cmsg = NULL;
    _cmsg = cmsg_firsthdr_x((struct msghdr*)&mhdr);

    struct cmsghdr cmsg;

    #ifdef ANCILLARY
    if (_cmsg == NULL){
      return 0;
    }
    #endif

    //size_t _i = SIZE_MAX;
    #pragma unroll
    for (size_t i = 0; i < ANCILLARY_COUNT; i++) {
      if (_cmsg) {
        bpf_probe_read(&cmsg, sizeof(struct cmsghdr), _cmsg);

        //note: we expand out the macro as such because we are not actually
        //      making full copies, but some of the math is done on the actual
        //      addresses.
        // if (!CMSG_OK(...) {
        if (!(cmsg.cmsg_len >= sizeof(struct cmsghdr)
            && cmsg.cmsg_len <= (mhdr.msg_controllen - ((void*)_cmsg - mhdr.msg_control))
          )) {
          if (cmsg.cmsg_len < sizeof(struct cmsghdr)) {
            n.error_code = CMSG_NOT_OK;
            n.error_msg = cmsg.cmsg_len;
          } else {
            n.error_code = CMSG_NOT_OK;
            n.error_msg = (mhdr.msg_controllen - ((void*)_cmsg - mhdr.msg_control)) - cmsg.cmsg_len;
          }

          goto pre_index_error;
        }

        if (process_cmsg(_cmsg, &cmsg, i, &n) != 0) {
          n.error_code = CMSG_BAD;
          n.error_msg = i;
          goto pre_index_error;
        }

        //note: when copying msghdr to stack, CMSG_NXTHDR doesn't directly trip
        //      the validator, but the resulting cmsghdr* cannot meaningfully
        //      be used w/o tripping the validator, even if you copy it to the
        //      stack. the thing that seems to have really made the change is
        //      using the cmsg_len from the cmsghdr copy on the stack.
        //_cmsg = CMSG_NXTHDR(&mhdr, _cmsg);
        _cmsg = (struct cmsghdr*)((void*)_cmsg + CMSG_ALIGN(cmsg.cmsg_len));

        if ( (((void*)_cmsg)+1 - mhdr.msg_control) > mhdr.msg_controllen) {
          _cmsg = NULL;
        }
      } else {

        //if (_i == SIZE_MAX) {
        //  _i = i;
        //}
        //break;
      }
    }

    //note: if there was another message when we stopped iterating,
    //      mark it using the high bit of the type
    if (_cmsg != NULL) {
      u32 t = 0x80000000 | n.scm[ANCILLARY_COUNT-1].type;
      n.scm[ANCILLARY_COUNT-1].type = t;
    }
    //clear_scm(&n, _i);
  }


  size_t len = msg->msg_iter.iov->iov_len;
  void* base = msg->msg_iter.iov->iov_base;

  //note: reporting 0 length writes may identify ancillary data
  /*if (len == 0) {
    return 0;
  }*/

  if (base == NULL) {
    n.error_code = IOVEC_BASE_NULL;
    n.error_msg = 0;
    goto pre_index_error;
  }

  size_t orig_len = len;

  if (len > BUFFER_SIZE) {
    //note: cannot be the same b/c of yet another incorrect validation check
    len = BUFFER_SIZE - 1;
  }

  struct sync_t* sync = NULL;

  int key = 0;
  sync = sync_buf.lookup(&key);
  if (!sync) {
    return 0;
  }

  //note: we do this to force the compiler to generate a specific bytecode
  //      implementation (short/fixed-size) that is accepted by the validator.
  //      ideomatic code optimizes differently and is rejected.
  // 79 01 00 00 00 00 00 00    r1 = *(u64 *)(r0 + 0)
  // bf 13 00 00 00 00 00 00    r3 = r1
  // 07 03 00 00 01 00 00 00    r3 += 1
  // b7 02 00 00 XX XX XX XX    r2 = N
  // 2d 12 01 00 00 00 00 00    if r2 > r1 goto +1
  // b7 03 00 00 01 00 00 00    r3 = 1
  // 7b 30 00 00 00 00 00 00    *(u64 *)(r0 + 0) = r3
  // 2d 12 01 00 00 00 00 00    if r2 > r1 goto +1
  // b7 01 00 00 00 00 00 00    r1 = 0

  nxt = 0;
  {{ratchet_switch}}
  n.index = nxt;

  data_t* entry = NULL;
  int _n = (int)nxt;
  entry = ring_buf.lookup(&_n); \
  if (entry == NULL) {
    n.error_code = RINGBUF_ENTRY_NULL;
    n.error_msg = 0;
    goto pre_is_truncated_error;
  }
  if (entry->used) {
    n.error_code = NO_SLOTS_AVAILABLE;
    n.error_msg = _n;
    goto pre_is_truncated_error;
  }

  n.is_truncated = orig_len > len ? 1 : 0;
  int l = (int)len;
  if (l > 0) {
    copy_into_entry_buffer(entry, len, base, &n.is_truncated);
    entry->used = 1;
  } else {
    n.error_code = SIGNED_LEN_NEGATIVE;
    n.error_msg = 0;
    goto no_buffer_error;
  }

  n.len = len;
  n.error_code = 0;
  n.error_msg = 0;
  notify(&n, ctx);
  return 0;
  //goto end;

pre_is_bound_error:
  n.is_bound = 0;

pre_path_error:
  n.sun_path_len = 0;
  #if !defined(FILTER_UNIX) || defined(BEGINS_WITH)
  #pragma unroll
  for (size_t i=0; i < 14; i++) {
    n.u.fill[i] = 0;
  }
  #endif
pre_file_error:
  n.sk_file = SIZE_MAX;
  n.peer_file = SIZE_MAX;

  clear_scm(&n, 0);
pre_index_error:
  n.index = UINT32_MAX;
pre_is_truncated_error:
  n.is_truncated = 0;
no_buffer_error:
  n.len = UINT32_MAX;
  notify(&n, ctx);
end:
  return 0;
}

"""
  text = render_code(code_template, format_args)

  if args.preprocessonly:
    print(text)
    sys.exit(0)

  #UNIX_PATH_MAX = 108

  class scm_rights(ctypes.Structure):
    _fields_ = [
      ("fds", ctypes.c_int*args.scmrightscount),
    ]

  class scm_credentials(ctypes.Structure):
    _fields_ = [
      ("pid", ctypes.c_uint32),
      ("uid", ctypes.c_uint32),
      ("gid", ctypes.c_uint32),
      ("pad", ctypes.c_uint32),
    ]

  class scm_content(ctypes.Union):
    _fields_ = [
      ("rights", scm_rights),
      ("creds", scm_credentials),
    ]

  class scm_data(ctypes.Structure):
    _fields_ = [
      ("type", ctypes.c_uint32),
      ("num", ctypes.c_uint32),
      ("content", scm_content),
    ]

  class notify_t(ctypes.Structure):
    _fields_ = [
      ("cpu", ctypes.c_uint16),
      ("type", ctypes.c_uint16),
      ("index", ctypes.c_uint32),
      ("sk_file", ctypes.c_size_t),
      ("peer_file", ctypes.c_size_t),
      ("pid", ctypes.c_uint32),
      ("peer_pid", ctypes.c_uint32),
      ("is_bound", ctypes.c_uint8),
      ("is_truncated", ctypes.c_uint8),
      ("sun_path_len", ctypes.c_uint8),
      ("error_code", ctypes.c_uint8),
      ("len", ctypes.c_uint32),
      ("error_msg", ctypes.c_size_t),
      ("scm_data", scm_data*args.ancillarycount),
      ("sun_path", ctypes.c_size_t*14),
    ]

  # TODO: convert to inline python 3 f-strings
  #       consider converting to % format string for performance in python 2
  sun_path_template = '''\
sun_path: {!r}, length {}
'''
  printed_template = '''\
{} PID {}.0x{:x} ({}) > {}.0x{:x} ({}), length {}{}
'''
  written_template = '''\
{} PID {}.0x{:x} ({}) > {}.0x{:x} ({})
'''
  command_template = '''\
command[{}]: {!r}
'''
  def format_printed_metadata(args, sun_path, ts, sock_type, is_bound,
                              pid, sk_file, command,
                              peer_pid, peer_file, peer_command,
                              data_len, data_is_truncated):
    out_str = ''
    if args.socket is not None and args.verbose:
      # should have already been set
      out_str += sun_path_template.format(sun_path, len(sun_path))
    elif args.socket is None:
      out_str += sun_path_template.format(sun_path, len(sun_path))

    sock_type_str = { 1: 'STREAM', 2: 'DGRAM' }[sock_type]
    role = "S" if is_bound else "C"
    peer_role = "S" if not is_bound else "C"
    data_truncated_str = " (truncated)" if data_is_truncated else ""

    out_str += printed_template.format(
                sock_type_str, pid, sk_file, role,
                peer_pid, peer_file, peer_role, data_len, data_truncated_str)

    pid_str = str(pid)
    peer_pid_str = str(peer_pid)
    m = max(len(pid_str), len(peer_pid_str))

    if args.verbose or (
        (len(args.pids) != 1 or args.pids[0] != pid)
        and len(args.pairs) != 1
      ):
      out_str += command_template.format(pid_str.rjust(m), command)
    if args.verbose or (
        (len(args.pids) != 1 or args.pids[0] != peer_pid)
        and len(args.pairs) != 1
      ):
      out_str += command_template.format(peer_pid_str.rjust(m), peer_command)
    return out_str

  def format_written_metadata(sun_path, sock_type, is_bound,
                              pid, sk_file, command,
                              peer_pid, peer_file, peer_command):
    out_str = ''
    out_str += sun_path_template.format(sun_path, len(sun_path))

    sock_type_str = { 1: 'STREAM', 2: 'DGRAM' }[sock_type]
    role = "S" if is_bound else "C"
    peer_role = "S" if not is_bound else "C"

    out_str += written_template.format(
                sock_type_str, pid, sk_file, role,
                peer_pid, peer_file, peer_role)

    pid_str = str(pid)
    peer_pid_str = str(peer_pid)
    m = max(len(pid_str), len(peer_pid_str))

    out_str += command_template.format(pid_str.rjust(m), command)
    out_str += command_template.format(peer_pid_str.rjust(m), peer_command)

    return out_str

  def dump_stats():
    if not args.stats:
      return
    sys.stderr.write("\n\n")
    sys.stderr.write("events_count: {}\n".format(events_count))
    sys.stderr.write("used_zero_count: {}\n".format(used_zero_count))
    sys.stderr.write("used_zero_queue: {}\n".format(used_zero_queue))
    sys.stderr.write("dropped_used_zero_count: {}\n".format(dropped_used_zero_count))
    sys.stderr.write("no_slots_count: {}\n".format(no_slots_count))

    sys.stderr.write("\n")

  ancillary_preamble_template = 'ancillary data sent (attempted): {} CMSG{} observed{}\n'
  scm_creds_template    = '  SCM_CREDENTIALS: pid={} uid={} gid={}\n'
  scm_rights_header     = '  SCM_RIGHTS: '
  scm_rights_template_a = 'FD {}, {}\n'
  scm_rights_template_b = '              FD {}, {}\n'
  scm_rights_template_c = '(truncated)\n'
  scm_rights_template_d = '              (truncated)\n'
  def handle_ancillary_data(event, pid):
    out_str = ''
    id_map = {}
    cmsg_count = 0

    had_scm_rights_header = False
    for scm in event.scm_data:
      scm_type = int(scm.type) & 0xffff
      if scm_type == 0:
        break
      elif scm_type == 1: # SCM_RIGHTS
        cmsg_count += 1
        out_str += '  SCM_RIGHTS: '
        scm_fds = []
        num = int(scm.num)
        fd_cap = len(scm.content.rights.fds)
        fd_trunc = False
        if num > fd_cap:
          fd_trunc = True
        for i in range(min(num, fd_cap)):
          scm_fds.append(int(scm.content.rights.fds[i]))
        for scm_fd in scm_fds:
          proc_path = "/proc/{}/fd/{}".format(pid, scm_fd)
          proc_link = None
          if proc_path in fd_map:
            proc_link = fd_map[proc_path]
          else:
            try:
              fd_map[proc_path] = proc_link = repr(os.readlink(proc_path))[1:]
            except OSError:
              proc_link = "(failed to read proc link)"
          if not had_scm_rights_header:
            out_str += scm_rights_template_a.format(scm_fd, proc_link)
            had_scm_rights_header = True
          else:
            out_str += scm_rights_template_b.format(scm_fd, proc_link)
        if fd_trunc:
          if not had_scm_rights_header:
            out_str += scm_rights_template_c
          else:
            out_str += scm_rights_template_d
        had_scm_rights_header = False
      elif scm_type == 2: # SCM_CREDENTIALS
        cmsg_count += 1
        scm_pid = int(scm.content.creds.pid)
        scm_uid = int(scm.content.creds.uid)
        scm_gid = int(scm.content.creds.gid)
        if scm_uid in id_map:
          cred_ids = id_map[scm_uid]
        else:
          cred_ids = check_output(['id', str(scm_uid)], shell=False).strip()
          cred_ids = [c.split('=') for c in cred_ids.split(' ')]
          id_map[scm_uid] = cred_ids

        out_str += scm_creds_template.format(
                     scm_pid, cred_ids[0][1], cred_ids[1][1]
                   )
      else:
        out_str += '  INVALID CMSG of type: 0x{:x}\n'.format(scm_type)

    if cmsg_count > 0:
      plural = '' if cmsg_count == 1 else "s"
      trunc = ''
      if event.scm_data[args.ancillarycount-1].type & 0xffff0000 != 0:
        trunc = ' (truncated)'
      return ancillary_preamble_template.format(cmsg_count, plural, trunc) + out_str
    return ''


  def print_event(cpu, data, size, rec=0):
    global events_count
    global used_zero_count
    global used_zero_queue
    global dropped_used_zero_count
    global no_slots_count

    if rec > args.retry:
      dropped_used_zero_count += 1
      return -1

    # will likely cause events to print out of order
    # todo: add metadata to buffer_t to confirm it matches the retried event
    if not args.dir:
      if len(used_zero_queue) > 0:
        copy_queue = used_zero_queue
        used_zero_queue = []
        for event in copy_queue:
          events_count -= 1
          #used_zero_count -= 1
          r = print_event(*event)
          if r == None:
            used_zero_count -= 1

    events_count += 1
    try:
      event = ctypes.cast(data, ctypes.POINTER(notify_t)).contents
      sock_type = int(event.type)
      if sock_type not in [1, 2]:
        if not args.dir: print("====")
        sys.stderr.write("INVALID event.type: " + str(sock_type) + "\n")
        return

      if args.socket is None or args.beginswith:
        sun_path = ctypes.string_at(event.sun_path, event.sun_path_len)
      else:
        sun_path = args.socket

      # ideally, by the time we have ts, we'll also be using pcapng
      # so we won't have to worry about writing metadata only once to disk
      ts = 0
      is_bound = event.is_bound

      peer_role = "server" if is_bound else "client"

      typ = { 1: 'SOCK_STREAM', 2: 'SOCK_DGRAM' }[sock_type]
      idx = int(event.index)
      if args.debug and rec == 0:
        print("cpu: " + str(cpu) + ":" + str(event.cpu))
        print("idx: " + str(idx))

      pid = event.pid
      command = "(unknown)"
      if args.verbose or (len(args.pids) != 1 or args.pids[0] != pid):
        if pid in pid_map:
          command = pid_map[pid]
        else:
          try:
            proc = check_output(['ps', '-q', str(pid), '-o', 'args='],
                                shell=False, stderr=-2).strip()
          except CalledProcessError as ex:
            proc = str('(already terminated)')

          pid_map[pid] = proc
          command = proc

      peer_pid = event.peer_pid
      peer_command = "(unknown)"
      if args.verbose or (len(args.pids) != 1 or args.pids[0] != peer_pid):
        if peer_pid in pid_map:
          peer_command = pid_map[peer_pid]
        else:
          try:
            proc = check_output(['ps', '-q', str(peer_pid), '-o', 'args='],
                                shell=False, stderr=-2).strip()
          except CalledProcessError as ex:
            proc = str('(already terminated)')
          pid_map[peer_pid] = proc
          peer_command = proc

      error_code = int(event.error_code)
      if error_code != 0:
        metadata = format_printed_metadata(
                     args, sun_path, ts, sock_type, is_bound,
                     pid, event.sk_file, command,
                     peer_pid, event.peer_file, peer_command,
                     int(event.len), event.is_truncated)

        if not args.dir:
          sys.stdout.write("====\nerror!\n")
          sys.stdout.write(metadata)
          sys.stdout.write("error: {}\n".format(errors_rev[error_code]))
          sys.stdout.write("error_msg: 0x{:x}\n".format(int(event.error_msg)))
        else:
          # error log writing
          error_filename = 'unixdump_error.log'
          file_directory = args.dir
          current_file = os.path.join(file_directory, error_filename)
          mode = 'a' if os.path.exists(current_file) else 'w'
          with open(str(current_file), mode) as e:
            e.write('====\n')
            e.write(metadata)
            e.write("error: {}\n".format(errors_rev[error_code]))
            e.write("error_msg: 0x{:x}\n".format(int(event.error_msg)))
        if error_code == errors['NO_SLOTS_AVAILABLE']:
          no_slots_count += 1
          py_ring.clearitem(int(event.error_msg))

        return

      entry = py_ring[idx][cpu]

      # need to somehow fit this appropriately
      if args.debug and rec == 0:
        print("used: {}".format(entry.used))

      if entry.used == 0:
        if rec == 0:
          used_zero_count += 1
        if args.dir:
          r = print_event(cpu, data, size, rec+1) # can lock up w/ overly recursive calls
          if rec == 0 and r == None:
            used_zero_count -= 1
          else:
            if not args.dir: print("used: 0")
            return r
        else:
          used_zero_queue.append([cpu, data, size, rec+1])
          return -1

      buffer = ctypes.string_at(entry.buffer, int(event.len))

      if not args.dir:
        sys.stdout.write("====\n")
        sys.stdout.write(
          format_printed_metadata(args, sun_path, ts, sock_type, is_bound,
                                  pid, event.sk_file, command,
                                  peer_pid, event.peer_file, peer_command,
                                  int(event.len), event.is_truncated)
        )
        ancillary_result = handle_ancillary_data(event, pid)
        if ancillary_result:
          print(ancillary_result)

        #todo: add type to file output
        #if not args.dir: print("type: " + typ)

        print("----")
        hexdump.hexdump(buffer)
      else:
        # dir/file name setup
        current_filename = None
        file_directory = args.dir

        pair_key = "{}-{}-{}-{}".format(str(pid), str(peer_pid),'0x{:x}'.format(event.sk_file),
              '0x{:x}'.format(event.peer_file))
        if pair_key in pid_pair_map:
          current_filename = pid_pair_map[pair_key]['fn']
        else:
          rev_pkey = "{}-{}-{}-{}".format(str(peer_pid), str(pid),'0x{:x}'.format(event.peer_file),
              '0x{:x}'.format(event.sk_file))
          pair_obj = { 'fn': '{}-{}'.format(pair_key,
              repr(sun_path).replace('/','_'))}
          pid_pair_map[pair_key] = pair_obj
          pid_pair_map[rev_pkey] = pair_obj
          current_filename = pid_pair_map[pair_key]['fn']

        current_file = os.path.join(file_directory, current_filename)
        mode = 'a' if os.path.exists(current_file) else 'w'
        with open(str(current_file), mode) as f:
          if mode == 'w':
            if args.verbose:
              print("writing to {} for: {}".format(current_filename, command))
            f.write(
              format_written_metadata(sun_path, sock_type, is_bound,
                                      pid, event.sk_file, command,
                                      peer_pid, event.peer_file, peer_command)
            )
          if is_bound:
            f.write("{} -> {}{}\n< ".format(str(pid),str(peer_pid),bcolors.BLUE))
            f.write(hexdump.hexdump(buffer, result='return').replace('\n','\n< '))
            f.write("\n")
            f.write(handle_ancillary_data(event, pid))
          else:
            f.write("{} -> {}{}\n> ".format(str(pid),str(peer_pid),bcolors.RED))
            f.write(hexdump.hexdump(buffer, result='return').replace('\n','\n> '))
            f.write("\n")
            f.write(handle_ancillary_data(event, pid))
          f.write('\n{}========\n'.format(bcolors.ENDC))
      py_ring.clearitem(idx)

    except KeyboardInterrupt:
      dump_stats()
      sys.exit(0)

  #b = BPF(text=text).trace_print()
  #b = BPF(text=text, debug=0x8)

  libc = ctypes.CDLL('libc.so.6')
  nstderr = libc.dup(2)
  PipeInType = ctypes.c_int * 2
  pipe_in = PipeInType(0,0)
  p_pipe_in = ctypes.pointer(pipe_in)
  libc.pipe(p_pipe_in)
  libc.close(2)
  r = libc.dup2(pipe_in[1], 2)

  pipe_err_poll = select.poll()
  pipe_err_poll.register(pipe_in[0], select.POLLIN | select.POLLPRI)

  b = None
  err_buf = b""
  e = None
  try:
    b = BPF(text=text)
  except Exception as _e:
    e = _e
    while True:
      poll_res = pipe_err_poll.poll(1)
      if len(poll_res) == 0:
        break
      err_buf += os.read(pipe_in[0], 1024)

  if e != None and str(e).find("Failed to load") != -1:
    if args.debug:
      print("[debug] First attempt to load program failed")
      os.write(nstderr, err_buf)
      print(str(e))

    err_buf = err_buf.decode('utf-8').strip()
    err_lines = err_buf.split('\n')
    if err_lines[-2].startswith("invalid indirect read from stack"):
      if args.debug:
        print("[debug] Trying again with notify_t memset")
      format_args['notify_memset'] = notify_memset
      text = render_code(code_template, format_args)

      e = None
      nerr_buf = b"" # for extra debugging, we will probably want both error messages in case they are different
      try:
        b = BPF(text=text)
      except Exception as _e:
        while True:
          poll_res = pipe_err_poll.poll(1)
          if len(poll_res) == 0:
            break
          nerr_buf += os.read(pipe_in[0], 1024)
        if args.debug:
          print("[debug] Second attempt to load program (with notify_t memset) failed")
          os.write(nstderr, err_buf)
          print(str(_e))
        #nerr_buf = nerr_buf.decode('utf-8').strip()

  libc.close(pipe_in[1])
  libc.close(pipe_in[0])
  libc.close(2)
  libc.dup2(nstderr, 2)
  libc.close(nstderr)

  if e != None:
    if not args.debug:
      print(err_buf, file=sys.stderr)
      print(str(e))
    sys.exit(1)

  py_ring = b["ring_buf"]
  b["output"].open_perf_buffer(print_event, page_cnt=PAGECNT)

  #b.trace_print()

  print("Listening...")
  while True:
    try:
      b.kprobe_poll()
    except KeyboardInterrupt:
      dump_stats()
      sys.exit(0)

if __name__ == '__main__':
  main()

__all__ = ["parse_args", "main"]

