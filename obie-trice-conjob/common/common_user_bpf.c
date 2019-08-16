#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <asm-generic/unistd.h>
#include <linux/limits.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <linux/memfd.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../common/bpf_load.h"

int load_bpf_object_from_buffer(unsigned char const* buf, size_t bufsz, size_t type, struct bpf_object** obj) {
  errno = 0;
  int fd = memfd_create("bpf", MFD_CLOEXEC);
  if (fd == -1) {
    perror("memfd_create");
    return -1;
  }

  ftruncate(fd, bufsz);
  char* mem = mmap(NULL, bufsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  memcpy(mem, buf, bufsz);

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

  int first_prog_fd = -1;
  int err = bpf_prog_load(path, type, obj, &first_prog_fd);
  if (err) {
    fprintf(stderr, "ERR: loading BPF-OBJ file (%d): %s\n", err, strerror(-err));
    first_prog_fd = -1;
  }

  munmap(mem, bufsz);
  close(fd);

  return first_prog_fd;
}

int load_bpf_file_from_buffer(unsigned char const* buf, size_t bufsz) {
  errno = 0;
  int fd = memfd_create("bpf", MFD_CLOEXEC);
  if (fd == -1) {
    perror("memfd_create");
    return 0;
  }

  ftruncate(fd, bufsz);
  char* mem = mmap(NULL, bufsz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  memcpy(mem, buf, bufsz);

  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

  if (load_bpf_file(path)) {
    //fprintf(stderr, "Error loading BPF file:\n%s\n", bpf_log_buf);
    return 0;
  }

  munmap(mem, bufsz);
  close(fd);

  return 1;
}
