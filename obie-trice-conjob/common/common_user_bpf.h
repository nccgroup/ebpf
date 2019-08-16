/* Common BPF functions used by userspace side programs */
#ifndef __COMMON_USER_BPF_H
#define __COMMON_USER_BPF_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int load_bpf_object_from_buffer(unsigned char const* buf, size_t bufsz, size_t type, struct bpf_object** obj);
int load_bpf_file_from_buffer(unsigned char const* buf, size_t bufsz);

#endif /* __COMMON_USER_BPF_H */

