# yolo-ebpf

Redirects a few internal eBPF functions to hook impls that disable/bypass a
couple of the poorly thought out validation checks that get in the way of
writing eBPF-based tracers.

***NOTE:*** This enables running unsafe eBPF code, but that's the eBPF's
validator's fault for randomly flipping between allowing and rejecting
perfectly fine code across minor kernel and compiler toolchain updates.
Please don't use this in productioon.

# Setup

(Install your kernel headers first.)

```
./build.sh && sudo rmmod yolo_ebpf; sudo insmod yolo_ebpf.ko
```

***Note:*** Not tested against current kernel versions...
