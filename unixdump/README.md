# unixdump
_"tcpdump for unix domain sockets"_

`unixdump` is a powerful command-line Unix domain socket "packet" capturer. It
is an eBPF-based kernel tracing tool that extracts, processes, and dumps all
data sent over unix domain sockets across an entire Linux host with support
for performant in-kernel filters for a wide range of filtering granularity. It
enables manual traffic inspection of Unix socket traffic between processes,
including ancillary data, such as file descriptors and Unix credentials.

# Installation

## BCC

`unixdump` depends on the BCC eBPF tracing tool framework. See the
[BCC install instructions](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
for your distribution. We recommend building and installing BCC from
[source](https://github.com/iovisor/bcc/blob/master/INSTALL.md#source).

***Note:*** While BCC updates may result in breakages, the current version of
`unixdump` is known to work with version [0.24.0](https://github.com/iovisor/bcc/releases/tag/v0.24.0)
on Ubuntu 20.04 when using clang/llvm 10 from <https://apt.llvm.org/> (bcc's
build hardcodes llvm 10 paths). If you are having issues with `unixdump`,
please make sure you are not running an out-of-date version of BCC (such as if
you installed the [Ubuntu packages](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---binary)).

## unixdump

### Quickstart

```
$ docker run --rm -it --privileged -v /lib/modules:/lib/modules:ro -v /sys:/sys -v /usr/src:/usr/src:ro alpine:edge
/ # apk add bcc-tools bcc-doc py3-pip procps
...
/ # pip install unixdump
...
/ # # [leave shell open]
```

```
$ sudo nsenter -a -t <container pid> /bin/sh
/ # unixdump -s /run/docker.sock
```

```
$ docker ps
```

### Via pip

```
sudo -H pip3 install unixdump
```

### From source

```
sudo python3 setup.py install
```

or

```
python3 setup.py bdist_wheel
sudo -H pip3 install ./dist/unixdump-*.whl
```

# Usage

`unixdump` is best used with filters. Several of the important ones are defined
[below](#Options), and the rest can be listed with `--help`. To dump all Unix
domain socket traffic of a system (sans the terminal process rendering the
output), run `unixdump` without any arguments:

***Note:*** `unixdump` requires `CAP_SYS_ADMIN` privileges and full access to
`sysfs`/`debugfs`.

```
sudo unixdump
```

For an example use case, let's say we know the program creates a Unix domain
socket with random characters that begins with `/tmp/domain-socket-`. We can
limit our output to only sockets beginning with that string:

```
sudo unixdump -b -s '/tmp/domain-socket'
```

The output can be further restricted using combinations of `unixdump` filter
options.

# Options

`unixdump` provides many different arguments to filter output and fine tune
performance. Below are some of the more notable options:

- `-s, --socket`: When the user knows the exact name of the socket path, this is 
the option to use. By specifying an empty string like so `-s ''`, `unixdump`
will filter on unnamed sockets.

- `-@, --base64`: To filter on binary abstract namespace keys, this option
instructs `unixdump` to parse the `-b`/`-s` options as base64.

- `-b, --beginswith`: One of `unixdump`'s most useful filters is to match starting
sequences of socket paths. This proves extremely helpful when the program creates 
socket paths ending with random characters yet the beginning is unique and constant.
This makes filtering possible without knowing the entire socket name ahead of time.

- `-p, --pid`: To home in on a specific process (and anything communicating
with it), use this option.

- `-x, --exclude`: For when the user is listening for general traffic and wants to 
hide noisy processes such as `Xorg`. This argument takes a space separated list 
of `pids` to exclude.

- `-t, --excludeownterminal`: (requires `wmctrl`) Attempts to exclude the current terminal process
from capture. Currently supports Wayland and X11, and the `tmux` and `screen`
terminal multiplexers.  
***Note:*** screen is not currently supported on Wayland

- `-l, --ancillarydata`: For those who want to only watch for traffic containing 
ancillary data. This will provide the file descriptors or Unix credentials that
were sent.

- `-o, --dir`: To save output into separate files based on `pid` pairs. The
option `-c, --color` can also be set to add color like in wireshark.

- `-B, --extract`: Extract the buffer contents from a file saved by `--dir`
and output it to binary in separate client and server files.
