# glibcpwn

Injects shared libraries into systemd using BCC-based eBPF kprobes.

***Note:*** The offsets in the ROP payload used are specific to Ubuntu 18.04
and may change over time. Use with caution, and, when in doubt, consult the
SHA256 hashes in `pwnlibc.py`. Also, `pwnlibc.py` does not terminate after
performing the injection, so make sure to `^C` it after it is done or it will
perform the injection about once a minute.
