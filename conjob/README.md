# conjob

Example BCC-based eBPF kprobe payload that intercepts reads for `/etc/crontab`
to inject arbitrary content.

## Usage

```bash
sudo python conjob.py '/usr/bin/id > /tmp/conjobid'
```
