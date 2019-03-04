import os
import sys
from subprocess import check_output
def get_wayland_current_terminal_pid():

  term_pids = []
  # retrieve pids using /dev/ptmx i.e. terminal emulators
  with open(os.devnull, 'w') as DEVNULL:
    window_pids = check_output(['fuser','/dev/ptmx'], shell=False, stderr=DEVNULL).strip().split('  ')

  # begin going up procfs, getting ppid of our parent's parent process
  with open('/proc/self/status', 'r') as proc_stat:
    ppid = proc_stat.read().split('\n')[6].split('\t')[1]
  status_file = '/proc/{}/status'.format(ppid)
  with open(status_file, 'r') as proc_stat:
    ppid = proc_stat.read().split('\n')[6].split('\t')[1]

  # keep going up procfs, if pid is 1 we've hit the top
  while (ppid != '1'):
    for wp in window_pids:
      if (ppid == wp):
        term_pids.append(int(ppid))
        return term_pids

    status_file = '/proc/{}/status'.format(ppid)
    with open(status_file, 'r') as proc_stat:
      stat_data = proc_stat.read().split('\n')
    ppid = stat_data[6].split('\t')[1]


  sys.stderr.write('terminal not found\n')
  sys.exit(1)
