import os
import sys
from subprocess import check_output
def get_screen_x11_current_terminal_pid():
  term_pids = []
  if (not os.path.exists('/usr/bin/wmctrl')):
    sys.stderr.write('command not found: wmctrl\n')
    sys.stderr.write('\texcludeownterminal requires wmctrl\n')
    sys.exit(1)
  # get pids of all windows
  window_pids = [pid.split(' ')[3] for pid in check_output(['wmctrl','-lp'], 
      shell=False).strip().split('\n')]
  # remove duplicates
  window_pids = list(set(window_pids))

  with open('/proc/self/status', 'r') as proc_stat:
    ppid = proc_stat.read().split('\n')[6].split('\t')[1]
  status_file = '/proc/{}/status'.format(ppid)
  with open(status_file, 'r') as proc_stat:
    ppid = proc_stat.read().split('\n')[6].split('\t')[1]

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
