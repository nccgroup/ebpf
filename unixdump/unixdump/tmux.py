import sys
def is_in_tmux():
  with open('/proc/self/status', 'r') as proc_stat:
    ppid = proc_stat.read().split('\n')[6].split('\t')[1]

  while (ppid != '1'):
    status_file = '/proc/{}/status'.format(ppid)
    with open(status_file, 'r') as proc_stat:
      stat_data = proc_stat.read().split('\n')
    comm = stat_data[0].split('\t')[1]
    ppid = stat_data[6].split('\t')[1]
    if comm.strip()[:4].lower() == 'tmux':
      return True
  return False
