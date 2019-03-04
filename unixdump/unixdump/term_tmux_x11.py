import os
import sys
from subprocess import check_output
def get_tmux_x11_current_terminal_pid():

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

  # begin going up procfs, getting ppid and comm of our parent's parent process
  with open('/proc/self/status', 'r') as proc_stat:
    ppid = proc_stat.read().split('\n')[6].split('\t')[1]
  
  # keep going up procfs, if pid is 1 we've hit the top
  while (ppid != '1'):
    status_file = '/proc/{}/status'.format(ppid)
    with open(status_file, 'r') as proc_stat:
      stat_data = proc_stat.read().split('\n')
    comm = stat_data[0].split('\t')[1]
    ppid = stat_data[6].split('\t')[1]

    # we've reached tmux pid
    if comm[:4] == 'tmux':
      uid = stat_data[8].split('\t')[1]
      tmux_user_socket = '/tmp/tmux-{}/default'.format(uid)
      try:
        # assuming default tmux socket location and default name,
        # get list of client pids
        tmux_client_pids = check_output(['tmux', '-S', tmux_user_socket,
            'lsc', '-F', '#{client_pid}'],shell=False).strip().split('\n')
        # go up each tmux client procfs
        # compare against window_pids
        for client_pid in tmux_client_pids:
          client_proc = '/proc/{}/status'.format(client_pid)
          with open(client_proc, 'r') as c_proc_file:
            c_ppid = c_proc_file.read().split('\n')[6].split('\t')[1]

          while(c_ppid != '1'):
            if c_ppid not in term_pids:
              for wp in window_pids:
                if (c_ppid == wp):
                  term_pids.append(c_ppid)
                  break

            client_proc = '/proc/{}/status'.format(c_ppid)
            with open(client_proc, 'r') as c_proc_file:
              c_ppid = c_proc_file.read().split('\n')[6].split('\t')[1]

        return term_pids

      except CalledProcessError as ex:
        sys.stderr.write('tmux lsc: non 0 exit')

  sys.stderr.write('not all terminals found\n')
  sys.exit(1)
