import os
import sys

def get_session_type():
  # attempt to get xdg_session_type from env
  try:
    session = os.environ['XDG_SESSION_TYPE']
    return session
  except KeyError as ex:
    # get xdg_session_type from a parent process
    with open('/proc/self/environ', 'r') as proc_env:
      environment = proc_env.read()
    with open('/proc/self/status', 'r') as proc_stat:
      ppid = proc_stat.read().split('\n')[6].split('\t')[1]

    while (ppid != '1'):
      for e in environment.split('\x00'):
        if e != '':
          if e.split('=')[0] == 'XDG_SESSION_TYPE':
            session = e.split('=')[1]
            return session

      with open('/proc/{}/status'.format(ppid), 'r') as proc_stat:
        ppid = proc_stat.read().split('\n')[6].split('\t')[1]
      with open('/proc/{}/environ'.format(ppid), 'r') as proc_env:
        environment = proc_env.read()

  sys.stderr.write('XDG_SESSION_TYPE not found\n')
  sys.exit(1)
