import hexdump
import sys
import os

def extract_buffer(filename):
  if not os.path.isfile(filename):
    sys.stderr.write('{} is not a file\n'.format(filename))
    sys.exit(1)
  
  with open(filename, 'r') as infile:
    content = infile.readlines()
  
  hex_data_server = ''
  hex_data_client = ''
  
  for l in content:
    if '>' is l[:1]:
      if l != '> \n':
        hex_data_client = hex_data_client + l[2:]
    if '<' is l[:1]:
      if l != '< \n':
        hex_data_server = hex_data_server + l[2:]
  
  if hex_data_client is '' and hex_data_server is '':
    print("no unixdump data found")
    sys.exit(1)
  
  if hex_data_client is not '':
    client_filename = "{}.client".format(filename)
    print('Client file created: {}'.format(client_filename))
    with open(client_filename, 'wb') as coutfile:
      coutfile.write(hexdump.restore(hex_data_client))
  
  if hex_data_server is not '':
    server_filename = "{}.server".format(filename)
    print('Server file created: {}'.format(server_filename))
    with open(server_filename, 'wb') as soutfile:
      soutfile.write(hexdump.restore(hex_data_server))
