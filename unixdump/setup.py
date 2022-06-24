import sys

from setuptools import setup

setup(
  name='unixdump',
  version='1.2.0',
  description='eBPF-based namespace-agnostic tcpdump-alike for Unix domain sockets',
  long_description=open('README.md').read(),
  long_description_content_type='text/markdown',
  author='Andy Olsen, Jeff Dileo',
  author_email='andy.olsen@nccgroup.com, jeff.dileo@nccgroup.com',
  url='https://github.com/nccgroup/ebpf',
  license='GPLv2 (Only)/BSD (2 Clause)',

  python_requires='>=3.5.0',
  #platforms=['linux'], #ignored by setuptools/distutils
  install_requires=[
    'pybst >=1.0, <2',
    'hexdump >=3.3, <4',
    'uninstallable > 0;platform_system!="Linux"',
  ],
  include_package_data=True,
  packages=['unixdump'],

  entry_points={
    'console_scripts': [
      'unixdump=unixdump:main',
    ],
  },
  classifiers=[
    'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    'License :: OSI Approved :: BSD License',
    'Programming Language :: Python :: 3.5',
    'Operating System :: POSIX :: Linux',
    'Topic :: System :: Networking :: Monitoring',
    'Topic :: System :: Operating System Kernels :: Linux',
    'Topic :: Security'
  ],
  keywords='unixdump packet capture pcap unix domain sockets tcpdump ebpf'
)
