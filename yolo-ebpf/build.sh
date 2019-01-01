#!/bin/sh

HOOK1_HEX=$(sudo cat /proc/kallsyms | grep -e 't check_reg_arg$' | awk '{print $1}') \
HOOK2_HEX=$(sudo cat /proc/kallsyms | grep -e 't __check_map_access$' | awk '{print $1}') \
make
