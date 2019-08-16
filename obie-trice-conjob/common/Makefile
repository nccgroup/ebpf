# SPDX-License-Identifier: (GPL-2.0)
CC := gcc

all: common_user_bpf.o bpf_load.o

CFLAGS := -Wall

LIBBPF_DIR = ../libbpf/src/
CFLAGS += -I$(LIBBPF_DIR)/root/usr/include/  -I../headers

common_user_bpf.o: common_user_bpf.c common_user_bpf.h
	$(CC) $(CFLAGS) -c -o $@ $<

bpf_load.o: bpf_load.c bpf_load.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean

clean:
	rm -f *.o
