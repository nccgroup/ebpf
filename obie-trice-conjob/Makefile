# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS := kern
USER_TARGETS := conjob

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ./libbpf/src/
COMMON_DIR = ./common/
HEADERS_DIR = ./headers/

#COMMON_OBJS := $(COMMON_DIR)/common_libbpf.o
COMMON_OBJS := $(COMMON_DIR)/bpf_load.o
COMMON_OBJS += $(COMMON_DIR)/common_user_bpf.o

include $(COMMON_DIR)/common.mk

CFLAGS += -I $(COMMON_DIR)

kern.o: regs.h
conjob.o: kern.o.h
