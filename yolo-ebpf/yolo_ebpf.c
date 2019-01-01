// Copyright (c) 2018 NCC Group Security Services, Inc. All rights reserved.
// Licensed under Dual BSD/GPLv2 per the repo LICENSE file.

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

MODULE_LICENSE("Dual BSD/GPL");

#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

static uint8_t hook_func[] = {
  0xeb, 0x08, // jmp a <pusher>
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // NOPs to be filled in
  0x4c, 0x8b, 0x1d, 0xf1, 0xff, 0xff, 0xff,  // mov r11,QWORD PTR [rip+0xfffffffffffffff1] # 2 <hookfunc>
  0x41, 0xff, 0xe3 // jmp r11
};

#define PAYLOAD hook_func

#define DO_EXPAND(VAL) 0x0 ## VAL
#define EXPAND(VAL) DO_EXPAND(VAL)

#ifndef HOOK1_HEX
  #error HOOK1_HEX not defined
#elif (EXPAND(HOOK1_HEX) == 0x0)
  #error HOOK1_HEX is empty (maybe wrong symbol name?)
#endif

#ifndef HOOK2_HEX
  #error HOOK2_HEX not defined
#elif (EXPAND(HOOK2_HEX) == 0x0)
  #error HOOK2_HEX is empty (maybe wrong symbol name?)
#endif

#define RAW_CONCAT(a, b) a ## b
#define CONCAT(a, b) RAW_CONCAT(a, b)

static uint8_t* check_reg_arg_addr = (void*)(CONCAT(0x0, HOOK1_HEX) + 0x5);
static uint8_t* check_reg_arg_end = NULL;
static uint8_t  check_reg_arg_orig[sizeof(PAYLOAD)] = { 0 };

static uint8_t* __check_map_access_addr = (void*)(CONCAT(0x0, HOOK2_HEX) + 0x5);
static uint8_t* __check_map_access_end = NULL;
static uint8_t  __check_map_access_orig[sizeof(PAYLOAD)] = { 0 };

static int __check_map_access_hook(struct bpf_verifier_env *env, u32 regno, int off,
			      int size, bool zero_size_allowed) {
  //printk("__check_map_access_hook\n");
  return 0;
}

static int check_reg_arg_hook(struct bpf_verifier_env *env, u32 regno,
			      /*enum reg_arg_type*/ int t) {
  //printk("check_reg_arg_hook\n");
  //printk("env: %p\n", env);
  //printk("regno: %u\n", regno);

  struct bpf_reg_state *regs = env->cur_state->regs;
  for (size_t i=0; i < MAX_BPF_REG; i++) {
    //regs[i].type = PTR_TO_STACK;
    regs[i].smin_value = 1;
    regs[i].smax_value = 1;
    regs[i].umin_value = 0;
    regs[i].umax_value = 0;
  }

  return 0;
}

static inline void hook_function(void* hook, uint8_t* orig, uint8_t* func_addr, uint8_t** func_end) {
  size_t hook_val = (uintptr_t)hook;
  uint8_t mod_payload[sizeof(PAYLOAD)];

  *func_end = &func_addr[sizeof(PAYLOAD)-1];
  for (size_t i=0; i < sizeof(PAYLOAD); i++) {
    orig[i] = func_addr[i];
  }

  unsigned int level1 = 0;
  unsigned int level2 = 0;
  pte_t *pte1 = lookup_address((unsigned long)func_addr, &level1);
  pte_t *pte2 = lookup_address((unsigned long)*func_end, &level2);
  set_pte_atomic(pte1, pte_mkwrite(*pte1));
  set_pte_atomic(pte2, pte_mkwrite(*pte2));

  memcpy(mod_payload, &PAYLOAD, sizeof(PAYLOAD));
  memcpy(&mod_payload[2], &hook_val, sizeof(hook_val));

  for (size_t i=0; i < sizeof(PAYLOAD); i++) {
    //printk("func_addr[%lu] = 0x%02hhx\n", i, mod_payload[i]);
    func_addr[i] = mod_payload[i];
  }

  set_pte_atomic(pte1, pte_wrprotect(*pte1));
  set_pte_atomic(pte2, pte_wrprotect(*pte2));
}

static inline void unhook_function(uint8_t* orig, uint8_t* func_addr, uint8_t* func_end) {
  unsigned int level1 = 0;
  unsigned int level2 = 0;
  pte_t *pte1 = lookup_address((unsigned long)func_addr, &level1);
  pte_t *pte2 = lookup_address((unsigned long)func_end, &level2);
  set_pte_atomic(pte1, pte_mkwrite(*pte1));
  set_pte_atomic(pte2, pte_mkwrite(*pte2));

  for (size_t i=0; i < sizeof(PAYLOAD); i++) {
    func_addr[i] = orig[i];
  }

  set_pte_atomic(pte1, pte_wrprotect(*pte1));
  set_pte_atomic(pte2, pte_wrprotect(*pte2));
}

static int __init mod_entry_func(void) {
  printk("init yolo-ebpf\n");

  hook_function(&check_reg_arg_hook, check_reg_arg_orig, check_reg_arg_addr, &check_reg_arg_end);
  hook_function(&__check_map_access_hook, __check_map_access_orig, __check_map_access_addr, &__check_map_access_end);

  return 0;
}

static void __exit mod_exit_func(void) {
  printk("exiting yolo-ebpf\n");

  unhook_function(check_reg_arg_orig, check_reg_arg_addr, check_reg_arg_end);
  unhook_function(__check_map_access_orig, __check_map_access_addr, __check_map_access_end);
}

module_init(mod_entry_func);
module_exit(mod_exit_func);
