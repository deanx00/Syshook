
//  syshooks.h
//  October 1, 2025 | copyright 2026 DeanX | GPL license

#ifndef SYSHOOK_H
#define SYSHOOK_H

#include <asm/unistd.h>
#include <linux/ptrace.h>
#include <linux/stdarg.h>
#include <linux/types.h>

// hook execution
void write_hook(void *syscall_offset_addr, int32_t syscall_offset);
long original_syscall(int NR_code, const struct pt_regs *regs);

// hook setup
unsigned long get_kallsyms_lookup_name(void);
void *get_hooked_syscall(int NR_code);

// debug
void debug_printk(const char *fmt, ...); 


// data table defines
#define ORIGINAL_SYSCALL_ADDR 0
#define SYSCALL_OFFSET       1
#define SYSCALL_OFFSET_ADDR  2

// general defines
#define DEBUG_MODE       0x01
#define SCAN_SIZE        0x5000
#define SYSHOOK_VERSION  "0.3"

#endif


