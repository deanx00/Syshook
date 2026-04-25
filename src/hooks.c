
//  hooks.c
//
//  October 1, 2025 | copyright 2026 DeanX | GPL license
//
//  READ THE FOLLWING BEFORE USE!!!
//
//  To add your own syscall hooks, you only need to modify this file, as follows:
//
//  1. Add your new syscall function, use as a template one of the hooked_<syscall_name> functions below.
//     If calling orignal_syscall() be sure to change the __NR__<syscall_name> to the syscall you're hooking.
//     (__NR_<syscall_name> code constants are defined in <asm/unistd.h>)
//     Make sure to add the function's prototype to the prototypes section
//
//  2. Add a case for your hook to get_hooked_syscall() function and return the address of your hooked function


#include "syshooks.h"

// prototypes for hooked syscall functions
asmlinkage long hooked_kill(const struct pt_regs *regs);
asmlinkage long hooked_reboot(const struct pt_regs *regs);


void *get_hooked_syscall(int NR_code) {

    switch (NR_code) {

        case __NR_kill:  // 62
            return &hooked_kill;

        case __NR_reboot:  // 169
            return &hooked_reboot;
    }
    return NULL;
}


asmlinkage long hooked_kill(const struct pt_regs *regs) {

    pid_t killed_process = regs->di;
    int signal = regs->si;

    if (signal != 0)
    	debug_printk("Process %i killed with signal %i\n", killed_process, signal);

    return orignal_syscall(__NR_kill, regs);
}


asmlinkage long hooked_reboot(const struct pt_regs *regs) {

    debug_printk("Dean hooked your reboot syscall... put your own hooking code here...\n"); 
    return orignal_syscall(__NR_reboot, regs);
}

