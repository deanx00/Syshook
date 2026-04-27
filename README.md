# Syshook 

A modern syscall hooking framework for Linux x86_64

## About Syshook

Syshook framework is a Linux Kernel Module (LKM) that allows you to create syscall hooks for the newest kernel.  Written entirely in C, Syshook works by locating the syscall's call offset in the new `x64_sys_call` switch and replacing it with an offset to call your hooked function.

Syshook can hook multiple syscalls at once by accepting an array of NR codes at the command line.  To add your own hooked syscall simply add a hook function in hooks.c and recompile the kernal module.  See hooks.c and the [example code](#example-code) section for details. 

Syshook employees a few techniques to execute a hook; it uses `kallsyms_lookup_name` to find `x64_sys_call` and `sys_call_table` (to pull the syscall function addresses from the old `sys_call_table`, which still exists and contains valid syscall addresses), and it temporarily turns off write protection to read-only pages so it can overwrite the call offsets in the kernal code itself (by disabling the CPU's CR0:WP and CR4:CET if required).

Syshook was written for educational purposes to learn about the new kernal and hooking syscalls, like intercepting `sys_recvfrom` to listen for magic packets or hooking `sys_kill` to make a process immortal.


## Requirements
| Requirement | Version/Environments |
| --- | --- |
| Kernel | 6.7+ |
| Architecture | x86_64 |

## Installation
```bash
git clone https://github.com/deanx00/syshook.git
```

## Compile
```bash
# run from the syshook directory
make
```
## Load 
```bash
sudo insmod syshook.ko NR_codes=<NR_CODE>,<NR_CODE>,...

# for example, to hook sys_kill: 
sudo insmod syshook.ko NR_codes=62
```
## Unload 
```bash
sudo rmmod syshook.ko
```

## Example code

The following code hooks sys_kill and sys_reboot.

To add your own syscall hooks, modify hooks.c to add your hooked function, then add a case with the NR_code to `get_hooked_syscall()`.


```C

// hooks.c

void *get_hooked_syscall(int NR_code) {

    switch (NR_code) {

        case __NR_kill:  // 62
            return &hooked_kill;

        case __NR_reboot:  // 169
            return &hooked_reboot;
    }
    return NULL;
}
```


```c
// hooked sys_kill

asmlinkage long hooked_kill(const struct pt_regs *regs) {  
    
    pid_t killed_process = regs->di;
    int signal = regs->si;
    
    if (signal != 0) 
        debug_printk("Process %i killed with signal %i\n", killed_process, signal);
    
    return orignal_syscall(__NR_kill, regs);
}


// hooked sys_reboot

asmlinkage long hooked_reboot(const struct pt_regs *regs) {  

    debug_printk("Dean hooked your reboot syscall... put your own hooking code here...\n");
    return orignal_syscall(__NR_reboot, regs);
}

```
