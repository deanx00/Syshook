
//  syshooks.c
//
//  October 1, 2025 | copyright 2026 DeanX | GPL license
//
//  Syshook framework to create syscall hooks
//  Requires Linux kernal 6.7 or higher
//


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include "syshooks.h"


static int __init syshook_init(void);
static void __exit syshook_exit(void);
static inline void change_write_protection(int wp);

typedef asmlinkage long (*t_syscall)(const struct pt_regs *regs); // universal syscall prototype for __x64_sys_ syscalls
unsigned long data_table[__NR_syscalls][3];  // holds addresses and offsets
static int NR_codes[__NR_syscalls];  // input arguments, syscalls to hook
static int args_size = 0;

MODULE_AUTHOR("DeanX");
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(NR_codes, "syscall NR codes to hook");


// code below executes at startup

module_param_array(NR_codes, int, &args_size, 0000);  // command line params, for example: sudo insmod syshook.ko NR_code=62,92

module_init(syshook_init);
module_exit(syshook_exit);

//
//  called when the kernel module is loaded to execute the hook
//
static int __init syshook_init(void) {

    debug_printk("Loaded Syshook v%s", SYSHOOK_VERSION);
    memset(data_table, 0, sizeof(data_table));

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    kallsyms_lookup_name = (kallsyms_lookup_name_t)get_kallsyms_lookup_name();

    void *syscall_table = (void *) kallsyms_lookup_name("sys_call_table");
    void *syscall_switch = (void *) kallsyms_lookup_name("x64_sys_call");

    debug_printk("Syscall_table address: 0x%lx\n", syscall_table);
    debug_printk("Syscall_switch address: 0x%lx\n", syscall_switch);
    debug_printk("Setup complete... hooking...\n");

    for (int arg = 0; arg < args_size; arg++)  {  // loop all NR_codes to hook

        int NR_code = NR_codes[arg];
        if (NR_code < 0 || NR_code > __NR_syscalls) {
            debug_printk("Invalid NR code: %i\n", NR_code);
            continue;
        }

        void *syscall_table_addr = ((void **)syscall_table)[NR_code];

        unsigned char *switch_ptr = (unsigned char *)syscall_switch;
        for (size_t i = 0; i < SCAN_SIZE - 4; ++i) {  // scan memory of syscalls switch 
            if (switch_ptr[i] == 0xe8) { // check for call instruction (0xe8)

                void *syscall_offset_addr = switch_ptr + i + 1;
                void *IP_addr = switch_ptr + i + 5; // instruction pointer
                int32_t syscall_offset = *(int32_t *)(syscall_offset_addr);
                void *syscall_addr = (void *)IP_addr + syscall_offset;

                if (syscall_addr == syscall_table_addr) {  // found our syscall?

                    void *hooked_syscall_addr = get_hooked_syscall(NR_code); 
                    if (hooked_syscall_addr == NULL) {
                        debug_printk("Cannot find hooked syscall address for NR code: %i\n", NR_code);
                        break;
                    }

                    int32_t hooked_syscall_offset = (unsigned long) hooked_syscall_addr - (unsigned long) IP_addr;

                    // update data table
                    data_table[NR_code][ORIGNAL_SYSCALL_ADDR] = (unsigned long) syscall_addr; 
                    data_table[NR_code][SYSCALL_OFFSET] = (unsigned long) syscall_offset;
                    data_table[NR_code][SYSCALL_OFFSET_ADDR] = (unsigned long) syscall_offset_addr;

                    // injects the hooked syscall
                    write_hook(syscall_offset_addr, hooked_syscall_offset);
                    debug_printk("Successfully hooked syscall %i at offset %i\n", NR_code, i + 1);

                    break;
                }
            }
        }
    }
    return 0;
}


//
//  called when the kernel module is unloaded
//  restore all the hooks to orignal syscalls


static void __exit syshook_exit(void) {

    for (int arg = 0; arg < args_size; arg++) {
        int NR_code = NR_codes[arg];

        if (NR_code < 0 || NR_code > __NR_syscalls)
            continue;

        void *orignal_syscall_offset_addr = (void *) data_table[NR_code][SYSCALL_OFFSET_ADDR];

        if (orignal_syscall_offset_addr == NULL)
            continue;

        int32_t orignal_syscall_offset = (int32_t) data_table[NR_code][SYSCALL_OFFSET];

        write_hook(orignal_syscall_offset_addr, orignal_syscall_offset);
        debug_printk("Successfully unhooked syscall: %i\n", NR_code);
    }
    debug_printk("Unloaded gracefully\n");
}


//
//  write hook in the syscall switch
//

void write_hook(void *syscall_offset_addr, int32_t syscall_offset) {

    change_write_protection(0);
    memcpy(syscall_offset_addr, &syscall_offset, sizeof(syscall_offset));
    change_write_protection(1);
}


//
//  turn on/off write protection via CR0:WP 
//  also turn on/off control flow enforcement via CR4:CET when its enabled (like Raptor Lake CPUs)

static inline void change_write_protection(int wp) {

    unsigned long __force_order; // prevent compiler from reordering asm instructions
    static unsigned long cr4_orig = 0;

    unsigned long cr0_val;
    unsigned long cr4_val;

    asm volatile("mov %%cr0, %0" : "=r"(cr0_val));
    asm volatile("mov %%cr4, %0" : "=r"(cr4_val));

    if (wp == 0) { // off - dissable write protect

        cr4_orig = cr4_val;

        cr0_val &= ~(1UL << 16);
        cr4_val &= ~(1UL << 23);

        asm volatile("mov %0,%%cr4" : "+r"(cr4_val),"+m"(__force_order));
        asm volatile("mov %0,%%cr0" : "+r"(cr0_val),"+m"(__force_order));

    } else { // on

        if (cr4_orig == 0)
            return;

        cr0_val |= (1UL << 16);

        asm volatile("mov %0,%%cr0" : "+r"(cr0_val), "+m"(__force_order));
        asm volatile("mov %0,%%cr4" : "+r"(cr4_orig), "+m"(__force_order));
    }
}


//
// call the orignal syscall
//

long orignal_syscall(int NR_code, const struct pt_regs *regs) {

    t_syscall orig_syscall;
    orig_syscall = (t_syscall) data_table[NR_code][ORIGNAL_SYSCALL_ADDR];

    if (orig_syscall) {
        return orig_syscall(regs);
    }
    return -1;
}


//
//  find kallsyms_lookup_name address via kprobe
//

unsigned long get_kallsyms_lookup_name(void) {

    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    register_kprobe(&kp);
    unsigned long lookup_name_addr = (unsigned long) kp.addr;
    unregister_kprobe(&kp);
    return lookup_name_addr;
}


//
// debug print to the kernel buffer (to view: sudo dmesg)
//

void debug_printk(const char *fmt, ...) {

#ifdef DEBUG_MODE
    va_list args;
    va_start(args, fmt);

    char new_fmt[512];
    snprintf(new_fmt, sizeof(new_fmt), "[Syshook] %s", fmt);

    vprintk(new_fmt, args);

    va_end(args);
#endif
}

