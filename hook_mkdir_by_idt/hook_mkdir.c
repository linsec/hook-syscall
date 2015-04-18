/*
* This kernel module locates the sys_call_table by scanning
* the system_call interrupt handler (int 0x80)
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>

/*
** module macros
*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("geeksword");
MODULE_DESCRIPTION("hook sys_mkdir");

/*
** module constructor/destructor
*/
typedef void (*sys_call_ptr_t)(void);
sys_call_ptr_t *_sys_call_table = NULL;

typedef asmlinkage long (*old_mkdir_t)(const char __user *pathname, umode_t mode);
old_mkdir_t old_mkdir = NULL;

// hooked mkdir function
asmlinkage long hooked_mkdir(const char __user *pathname, umode_t mode) {
	static char* msg = "hooked sys_mkdir(), mkdir name: ";
	printk("%s%s\n", msg, pathname);
	old_mkdir(pathname, mode);
}

// memory protection shinanigans
unsigned int level;
pte_t *pte;

// initialize the module
static int hooked_init(void) {
    printk("+ Loading hook_mkdir module\n");
    
    // struct for IDT register contents
    struct desc_ptr idtr;

    // pointer to IDT table of desc structs
    gate_desc *idt_table;

    // gate struct for int 0x80
    gate_desc *system_call_gate;

    // system_call (int 0x80) offset and pointer
    unsigned int _system_call_off;
    unsigned char *_system_call_ptr;

    // temp variables for scan
    unsigned int i;
    unsigned char *off;

    // store IDT register contents directly into memory
    asm ("sidt %0" : "=m" (idtr));

    // print out location
    printk("+ IDT is at %08x\n", idtr.address);

    // set table pointer
    idt_table = (gate_desc *) idtr.address;

    // set gate_desc for int 0x80
    system_call_gate = &idt_table[0x80];

    // get int 0x80 handler offset
    _system_call_off = (system_call_gate->a & 0xffff) | (system_call_gate->b & 0xffff0000);
    _system_call_ptr = (unsigned char *) _system_call_off;

    // print out int 0x80 handler
    printk("+ system_call is at %08x\n", _system_call_off);

    // scan for known pattern(0xff1485xx) in system_call (int 0x80) handler
    // pattern is just before sys_call_table address
    for(i = 0; i < 128; i++) {
        off = _system_call_ptr + i;
        if(*(off) == 0xff && *(off+1) == 0x14 && *(off+2) == 0x85) {
            _sys_call_table = *(sys_call_ptr_t **)(off+3);
            break;
        }
    }

    // bail out if the scan came up empty
    if(_sys_call_table == NULL) {
        printk("- unable to locate sys_call_table\n");
        return 0;
    }

    // print out sys_call_table address
    printk("+ found sys_call_table at %08x!\n", _sys_call_table);

    // now we can hook syscalls ...such as uname
    // first, save the old gate (fptr)
    old_mkdir = (old_mkdir_t) _sys_call_table[__NR_mkdir];

    // unprotect sys_call_table memory page
    pte = lookup_address((unsigned long) _sys_call_table, &level);

    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));

    printk("+ unprotected kernel memory page containing sys_call_table\n");

    // now overwrite the __NR_uname entry with address to our uname
    _sys_call_table[__NR_mkdir] = (sys_call_ptr_t) hooked_mkdir;

    printk("+ sys_mkdir hooked!\n");

    return 0;
}

static void hooked_exit(void) {
    if(old_mkdir != NULL) {
        // restore sys_call_table to original state
        _sys_call_table[__NR_mkdir] = (sys_call_ptr_t) old_mkdir;

        // reprotect page
        set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    }
    
    printk("+ Unloading hook_mkdir module\n");
}

/*
** entry/exit macros
*/
module_init(hooked_init);
module_exit(hooked_exit);
