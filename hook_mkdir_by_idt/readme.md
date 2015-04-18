
hook sys_mkdir
====

1. Locates the Interrupt Descriptor Table using the sidt instruction.
2. Locates the syscall handler routine through the IDT.
3. Locates the system call table (sys_call_table) by scanning for a known code pattern in memory in the syscall handler.
4. Saves the state of the sys_call_table.
5. Disables memory protection on the sys_call_table.
6. Overwrites entries in the sys_call_table with pointers to the hooked functions.


reference
====
- [blog post with detailed comment](http://onestraw.net/linux/lkm-and-syscall-hook/)
- [hook uname](https://github.com/ebradbury/linux-syscall-hooker)
