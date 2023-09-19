# _entry should be the first function invoked when
# the QEMU CPU starts executing. It's location should
# according to the memory layout provided in param.h

.section .text
.global _entry
_entry:
        # task: setup a per-CPU stack for C and jump to start() function
	# sp = l_stack + 4096
	la sp, bl_stack
	li a0, 4096
	add sp, sp, a0
	call start
	
spin:
        j spin
