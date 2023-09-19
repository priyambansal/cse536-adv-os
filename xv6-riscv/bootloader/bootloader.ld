OUTPUT_ARCH( "riscv" )

/* Task: ensure the correct starting function. */
ENTRY( _entry )

SECTIONS
{
  /* Task: ensure the correct entry address based on where -kernel in QEMU jumps. */
  . = 0x0000000080000000;

  /* Task lay out the sections as mentioned in the handout */
  .text : {
  	*(.text)
  	ecode = .;
  }
  .data : {
  	*(.data)
  	edata = .;
  }
  .erodata : {
  	*(.erodata)
  	erodata = .;
  }
  .bss : {
  	*(.bss)
  	ebss = .;
  }
  end = .;  
}
