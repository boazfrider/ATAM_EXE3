
ENTRY(_hw3_dance)

/* MEMORY
{
  data (rx) : ORIGIN = 0x20000, LENGTH = 0x3E0000
  text (!rx) : ORIGIN = 0x400000, LENGTH = 0x8FC00000
  rodata (rx) : ORIGIN = 0x90000000, LENGTH = 0x8FC00000
} */

PHDRS
{
   /* 0b000 = 0brwx */
    text   PT_LOAD FLAGS(3);    /* 0b011 = 0brwx */
    rodata PT_LOAD FLAGS(5);    /* 0b101 = 0brwx */
    data   PT_LOAD FLAGS(2);    /* 0b010 = 0brwx */
}

SECTIONS
{
  . = 0x20000;
  .data : 
  {
    *(.data)
    *(.bss)
  } :data

  . = 0x400000;
  .text : 
  {
    *(.text)
  } :text

  . = 0x90000000;
  .rodata : 
  {
    *(.rodata)
  } :rodata
}

EXTERN ( greens blacks )
