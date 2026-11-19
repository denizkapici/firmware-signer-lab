.syntax unified
.cpu cortex-m4
.thumb

/*
 * STM32F407 vector table: 16 core exceptions + 82 device interrupts.
 * Every entry is populated, so enabling an interrupt can never jump to an
 * address taken from unrelated flash contents. Unused interrupts go to
 * Default_Handler; all fault exceptions go to the fault reporter.
 */
.section .isr_vector, "a", %progbits
.global vector_table
vector_table:
    .word _estack
    .word Reset_Handler
    .word NMI_Handler
    .word HardFault_Handler
    .word MemManage_Handler
    .word BusFault_Handler
    .word UsageFault_Handler
    .rept 4
    .word 0                     /* reserved */
    .endr
    .word SVC_Handler
    .word DebugMon_Handler
    .word 0                     /* reserved */
    .word PendSV_Handler
    .word SysTick_Handler

    /* IRQ 0..51 */
    .rept 52
    .word Default_Handler
    .endr
    /* IRQ 52 */
    .word UART4_IRQHandler
    /* IRQ 53..81 */
    .rept 29
    .word Default_Handler
    .endr

.section .text.Reset_Handler, "ax", %progbits
.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    ldr r0, =_sidata
    ldr r1, =_sdata
    ldr r2, =_edata

copy_data:
    cmp r1, r2
    bcs clear_bss_setup
    ldr r3, [r0], #4
    str r3, [r1], #4
    b copy_data

clear_bss_setup:
    ldr r1, =_sbss
    ldr r2, =_ebss
    movs r3, #0

clear_bss:
    cmp r1, r2
    bcs call_main
    str r3, [r1], #4
    b clear_bss

call_main:
    bl main
    b Default_Handler

.size Reset_Handler, .-Reset_Handler

/*
 * Fault entry: pass the stacked exception frame to C. Bit 2 of LR
 * (EXC_RETURN) tells whether the frame is on MSP or PSP.
 */
.section .text.Fault_Entry, "ax", %progbits
.global Fault_Entry
.type Fault_Entry, %function
.thumb_func
Fault_Entry:
    tst lr, #4
    ite eq
    mrseq r0, msp
    mrsne r0, psp
    b fault_report

.size Fault_Entry, .-Fault_Entry

.section .text.Default_Handler, "ax", %progbits
.global Default_Handler
.type Default_Handler, %function
.thumb_func
Default_Handler:
    b Default_Handler

.size Default_Handler, .-Default_Handler

/* Weak aliases: a C definition with the same name replaces them. */
.macro weak_alias name, target
    .weak \name
    .thumb_set \name, \target
.endm

weak_alias NMI_Handler, Default_Handler
weak_alias HardFault_Handler, Fault_Entry
weak_alias MemManage_Handler, Fault_Entry
weak_alias BusFault_Handler, Fault_Entry
weak_alias UsageFault_Handler, Fault_Entry
weak_alias SVC_Handler, Default_Handler
weak_alias DebugMon_Handler, Default_Handler
weak_alias PendSV_Handler, Default_Handler
weak_alias SysTick_Handler, Default_Handler
weak_alias UART4_IRQHandler, Default_Handler
/* Images without fault.c (the crypto test) still link. */
weak_alias fault_report, Default_Handler
