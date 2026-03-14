// SPDX-License-Identifier: GPL-3.0-only

#include <core/arch/idt.h>

void idt_install_handler(uint8_t vector, void* handler) {
    idtr_t idtr;
    __asm__ volatile("sidt %0" : "=m"(idtr));

    idt_entry_t* idt = (idt_entry_t*)idtr.base;
    uint64_t addr = (uint64_t)handler;

    idt[vector].offset_0_15  = (uint16_t)(addr & 0xFFFF);
    idt[vector].selector     = KERNEL_CS;
    idt[vector].ist          = 0;
    idt[vector].type_attr    = INTERRUPT_GATE;
    idt[vector].offset_16_31 = (uint16_t)((addr >> 16) & 0xFFFF);
    idt[vector].offset_32_63 = (uint32_t)(addr >> 32);
    idt[vector].zero         = 0;
}
