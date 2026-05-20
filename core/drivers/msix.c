// SPDX-License-Identifier: GPL-3.0-only

#include <core/drivers/msix.h>
#include <core/drivers/pci.h>
#include <core/kernel/mem/allocator.h>
#include <log.h>
#include <stdint.h>
#include <stdbool.h>

// x86 LAPIC base for BSP (destination field left at 0 — BSP)
#define LAPIC_MSG_ADDR 0xFEE00000ULL

typedef struct __attribute__((packed)) {
    uint32_t msg_addr_lo;
    uint32_t msg_addr_hi;
    uint32_t msg_data;
    uint32_t vector_ctrl;
} msix_table_entry_t;

bool msix_find(uint8_t bus, uint8_t slot, uint8_t func, msix_info_t *out) {
    uint16_t status = (uint16_t)(pci_read(bus, slot, func, 0x04) >> 16);
    if (!(status & (1 << 4))) {
        LOG_DEBUG("MSI-X: no capability list on %02x:%02x.%x\n", bus, slot, func);
        return false;
    }

    uint8_t cap_ptr = (uint8_t)(pci_read(bus, slot, func, 0x34) & 0xFF);

    while (cap_ptr != 0) {
        uint32_t dword0  = pci_read(bus, slot, func, cap_ptr);
        uint8_t  cap_id  = (uint8_t)(dword0 & 0xFF);
        uint8_t  cap_nxt = (uint8_t)((dword0 >> 8) & 0xFF);

        if (cap_id == MSIX_CAP_ID) {
            uint16_t msg_ctrl   = (uint16_t)(dword0 >> 16);
            uint16_t num_vectors = (uint16_t)((msg_ctrl & 0x7FF) + 1);

            uint32_t table_reg    = pci_read(bus, slot, func, cap_ptr + 4);
            uint8_t  bir          = (uint8_t)(table_reg & 0x7);
            uint32_t table_offset = table_reg & ~0x7u;

            out->bus          = bus;
            out->slot         = slot;
            out->func         = func;
            out->table_bir    = bir;
            out->table_offset = table_offset;
            out->num_vectors  = num_vectors;

            LOG_DEBUG("MSI-X: cap at 0x%x, BIR=%u, offset=0x%x, vectors=%u\n",
                      cap_ptr, bir, table_offset, num_vectors);
            return true;
        }

        cap_ptr = cap_nxt;
    }

    LOG_DEBUG("MSI-X: capability not found on %02x:%02x.%x\n", bus, slot, func);
    return false;
}

bool msix_setup(const msix_info_t *info, uint8_t entry_index, uint8_t vector) {
    if (entry_index >= info->num_vectors) {
        LOG_ERROR("MSI-X: entry %u out of range (max %u)\n",
                  entry_index, info->num_vectors);
        return false;
    }

    uint64_t bar = pci_read_bar(info->bus, info->slot, info->func, info->table_bir);
    if (bar == 0) {
        LOG_ERROR("MSI-X: BAR%u is zero\n", info->table_bir);
        return false;
    }

    volatile msix_table_entry_t *table =
        (volatile msix_table_entry_t *)(bar + get_hhdm_offset() + info->table_offset);

    table[entry_index].msg_addr_lo = (uint32_t)(LAPIC_MSG_ADDR & 0xFFFFFFFF);
    table[entry_index].msg_addr_hi = 0;
    table[entry_index].msg_data    = vector;
    table[entry_index].vector_ctrl = 0;

    uint8_t cap_ptr = (uint8_t)(pci_read(info->bus, info->slot, info->func, 0x34) & 0xFF);
    while (cap_ptr != 0) {
        uint32_t dword0 = pci_read(info->bus, info->slot, info->func, cap_ptr);
        if ((dword0 & 0xFF) == MSIX_CAP_ID) {
            // Set MSI-X Enable bit (bit 15 of Message Control = bit 31 of dword0)
            pci_write(info->bus, info->slot, info->func, cap_ptr, dword0 | (1u << 31));
            LOG_DEBUG("MSI-X: enabled, entry %u -> IDT vector 0x%x\n", entry_index, vector);
            return true;
        }
        cap_ptr = (uint8_t)((dword0 >> 8) & 0xFF);
    }

    LOG_ERROR("MSI-X: capability disappeared during enable\n");
    return false;
}
