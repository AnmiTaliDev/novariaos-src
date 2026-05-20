// SPDX-License-Identifier: GPL-3.0-only

#include <core/drivers/pci.h>
#include <core/arch/io.h>

uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset) {
    uint32_t addr = (1u << 31) | ((uint32_t)bus << 16) |
                    ((uint32_t)slot << 11) | ((uint32_t)func << 8) |
                    (offset & 0xFC);
    outl(PCI_CONFIG_ADDR, addr);
    return inl(PCI_CONFIG_DATA);
}

void pci_write(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value) {
    uint32_t addr = (1u << 31) | ((uint32_t)bus << 16) |
                    ((uint32_t)slot << 11) | ((uint32_t)func << 8) |
                    (offset & 0xFC);
    outl(PCI_CONFIG_ADDR, addr);
    outl(PCI_CONFIG_DATA, value);
}

uint64_t pci_read_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_index) {
    uint8_t  offset = 0x10 + bar_index * 4;
    uint32_t lo     = pci_read(bus, slot, func, offset);

    if ((lo & 0x6) == 0x4) {
        uint32_t hi = pci_read(bus, slot, func, offset + 4);
        return ((uint64_t)hi << 32) | (lo & ~0xFu);
    }

    return lo & ~0xFu;
}
