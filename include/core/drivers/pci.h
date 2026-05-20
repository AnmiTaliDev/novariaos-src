// SPDX-License-Identifier: GPL-3.0-only

#ifndef DRIVERS_PCI_H
#define DRIVERS_PCI_H

#include <stdint.h>

#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

uint32_t pci_read(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
void     pci_write(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value);
uint64_t pci_read_bar(uint8_t bus, uint8_t slot, uint8_t func, uint8_t bar_index);

#endif // DRIVERS_PCI_H
