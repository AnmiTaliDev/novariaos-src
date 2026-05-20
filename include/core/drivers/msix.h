// SPDX-License-Identifier: GPL-3.0-only

#ifndef DRIVERS_MSIX_H
#define DRIVERS_MSIX_H

#include <stdint.h>
#include <stdbool.h>

#define MSIX_CAP_ID 0x11

typedef struct {
    uint8_t  bus;
    uint8_t  slot;
    uint8_t  func;
    uint8_t  table_bir;
    uint32_t table_offset;
    uint16_t num_vectors;
} msix_info_t;

bool msix_find(uint8_t bus, uint8_t slot, uint8_t func, msix_info_t *out);
bool msix_setup(const msix_info_t *info, uint8_t entry_index, uint8_t vector);

#endif // DRIVERS_MSIX_H
