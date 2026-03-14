// SPDX-License-Identifier: GPL-3.0-only

#include <core/drivers/nvme.h>
#include <core/drivers/pci.h>
#include <core/arch/idt.h>
#include <core/fs/block.h>
#include <core/kernel/mem/allocator.h>
#include <core/kernel/mem/buddy.h>

#define virt_to_phys(addr) ((uint64_t)(addr) - get_hhdm_offset())
#include <log.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define NVME_MMIO_BASE   0xFEBF0000ULL
#define NVME_IRQ_VECTOR  0x41
#define LAPIC_BASE       0xFEE00000ULL
#define LAPIC_EOI        0x0B0

static void* alloc_dma(size_t size) {
    /* Use buddy_alloc directly — it returns page-aligned memory with no header.
       Round up to the next power-of-2 page multiple. */
    size_t order = BUDDY_MIN_ORDER;
    size_t block_size = BUDDY_BLOCK_SIZE(order);
    while (block_size < size && order < BUDDY_MAX_ORDER) {
        order++;
        block_size <<= 1;
    }
    return buddy_alloc(slab_get_buddy(), block_size);
}

static volatile nvme_controller_regs_t* nvme_regs = NULL;
static nvme_command_t*    admin_sq = NULL;
static nvme_completion_t* admin_cq = NULL;
static nvme_command_t*    io_sq    = NULL;
static nvme_completion_t* io_cq    = NULL;

static uint16_t admin_sq_tail  = 0;
static uint16_t admin_cq_head  = 0;
static uint16_t io_sq_tail     = 0;
static uint16_t io_cq_head     = 0;
static uint16_t command_id     = 0;
static uint8_t  admin_cq_phase = 1;
static uint8_t  io_cq_phase    = 1;

static uint32_t nsid        = 1;
static uint64_t block_count = 0;

static volatile bool     nvme_io_complete = false;
static volatile uint16_t nvme_io_result   = 0;
static bool              nvme_use_irq     = false;

static inline void mmio_write32(volatile uint32_t* addr, uint32_t value) {
    *addr = value;
    __asm__ volatile("" ::: "memory");
}

static inline uint32_t mmio_read32(volatile uint32_t* addr) {
    uint32_t value = *addr;
    __asm__ volatile("" ::: "memory");
    return value;
}

static inline void mmio_write64(volatile uint64_t* addr, uint64_t value) {
    *addr = value;
    __asm__ volatile("" ::: "memory");
}

static inline uint64_t mmio_read64(volatile uint64_t* addr) {
    uint64_t value = *addr;
    __asm__ volatile("" ::: "memory");
    return value;
}

static inline void lapic_eoi(void) {
    volatile uint32_t* p = (volatile uint32_t*)(LAPIC_BASE + LAPIC_EOI);
    *p = 0;
}

static inline void lapic_clear_tpr(void) {
    volatile uint32_t* p = (volatile uint32_t*)(LAPIC_BASE + 0x080);
    *p = 0;
}

static void nvme_write_doorbell(uint32_t queue_id, uint32_t value, bool is_sq) {
    uint64_t cap    = mmio_read64(&nvme_regs->cap);
    uint32_t dstrd  = (uint32_t)((cap & NVME_CAP_DSTRD_MASK) >> NVME_CAP_DSTRD_SHIFT);
    uint32_t offset = queue_id * 2 * (1 << dstrd);

    if (!is_sq)
        offset += (1 << dstrd);

    mmio_write32(&nvme_regs->doorbells[offset], value);
}

static int nvme_wait_ready(bool ready_state, uint32_t timeout_ms) {
    for (uint32_t i = 0; i < timeout_ms * 100; i++) {
        uint32_t csts     = mmio_read32(&nvme_regs->csts);
        bool     is_ready = (csts & NVME_CSTS_RDY) != 0;

        if (is_ready == ready_state)
            return 0;

        for (volatile int j = 0; j < 1000; j++);
    }
    return -1;
}

static int nvme_submit_admin_command(nvme_command_t* cmd) {
    uint16_t slot = admin_sq_tail;
    memcpy(&admin_sq[slot], cmd, sizeof(nvme_command_t));

    admin_sq_tail = (admin_sq_tail + 1) % NVME_ADMIN_QUEUE_SIZE;
    nvme_write_doorbell(0, admin_sq_tail, true);

    for (int timeout = 0; timeout < 10000; timeout++) {
        nvme_completion_t* cqe   = &admin_cq[admin_cq_head];
        uint8_t            phase = (cqe->status >> 0) & 1;

        if (phase == admin_cq_phase) {
            uint16_t status_code = (cqe->status >> 1) & 0x7FFF;
            admin_cq_head = (admin_cq_head + 1) % NVME_ADMIN_QUEUE_SIZE;

            if (admin_cq_head == 0)
                admin_cq_phase = !admin_cq_phase;

            nvme_write_doorbell(0, admin_cq_head, false);

            if (status_code != 0) {
                LOG_ERROR("NVMe admin command failed with status: 0x%x\n", status_code);
                return -1;
            }
            return 0;
        }

        for (volatile int i = 0; i < 1000; i++);
    }

    LOG_ERROR("NVMe admin command timeout\n");
    return -1;
}

static int nvme_identify_namespace(uint32_t ns_id, void* data) {
    nvme_command_t cmd = {0};
    cmd.cdw0  = NVME_ADMIN_IDENTIFY;
    cmd.nsid  = ns_id;
    cmd.prp1  = virt_to_phys(data);
    cmd.cdw10 = NVME_IDENTIFY_CNS_NAMESPACE;
    return nvme_submit_admin_command(&cmd);
}

static int nvme_create_io_completion_queue(uint16_t qid, uint16_t size, void* buffer) {
    nvme_command_t cmd = {0};
    cmd.cdw0  = NVME_ADMIN_CREATE_CQ;
    cmd.prp1  = virt_to_phys(buffer);
    cmd.cdw10 = ((uint32_t)(size - 1) << 16) | qid;
    cmd.cdw11 = NVME_QUEUE_PHYS_CONTIG | NVME_CQ_IRQ_ENABLED;
    return nvme_submit_admin_command(&cmd);
}

static int nvme_create_io_submission_queue(uint16_t qid, uint16_t cqid, uint16_t size, void* buffer) {
    nvme_command_t cmd = {0};
    cmd.cdw0  = NVME_ADMIN_CREATE_SQ;
    cmd.prp1  = virt_to_phys(buffer);
    cmd.cdw10 = ((uint32_t)(size - 1) << 16) | qid;
    cmd.cdw11 = (cqid << 16) | NVME_QUEUE_PHYS_CONTIG;
    return nvme_submit_admin_command(&cmd);
}

static int nvme_reset_controller(void) {
    LOG_DEBUG("NVMe: Resetting controller...\n");

    uint32_t cc = mmio_read32(&nvme_regs->cc);
    cc &= ~NVME_CC_ENABLE;
    mmio_write32(&nvme_regs->cc, cc);

    if (nvme_wait_ready(false, 5000) < 0) {
        LOG_ERROR("NVMe: Controller disable timeout, CSTS=0x%x\n", mmio_read32(&nvme_regs->csts));
        return -1;
    }

    LOG_DEBUG("NVMe: Controller disabled\n");
    return 0;
}

static int nvme_enable_controller(void) {
    uint32_t page_shift = 12;

    uint32_t cc = 0;
    cc |= NVME_CC_ENABLE;
    cc |= NVME_CC_CSS_NVM;
    cc |= ((page_shift - 12) << NVME_CC_MPS_SHIFT);
    cc |= NVME_CC_AMS_RR;
    cc |= NVME_CC_SHN_NONE;
    cc |= NVME_CC_IOSQES;
    cc |= NVME_CC_IOCQES;

    mmio_write32(&nvme_regs->cc, cc);

    if (nvme_wait_ready(true, 5000) < 0) {
        LOG_ERROR("NVMe: Controller enable timeout, CSTS=0x%x\n", mmio_read32(&nvme_regs->csts));
        return -1;
    }

    LOG_DEBUG("NVMe: Controller enabled\n");
    return 0;
}

static int nvme_setup_admin_queues(void) {
    admin_sq = alloc_dma(NVME_ADMIN_QUEUE_SIZE * sizeof(nvme_command_t));
    admin_cq = alloc_dma(NVME_ADMIN_QUEUE_SIZE * sizeof(nvme_completion_t));

    if (!admin_sq || !admin_cq) {
        LOG_ERROR("NVMe: Failed to allocate admin queues\n");
        return -1;
    }

    memset(admin_sq, 0, NVME_ADMIN_QUEUE_SIZE * sizeof(nvme_command_t));
    memset(admin_cq, 0, NVME_ADMIN_QUEUE_SIZE * sizeof(nvme_completion_t));

    uint32_t aqa = ((NVME_ADMIN_QUEUE_SIZE - 1) << 16) | (NVME_ADMIN_QUEUE_SIZE - 1);
    mmio_write32(&nvme_regs->aqa, aqa);
    mmio_write64(&nvme_regs->asq, virt_to_phys(admin_sq));
    mmio_write64(&nvme_regs->acq, virt_to_phys(admin_cq));

    LOG_DEBUG("NVMe: Admin queues configured\n");
    return 0;
}

static int nvme_setup_io_queues(void) {
    io_sq = alloc_dma(NVME_IO_QUEUE_SIZE * sizeof(nvme_command_t));
    io_cq = alloc_dma(NVME_IO_QUEUE_SIZE * sizeof(nvme_completion_t));

    if (!io_sq || !io_cq) {
        LOG_ERROR("NVMe: Failed to allocate I/O queues\n");
        return -1;
    }

    memset(io_sq, 0, NVME_IO_QUEUE_SIZE * sizeof(nvme_command_t));
    memset(io_cq, 0, NVME_IO_QUEUE_SIZE * sizeof(nvme_completion_t));

    if (nvme_create_io_completion_queue(1, NVME_IO_QUEUE_SIZE, io_cq) < 0) {
        LOG_ERROR("NVMe: Failed to create I/O completion queue\n");
        return -1;
    }

    if (nvme_create_io_submission_queue(1, 1, NVME_IO_QUEUE_SIZE, io_sq) < 0) {
        LOG_ERROR("NVMe: Failed to create I/O submission queue\n");
        return -1;
    }

    LOG_DEBUG("NVMe: I/O queues created\n");
    return 0;
}

void __attribute__((interrupt, target("general-regs-only"))) nvme_irq_handler(interrupt_frame_t* frame) {
    (void)frame;

    nvme_completion_t* cqe = &io_cq[io_cq_head];
    if ((cqe->status & 1) == io_cq_phase) {
        nvme_io_result = (cqe->status >> 1) & 0x7FFF;
        io_cq_head = (io_cq_head + 1) % NVME_IO_QUEUE_SIZE;

        if (io_cq_head == 0)
            io_cq_phase = !io_cq_phase;

        nvme_write_doorbell(1, io_cq_head, false);
        nvme_io_complete = true;
    }

    lapic_eoi();
}

static int nvme_submit_io_and_wait(nvme_command_t* cmd) {
    nvme_io_complete = false;
    nvme_io_result   = 0;

    uint16_t slot = io_sq_tail;
    memcpy(&io_sq[slot], cmd, sizeof(nvme_command_t));
    io_sq_tail = (io_sq_tail + 1) % NVME_IO_QUEUE_SIZE;
    nvme_write_doorbell(1, io_sq_tail, true);

    if (nvme_use_irq) {
        for (int i = 0; i < 10000 && !nvme_io_complete; i++)
            __asm__ volatile("sti; hlt; cli" ::: "memory");
    } else {
        for (int timeout = 0; timeout < 10000 && !nvme_io_complete; timeout++) {
            nvme_completion_t* cqe = &io_cq[io_cq_head];
            if ((cqe->status & 1) == io_cq_phase) {
                nvme_io_result = (cqe->status >> 1) & 0x7FFF;
                io_cq_head = (io_cq_head + 1) % NVME_IO_QUEUE_SIZE;

                if (io_cq_head == 0)
                    io_cq_phase = !io_cq_phase;

                nvme_write_doorbell(1, io_cq_head, false);
                nvme_io_complete = true;
            }
            for (volatile int i = 0; i < 1000; i++);
        }
    }

    if (!nvme_io_complete) {
        LOG_ERROR("NVMe: I/O timeout\n");
        return -1;
    }

    if (nvme_io_result != 0) {
        LOG_ERROR("NVMe: I/O failed, status=0x%x\n", nvme_io_result);
        return -1;
    }

    return 0;
}

static int nvme_read_blocks(struct block_device* dev, uint64_t lba, size_t count, void* buf) {
    (void)dev;

    if (lba + count > block_count)
        return -1;

    while (count > 0) {
        size_t n = (count > 256) ? 256 : count;

        nvme_command_t cmd = {0};
        cmd.cdw0  = NVME_CMD_READ | ((uint32_t)(command_id++) << 16);
        cmd.nsid  = nsid;
        cmd.prp1  = virt_to_phys(buf);
        cmd.cdw10 = (uint32_t)(lba & 0xFFFFFFFF);
        cmd.cdw11 = (uint32_t)(lba >> 32);
        cmd.cdw12 = (uint32_t)(n - 1) & 0xFFFF;

        if (nvme_submit_io_and_wait(&cmd) < 0)
            return -1;

        buf    = (void*)((uint64_t)buf + n * 512);
        lba   += n;
        count -= n;
    }

    return 0;
}

static int nvme_write_blocks(struct block_device* dev, uint64_t lba, size_t count, const void* buf) {
    (void)dev;

    if (lba + count > block_count)
        return -1;

    while (count > 0) {
        size_t n = (count > 256) ? 256 : count;

        nvme_command_t cmd = {0};
        cmd.cdw0  = NVME_CMD_WRITE | ((uint32_t)(command_id++) << 16);
        cmd.nsid  = nsid;
        cmd.prp1  = virt_to_phys(buf);
        cmd.cdw10 = (uint32_t)(lba & 0xFFFFFFFF);
        cmd.cdw11 = (uint32_t)(lba >> 32);
        cmd.cdw12 = (uint32_t)(n - 1) & 0xFFFF;

        if (nvme_submit_io_and_wait(&cmd) < 0)
            return -1;

        buf    = (const void*)((uint64_t)buf + n * 512);
        lba   += n;
        count -= n;
    }

    return 0;
}

void nvme_init(void) {
    LOG_DEBUG("NVMe: Initializing driver...\n");

    nvme_regs = (volatile nvme_controller_regs_t*)NVME_MMIO_BASE;

    uint8_t pci_bus = 0, pci_dev = 0, pci_func = 0;
    bool pci_found = pci_find_device_by_class(0x01, 0x08, 0x02,
                                               &pci_bus, &pci_dev, &pci_func);
    if (pci_found) {
        LOG_DEBUG("NVMe: PCI device at %u:%u.%u\n", pci_bus, pci_dev, pci_func);

        uint32_t bar0_lo = pci_read32(pci_bus, pci_dev, pci_func, 0x10);
        uint32_t bar0_hi = pci_read32(pci_bus, pci_dev, pci_func, 0x14);
        uint64_t bar0    = ((uint64_t)bar0_hi << 32) | (bar0_lo & ~0xFull);
        if (bar0 != 0) {
            nvme_regs = (volatile nvme_controller_regs_t*)bar0;
            LOG_DEBUG("NVMe: MMIO at 0x%llx\n", bar0);
        }

        uint16_t pcicmd = pci_read16(pci_bus, pci_dev, pci_func, 0x04);
        pcicmd |= (1 << 1) | (1 << 2);
        pci_write16(pci_bus, pci_dev, pci_func, 0x04, pcicmd);
    }

    uint64_t cap = mmio_read64(&nvme_regs->cap);
    if (cap == 0xFFFFFFFFFFFFFFFFULL || cap == 0) {
        LOG_DEBUG("NVMe: No controller found\n");
        return;
    }

    LOG_DEBUG("NVMe: Controller found, CAP=0x%llx\n", cap);

    if (nvme_reset_controller() < 0) return;
    if (nvme_setup_admin_queues() < 0) return;
    if (nvme_enable_controller() < 0) return;

    uint8_t* identify_data = alloc_dma(4096);
    if (!identify_data) {
        LOG_ERROR("NVMe: Failed to allocate identify buffer\n");
        return;
    }

    memset(identify_data, 0, 4096);

    if (nvme_identify_namespace(nsid, identify_data) < 0) {
        LOG_ERROR("NVMe: Failed to identify namespace\n");
        return;
    }

    block_count = *(uint64_t*)identify_data;
    LOG_DEBUG("NVMe: Namespace size: %llu blocks\n", block_count);

    if (nvme_setup_io_queues() < 0) return;

    /* Polling mode: MSI/interrupts require a proper IDT which this kernel does not
       yet provide. nvme_use_irq stays false; nvme_submit_io_and_wait polls the CQ. */

    block_device_ops_t ops = {
        .read_blocks  = nvme_read_blocks,
        .write_blocks = nvme_write_blocks,
    };

    register_block_device("nvme0n1", 512, block_count, &ops, NULL);
    LOG_DEBUG("NVMe: Initialization complete\n");
}
