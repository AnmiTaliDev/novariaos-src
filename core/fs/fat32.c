// SPDX-License-Identifier: GPL-3.0-only

#include <core/fs/fat32.h>
#include <core/fs/block.h>
#include <core/kernel/kstd.h>
#include <core/kernel/log.h>
#include <core/kernel/mem.h>

static const vfs_fs_ops_t fat32_ops;

void fat32_init(void) {
    vfs_register_filesystem("fat32", &fat32_ops, 0);
    LOG_INFO("FAT32 filesystem driver registered\n");
}

int fat32_mount(vfs_mount_t* mnt, const char* device, void* data) {
    LOG_DEBUG("Mounting FAT32 filesystem on device: %s\n", device);
    
    block_device_t* bdev = find_block_device(device);
    if (!bdev) {
        LOG_ERROR("Block device '%s' not found\n", device);
        return -19;
    }
    
    uint8_t* boot_sector = kmalloc(bdev->block_size);
    if (!boot_sector) {
        return -12;
    }
    
    int result = bdev->ops.read_blocks(bdev, 0, 1, boot_sector);
    if (result != 0) {
        LOG_ERROR("Failed to read boot sector: %d\n", result);
        kfree(boot_sector);
        return result;
    }
    
    fat32_bpb_t* bpb = (fat32_bpb_t*)boot_sector;
    
    uint16_t signature = le16_to_cpu(bpb->signature);
    if (signature != 0xAA55) {
        LOG_ERROR("Invalid boot signature: 0x%X (expected 0xAA55)\n", signature);
        kfree(boot_sector);
        return -22;
    }
    
    if (strncmp(bpb->fs_type, "FAT32   ", 8) != 0) {
        LOG_WARN("Filesystem type is not 'FAT32': %.8s\n", bpb->fs_type);
    }
    
    fat32_fs_t* fs_data = kmalloc(sizeof(fat32_fs_t));
    if (!fs_data) {
        kfree(boot_sector);
        return -12;
    }
    
    fs_data->block_dev = bdev;
    fs_data->bytes_per_sector = le16_to_cpu(bpb->bytes_per_sector);
    fs_data->sectors_per_cluster = bpb->sectors_per_cluster;
    fs_data->bytes_per_cluster = fs_data->bytes_per_sector * fs_data->sectors_per_cluster;
    fs_data->reserved_sectors = le16_to_cpu(bpb->reserved_sectors);
    fs_data->num_fats = bpb->num_fats;
    fs_data->fat_size = le32_to_cpu(bpb->fat_size_32);
    fs_data->root_cluster = le32_to_cpu(bpb->root_cluster);
    
    uint32_t total_sectors_16 = le16_to_cpu(bpb->total_sectors_16);
    fs_data->total_sectors = (total_sectors_16 != 0) ? 
        total_sectors_16 : le32_to_cpu(bpb->total_sectors_32);
    
    fs_data->data_start_sector = fs_data->reserved_sectors + 
        (fs_data->num_fats * fs_data->fat_size);
    
    uint32_t data_sectors = fs_data->total_sectors - fs_data->data_start_sector;
    fs_data->total_clusters = data_sectors / fs_data->sectors_per_cluster;
    
    if (fs_data->total_clusters < 65525) {
        LOG_ERROR("Too few clusters for FAT32: %u (need >= 65525)\n", 
                  fs_data->total_clusters);
        kfree(fs_data);
        kfree(boot_sector);
        return -22;
    }
    
    LOG_INFO("FAT32 mounted successfully:\n");
    LOG_INFO("  Volume Label: %.11s\n", bpb->volume_label);
    LOG_INFO("  Bytes/Sector: %u\n", fs_data->bytes_per_sector);
    LOG_INFO("  Sectors/Cluster: %u\n", fs_data->sectors_per_cluster);
    LOG_INFO("  Reserved Sectors: %u\n", fs_data->reserved_sectors);
    LOG_INFO("  Number of FATs: %u\n", fs_data->num_fats);
    LOG_INFO("  FAT Size: %u sectors\n", fs_data->fat_size);
    LOG_INFO("  Root Cluster: %u\n", fs_data->root_cluster);
    LOG_INFO("  Total Sectors: %u\n", fs_data->total_sectors);
    LOG_INFO("  Total Clusters: %u\n", fs_data->total_clusters);
    
    mnt->fs_private = fs_data;
    
    kfree(boot_sector);
    return 0;
}

int fat32_unmount(vfs_mount_t* mnt) {
    if (!mnt || !mnt->fs_private) {
        return -22;
    }
    
    fat32_fs_t* fs_data = (fat32_fs_t*)mnt->fs_private;
    kfree(fs_data);
    mnt->fs_private = NULL;
    
    LOG_INFO("FAT32 filesystem unmounted\n");
    return 0;
}

<<<<<<< HEAD
// --- Cluster chain management ---

int fat32_read_fat_entry(fat32_fs_t* fs, uint32_t cluster, uint32_t* out_entry) {
    if (!fs || !out_entry) return -EINVAL;
    if (cluster < 2 || cluster >= fs->total_clusters + 2) {
        LOG_ERROR("fat32_read_fat_entry: cluster %u out of range\n", cluster);
        return -EINVAL;
    }

    uint32_t fat_offset = cluster * 4;
    uint32_t fat_sector = fs->reserved_sectors + (fat_offset / fs->bytes_per_sector);
    uint32_t offset_in_sector = fat_offset % fs->bytes_per_sector;

    uint8_t* sector_buf = kmalloc(fs->bytes_per_sector);
    if (!sector_buf) return -ENOMEM;

    int rc = fs->block_dev->ops.read_blocks(fs->block_dev, fat_sector, 1, sector_buf);
    if (rc != 0) {
        LOG_ERROR("fat32_read_fat_entry: read failed at sector %u: %d\n", fat_sector, rc);
        kfree(sector_buf);
        return rc;
    }

    uint32_t raw = le32_to_cpu(*(uint32_t*)(sector_buf + offset_in_sector));
    *out_entry = raw & FAT32_MASK;

    kfree(sector_buf);
    return 0;
}

int fat32_write_fat_entry(fat32_fs_t* fs, uint32_t cluster, uint32_t value) {
    if (!fs) return -EINVAL;
    if (cluster < 2 || cluster >= fs->total_clusters + 2) {
        LOG_ERROR("fat32_write_fat_entry: cluster %u out of range\n", cluster);
        return -EINVAL;
    }

    uint32_t fat_offset = cluster * 4;
    uint32_t sector_offset_in_fat = fat_offset / fs->bytes_per_sector;
    uint32_t offset_in_sector = fat_offset % fs->bytes_per_sector;

    uint8_t* sector_buf = kmalloc(fs->bytes_per_sector);
    if (!sector_buf) return -ENOMEM;

    for (uint32_t i = 0; i < fs->num_fats; i++) {
        uint32_t fat_sector = fs->reserved_sectors +
                              (i * fs->fat_size) + sector_offset_in_fat;

        int rc = fs->block_dev->ops.read_blocks(fs->block_dev, fat_sector, 1, sector_buf);
        if (rc != 0) {
            LOG_ERROR("fat32_write_fat_entry: read failed at sector %u: %d\n", fat_sector, rc);
            kfree(sector_buf);
            return rc;
        }

        uint32_t* entry_ptr = (uint32_t*)(sector_buf + offset_in_sector);
        uint32_t old_raw = le32_to_cpu(*entry_ptr);
        uint32_t new_raw = (old_raw & ~FAT32_MASK) | (value & FAT32_MASK);
        *entry_ptr = cpu_to_le32(new_raw);

        rc = fs->block_dev->ops.write_blocks(fs->block_dev, fat_sector, 1, sector_buf);
        if (rc != 0) {
            LOG_ERROR("fat32_write_fat_entry: write failed at sector %u: %d\n", fat_sector, rc);
            kfree(sector_buf);
            return rc;
        }
    }

    kfree(sector_buf);
    return 0;
}

int fat32_get_cluster_chain(fat32_fs_t* fs, uint32_t start_cluster,
                            uint32_t* chain, size_t max_len, size_t* out_len) {
    if (!fs || !chain || !out_len || max_len == 0) return -EINVAL;

    size_t count = 0;
    uint32_t cluster = start_cluster;

    while (count < max_len) {
        if (cluster < 2 || fat32_is_bad(cluster) || fat32_is_eoc(cluster))
            break;

        chain[count++] = cluster;

        uint32_t next;
        int rc = fat32_read_fat_entry(fs, cluster, &next);
        if (rc != 0) return rc;

        cluster = next;
    }

    *out_len = count;
    return 0;
}

int fat32_alloc_cluster(fat32_fs_t* fs, uint32_t* out_cluster) {
    if (!fs || !out_cluster) return -EINVAL;

    for (uint32_t c = 2; c < fs->total_clusters + 2; c++) {
        uint32_t entry;
        int rc = fat32_read_fat_entry(fs, c, &entry);
        if (rc != 0) return rc;

        if (fat32_is_free(entry)) {
            rc = fat32_write_fat_entry(fs, c, FAT32_EOC);
            if (rc != 0) return rc;

            *out_cluster = c;
            LOG_DEBUG("fat32_alloc_cluster: allocated cluster %u\n", c);
            return 0;
        }
    }

    LOG_ERROR("fat32_alloc_cluster: no free clusters\n");
    return -ENOSPC;
}

int fat32_extend_chain(fat32_fs_t* fs, uint32_t last_cluster, uint32_t* out_new) {
    if (!fs || !out_new) return -EINVAL;

    uint32_t new_cluster;
    int rc = fat32_alloc_cluster(fs, &new_cluster);
    if (rc != 0) return rc;

    rc = fat32_write_fat_entry(fs, last_cluster, new_cluster);
    if (rc != 0) {
        fat32_write_fat_entry(fs, new_cluster, FAT32_FREE);
        return rc;
    }

    *out_new = new_cluster;
    return 0;
}

int fat32_free_chain(fat32_fs_t* fs, uint32_t start_cluster) {
    if (!fs) return -EINVAL;

    uint32_t cluster = start_cluster;

    while (cluster >= 2 && !fat32_is_free(cluster) && !fat32_is_bad(cluster)) {
        uint32_t next;
        int rc = fat32_read_fat_entry(fs, cluster, &next);
        if (rc != 0) return rc;

        rc = fat32_write_fat_entry(fs, cluster, FAT32_FREE);
        if (rc != 0) return rc;

        LOG_TRACE("fat32_free_chain: freed cluster %u\n", cluster);

        if (fat32_is_eoc(next))
            break;

        cluster = next;
    }

    return 0;
}

uint32_t fat32_cluster_to_sector(fat32_fs_t* fs, uint32_t cluster) {
    return fs->data_start_sector + (uint32_t)(cluster - 2) * fs->sectors_per_cluster;
}

int fat32_read_cluster(fat32_fs_t* fs, uint32_t cluster, void* buffer) {
    if (!fs || !buffer) return -EINVAL;
    if (cluster < 2 || cluster >= fs->total_clusters + 2) return -EINVAL;

    uint32_t sector = fat32_cluster_to_sector(fs, cluster);
    return fs->block_dev->ops.read_blocks(fs->block_dev, sector,
                                          fs->sectors_per_cluster, buffer);
}

int fat32_write_cluster(fat32_fs_t* fs, uint32_t cluster, const void* buffer) {
    if (!fs || !buffer) return -EINVAL;
    if (cluster < 2 || cluster >= fs->total_clusters + 2) return -EINVAL;

    uint32_t sector = fat32_cluster_to_sector(fs, cluster);
    return fs->block_dev->ops.write_blocks(fs->block_dev, sector,
                                           fs->sectors_per_cluster, buffer);
}

// --- Mock block device for testing ---

#define TEST_SECTOR_SIZE  512
#define TEST_TOTAL_SECTORS 262144  // 128MB
#define TEST_DISK_SIZE (TEST_SECTOR_SIZE * 256) // only allocate FAT area in memory

static uint8_t* test_disk = NULL;

static int mock_read_blocks(block_device_t* dev, uint64_t lba, size_t count, void* buf) {
    size_t offset = lba * TEST_SECTOR_SIZE;
    size_t len = count * TEST_SECTOR_SIZE;
    if (offset + len > TEST_DISK_SIZE) {
        memset(buf, 0, len);
        return 0;
    }
    memcpy(buf, test_disk + offset, len);
    return 0;
}

static int mock_write_blocks(block_device_t* dev, uint64_t lba, size_t count, const void* buf) {
    size_t offset = lba * TEST_SECTOR_SIZE;
    size_t len = count * TEST_SECTOR_SIZE;
    if (offset + len > TEST_DISK_SIZE) return -EINVAL;
    memcpy(test_disk + offset, buf, len);
    return 0;
}

void fat32_test(void) {
    LOG_INFO("=== FAT32 cluster chain management test ===\n");

    test_disk = kmalloc(TEST_DISK_SIZE);
    if (!test_disk) {
        LOG_ERROR("fat32_test: failed to allocate test disk\n");
        return;
    }
    memset(test_disk, 0, TEST_DISK_SIZE);

    block_device_t mock_bdev;
    memset(&mock_bdev, 0, sizeof(mock_bdev));
    mock_bdev.block_size = TEST_SECTOR_SIZE;
    mock_bdev.total_blocks = TEST_TOTAL_SECTORS;
    mock_bdev.ops.read_blocks = mock_read_blocks;
    mock_bdev.ops.write_blocks = mock_write_blocks;

    fat32_fs_t fs;
    fs.block_dev = &mock_bdev;
    fs.bytes_per_sector = TEST_SECTOR_SIZE;
    fs.sectors_per_cluster = 8;
    fs.bytes_per_cluster = fs.bytes_per_sector * fs.sectors_per_cluster;
    fs.reserved_sectors = 32;
    fs.num_fats = 2;
    fs.fat_size = 64;
    fs.root_cluster = 2;
    fs.total_sectors = TEST_TOTAL_SECTORS;
    fs.data_start_sector = fs.reserved_sectors + (fs.num_fats * fs.fat_size);
    uint32_t data_sectors = fs.total_sectors - fs.data_start_sector;
    fs.total_clusters = data_sectors / fs.sectors_per_cluster;

    // Set up FAT: cluster 0 and 1 are reserved (media type + EOC)
    uint32_t* fat_base = (uint32_t*)(test_disk + fs.reserved_sectors * TEST_SECTOR_SIZE);
    fat_base[0] = cpu_to_le32(0x0FFFFFF8);  // media type
    fat_base[1] = cpu_to_le32(0x0FFFFFFF);  // EOC
    fat_base[2] = cpu_to_le32(0x0FFFFFFF);  // root dir = 1 cluster, EOC

    int rc;
    int passed = 0;
    int failed = 0;

    // Test 1: read_fat_entry on root cluster
    uint32_t entry;
    rc = fat32_read_fat_entry(&fs, 2, &entry);
    if (rc == 0 && fat32_is_eoc(entry)) {
        LOG_INFO("  [PASS] Test 1: read_fat_entry(cluster 2) = 0x%X (EOC)\n", entry);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 1: read_fat_entry(cluster 2) rc=%d entry=0x%X\n", rc, entry);
        failed++;
    }

    // Test 2: alloc_cluster
    uint32_t new_c;
    rc = fat32_alloc_cluster(&fs, &new_c);
    if (rc == 0 && new_c == 3) {
        LOG_INFO("  [PASS] Test 2: alloc_cluster returned cluster %u\n", new_c);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 2: alloc_cluster rc=%d cluster=%u\n", rc, new_c);
        failed++;
    }

    // Test 3: verify allocated cluster is EOC
    rc = fat32_read_fat_entry(&fs, new_c, &entry);
    if (rc == 0 && fat32_is_eoc(entry)) {
        LOG_INFO("  [PASS] Test 3: allocated cluster %u is EOC (0x%X)\n", new_c, entry);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 3: cluster %u entry=0x%X, rc=%d\n", new_c, entry, rc);
        failed++;
    }

    // Test 4: extend_chain from root cluster
    uint32_t ext_c;
    rc = fat32_extend_chain(&fs, 2, &ext_c);
    if (rc == 0 && ext_c == 4) {
        LOG_INFO("  [PASS] Test 4: extend_chain from cluster 2 -> new cluster %u\n", ext_c);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 4: extend_chain rc=%d cluster=%u\n", rc, ext_c);
        failed++;
    }

    // Test 5: verify chain 2 -> 4 -> EOC
    rc = fat32_read_fat_entry(&fs, 2, &entry);
    if (rc == 0 && entry == 4) {
        LOG_INFO("  [PASS] Test 5: cluster 2 -> %u\n", entry);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 5: cluster 2 entry=0x%X, rc=%d\n", entry, rc);
        failed++;
    }

    rc = fat32_read_fat_entry(&fs, 4, &entry);
    if (rc == 0 && fat32_is_eoc(entry)) {
        LOG_INFO("  [PASS] Test 5b: cluster 4 is EOC\n");
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 5b: cluster 4 entry=0x%X, rc=%d\n", entry, rc);
        failed++;
    }

    // Test 6: get_cluster_chain from cluster 2
    uint32_t chain[16];
    size_t chain_len;
    rc = fat32_get_cluster_chain(&fs, 2, chain, 16, &chain_len);
    if (rc == 0 && chain_len == 2 && chain[0] == 2 && chain[1] == 4) {
        LOG_INFO("  [PASS] Test 6: get_cluster_chain = [%u, %u], len=%u\n",
                 chain[0], chain[1], chain_len);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 6: rc=%d len=%u\n", rc, chain_len);
        failed++;
    }

    // Test 7: free_chain on cluster 3 (standalone)
    rc = fat32_free_chain(&fs, 3);
    if (rc == 0) {
        rc = fat32_read_fat_entry(&fs, 3, &entry);
        if (rc == 0 && fat32_is_free(entry)) {
            LOG_INFO("  [PASS] Test 7: free_chain(3), cluster 3 is now FREE\n");
            passed++;
        } else {
            LOG_ERROR("  [FAIL] Test 7: cluster 3 entry=0x%X after free\n", entry);
            failed++;
        }
    } else {
        LOG_ERROR("  [FAIL] Test 7: free_chain rc=%d\n", rc);
        failed++;
    }

    // Test 8: free_chain on cluster 2 (chain 2->4)
    rc = fat32_free_chain(&fs, 2);
    fat32_read_fat_entry(&fs, 2, &entry);
    uint32_t entry4;
    fat32_read_fat_entry(&fs, 4, &entry4);
    if (rc == 0 && fat32_is_free(entry) && fat32_is_free(entry4)) {
        LOG_INFO("  [PASS] Test 8: free_chain(2), clusters 2 and 4 are FREE\n");
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 8: c2=0x%X c4=0x%X rc=%d\n", entry, entry4, rc);
        failed++;
    }

    // Test 9: cluster_to_sector
    uint32_t sector = fat32_cluster_to_sector(&fs, 2);
    uint32_t expected = fs.data_start_sector;
    if (sector == expected) {
        LOG_INFO("  [PASS] Test 9: cluster_to_sector(2) = %u\n", sector);
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 9: expected %u, got %u\n", expected, sector);
        failed++;
    }

    // Test 10: out-of-range cluster
    rc = fat32_read_fat_entry(&fs, 0, &entry);
    if (rc == -EINVAL) {
        LOG_INFO("  [PASS] Test 10: read_fat_entry(0) returned -EINVAL\n");
        passed++;
    } else {
        LOG_ERROR("  [FAIL] Test 10: expected -EINVAL, got %d\n", rc);
        failed++;
    }

    LOG_INFO("=== FAT32 test results: %d passed, %d failed ===\n", passed, failed);

    kfree(test_disk);
    test_disk = NULL;
}

static const vfs_fs_ops_t fat32_ops = {
    .name = "fat32",
    .mount = fat32_mount,
    .unmount = fat32_unmount,
    .open = NULL,
    .close = NULL,
    .read = NULL,
    .write = NULL,
    .seek = NULL,
    .mkdir = NULL,
    .rmdir = NULL,
    .readdir = NULL,
    .stat = NULL,
    .unlink = NULL,
    .ioctl = NULL,
    .sync = NULL,
};
