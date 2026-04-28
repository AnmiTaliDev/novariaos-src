#ifndef SYSCALL_H
#define SYSCALL_H

#include <core/kernel/nvm/nvm.h>
#include <stdint.h>

// Process Managment
#define SYS_EXIT            0x00
#define SYS_SPAWN           0x01
#define SYS_CAP_SPAWN       0x02
#define SYS_SLEEP           0x03

// Files
#define SYS_OPEN            0x10 
#define SYS_CLOSE           0x11
#define SYS_READ            0x12
#define SYS_WRITE           0x13
#define SYS_MKDIR           0x14
#define SYS_REMOVE          0x15
#define SYS_DUP2            0x16

// Memory
#define SYS_SBRK            0x20

// Synchronization
#define SYS_AWAIT           0x30 

int32_t syscall_handler(uint8_t syscall_id, nvm_process_t* proc);

#endif