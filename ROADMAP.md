# Roadmap for NovariaOS 0.2.0

## High Priority
- [X] Refactor internal shell
- [ ] Memory manager rework:
    - [ ] Buddy
        - [ ] Buddy allocation
        - [ ] Buddy free
    - [ ] Slab
        - [ ] Slab allocation
        - [ ] Slab free
    - [ ] Kstd allocations
        - [ ] kmalloc
        - [ ] kfree

## Medium Priority
- [ ] /dev/tty (WIP: current stage — write only)
- [ ] Poor /sys/pci (vendor/device without interrupts)

## Low Priority 
- [ ] Shell's removal from the kernel
- [ ] Nutils:
    - [ ] cat
    - [ ] ls
- [ ] Passing ARGC, ARGV for binaries running from the Internal Shell
- [ ] Full init system