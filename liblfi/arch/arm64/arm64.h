#ifndef LFI_ARM64_H
#define LFI_ARM64_H

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "lfi.h"

static uint64_t r_tpidr() {
    uint64_t val;
    asm volatile ("mrs %0, tpidr_el0" : "=r"(val));
    return val;
}

static void w_tpidr(uint64_t val) {
    asm volatile ("msr tpidr_el0, %0" :: "r"(val));
}

static void wr_regs_base(struct lfi_regs* regs, uint64_t val) {
    regs->x21 = val;
}

static uint64_t* regs_addr(struct lfi_regs* regs, int n) {
    switch (n) {
    case 0:
        return &regs->x18;
    case 1:
        return &regs->sp;
    case 2:
        return &regs->x30;
    }
    return NULL;
}

static uint64_t* regs_sys(struct lfi_regs* regs) {
#ifdef SYSEXTERNAL
    return &regs->x25;
#else
    (void) regs;
    return NULL;
#endif
}

static uint64_t* regs_gas(struct lfi_regs* regs) {
    return &regs->x23;
}

static uint64_t* regs_mask(struct lfi_regs* regs) {
    return &regs->x24;
}

static void regs_init(struct lfi_regs* regs, uint64_t entry, uint64_t sp) {
    regs->x30 = entry;
    regs->sp = sp;
}

#endif
