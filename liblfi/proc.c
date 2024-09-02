#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

#include "align.h"
#include "lfi.h"
#include "lfiv.h"
#include "engine.h"
#include "proc.h"
#include "err.h"
#include "elf.h"

#if defined(__aarch64__) || defined(_M_ARM64)
#include "arch/arm64/arm64.h"
#elif defined(__x86_64__) || defined(_M_X64)
#include "arch/amd64/amd64.h"
#endif

extern uint64_t lfi_proc_entry(LFIProc* proc, void** kstackp) asm ("lfi_proc_entry");
extern uint64_t lfi_asm_invoke(LFIProc* proc, void* fn, void** kstackp) asm ("lfi_asm_invoke");
extern void lfi_asm_proc_exit(void* kstackp, uint64_t code) asm ("lfi_asm_proc_exit");
extern void lfi_syscall_entry() asm ("lfi_syscall_entry");
extern void lfi_get_tp() asm ("lfi_get_tp");
extern void lfi_set_tp() asm ("lfi_set_tp");

static uintptr_t
procaddr(uintptr_t base, uintptr_t addr)
{
    return base | ((uint32_t) addr);
}

static uint64_t
mask(int size)
{
    return (~0ULL) >> (64 - size);
}

static void
proc_validate(LFIProc* proc)
{
    uint64_t* r;

    // base
    wr_regs_base(&proc->regs, proc->base);

    // address registers
    int n = 0;
    while ((r = regs_addr(&proc->regs, n++)))
        *r = procaddr(proc->base, *r);

    // sys register (if used for this arch)
    if ((r = regs_sys(&proc->regs)))
        *r = (uintptr_t) proc->sys;

    if (proc->lfi->opts.p2size != 32 && proc->lfi->opts.p2size != 0)
        /* *regs_mask(&proc->regs) = 64 - proc->lfi->opts.p2size; */
        *lfi_regs_mask(&proc->regs) = mask(proc->lfi->opts.p2size);
}

bool
lfi_proc_init(LFIProc* proc, uintptr_t entry, uintptr_t sp)
{
    regs_init(&proc->regs, entry, sp);
    proc_validate(proc);
    if (proc->lfi->opts.gas) {
        uint64_t* r;
        if ((r = lfi_regs_gas(&proc->regs))) {
            *r = proc->lfi->opts.gas;
        } else {
            lfi_errno = LFI_ERR_INVALID_GAS;
            return false;
        }
    }
    return true;
}

__attribute__((visibility("hidden"))) _Thread_local LFIProc* lfi_myproc;

LFIProc*
lfi_proc()
{
    return lfi_myproc;
}

void
lfi_proc_settp(LFIProc* p, void* tp)
{
    p->tp = tp;
}

uint64_t
lfi_proc_start(LFIProc* proc)
{
    lfi_myproc = proc;
    return lfi_proc_entry(proc, &proc->kstackp);
}

uint64_t
lfi_proc_invoke(LFIProc* proc, void* fn, void* ret)
{
    lfi_myproc = proc;
    // TODO: set return point to retfn in a cross-architecture way
#if defined(__x86_64__) || defined(_M_X64)
    *((void**) proc->regs.rsp) = ret;
#endif
    return lfi_asm_invoke(proc, fn, &proc->kstackp);
}

void
lfi_proc_exit(uint64_t code)
{
    LFIProc* p = lfi_myproc;
    lfi_myproc = NULL;
    lfi_asm_proc_exit(p->kstackp, code);
}

static bool
elfcheck(ElfFileHeader* ehdr)
{
    return ehdr->magic == ELF_MAGIC &&
        ehdr->width == ELFCLASS64 &&
        ehdr->version == EV_CURRENT &&
        (ehdr->type == ET_DYN || ehdr->type == ET_EXEC);
}

static int
pflags(int prot)
{
    return ((prot & PF_R) ? PROT_READ : 0) |
        ((prot & PF_W) ? PROT_WRITE : 0) |
        ((prot & PF_X) ? PROT_EXEC : 0);
}

static int
mprotectverify(void* base, size_t size, int prot, LFIVerifier* verifier)
{
    if ((prot & PROT_EXEC) == 0 || !verifier)
        return mprotect(base, size, prot);
    if (!lfiv_verify(verifier, base, size, (uintptr_t) base)) {
        lfi_errno = LFI_ERR_VERIFY;
        return -1;
    }
    return mprotect(base, size, prot);
}

static void*
mmapverify(void* base, size_t size, int prot, int flags, int fd, off_t offset, LFIVerifier* verifier)
{
    if ((prot & PROT_EXEC) == 0)
        return mmap(base, size, prot, flags, fd, offset);
    void* p = mmap(base, size, PROT_READ, flags, fd, offset);
    if (p == (void*) -1) {
        lfi_errno = LFI_ERR_CANNOT_MAP;
        return p;
    }
    if (mprotectverify(base, size, prot, verifier) < 0) {
        munmap(base, size);
        return (void*) -1;
    }
    return p;
}

static void
sanitize(void* p, size_t sz, int prot)
{
    if ((prot & PROT_EXEC) == 0)
        return;
#if defined(__x86_64__) || defined(_M_X64)
    const uint8_t SAFE_BYTE = 0xcc;
    memset(p, SAFE_BYTE, sz);
#endif
}

static bool
preadcode(void* base, size_t size, int prot, size_t offset, ssize_t amt, int fd, LFIVerifier* verifier)
{
    sanitize(base, size, prot);
    ssize_t n = pread(fd, base, amt, offset);
    if (n != amt) {
        lfi_errno = LFI_ERR_INVALID_ELF;
        return false;
    }
    if (mprotectverify(base, size, prot, verifier) < 0)
        return false;
    return true;
}

enum {
    MAPANON = MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
    MAPFILE = MAP_PRIVATE | MAP_FIXED,
};

// mapelfseg maps an ELF segment from a file.
//
// start:    the page-aligned start of the segment.
// offset:   the offset within the segment that the data begins at.
// end:      the page-aligned end of the segment.
// p_offset: the offset within the file that the data begins at.
// filesz:   the amount of data in the file.
// fd:       the file descriptor.
// verifier: the LFI verifier.
//
// The caller is expected to munmap all regions in case of an error.
static bool
mapelfseg(uintptr_t start, uintptr_t offset, uintptr_t end,
        size_t p_offset, size_t filesz, int prot, int fd,
        size_t pagesize, LFIVerifier* verifier)
{
    // Map the first page, which we will copy into from the file.
    void* pg1 = mmap((void*) start, pagesize, PROT_READ | PROT_WRITE, MAPANON, -1, 0);
    if (pg1 == (void*) -1) {
        lfi_errno = LFI_ERR_CANNOT_MAP;
        return false;
    }
    // If we have any subsequent errors, it is expected that the caller will
    // munmap all mapped regions.

    ssize_t amt = pagesize < filesz ? pagesize : filesz;
    if (!preadcode(pg1, pagesize, prot, p_offset, amt, fd, verifier))
        return false;
    if (filesz < pagesize)
        return true;

    // Page-aligned start of the final region of the segment.
    uintptr_t laststart = truncp(start + offset + filesz, pagesize);
    void* pgend = mmap((void*) laststart, end - laststart, PROT_READ | PROT_WRITE, MAPANON, -1, 0);
    if (pgend == (void*) -1) {
        lfi_errno = LFI_ERR_CANNOT_MAP;
        return false;
    }
    size_t lastfilestart = truncp(offset + filesz, pagesize);
    if (!preadcode(pgend, end - laststart, prot, lastfilestart, offset + filesz - lastfilestart, fd, verifier))
        return false;

    // Map everything in the middle directly from the file.
    uintptr_t midstart = start + pagesize;
    if (midstart == 0)
        return true;
    void* middle = mmapverify((void*) midstart, laststart - midstart, prot, MAPFILE, fd, p_offset + amt, verifier);
    if (middle == (void*) -1)
        return false;

    return true;
}

// Alternative to mapelfseg that copies data out of the ELF file instead of
// directly mapping it. This may be desired because if we directly map the ELF
// file any changes to the underlying file data could cause unspecified updates
// in our mapping. The caller is expected to munmap all regions in case of an
// error.
static bool
preadelfseg(uintptr_t start, uintptr_t offset, uintptr_t end,
        size_t p_offset, size_t filesz, int prot, int fd,
        size_t pagesize, LFIVerifier* verifier)
{
    void* p = mmap((void*) start, end - start, PROT_READ | PROT_WRITE, MAPANON, -1, 0);
    if (p == (void*) -1) {
        lfi_errno = LFI_ERR_CANNOT_MAP;
        return false;
    }
    // If we have any subsequent errors, it is expected that the caller will
    // munmap all mapped regions.

    sanitize(p, pagesize, prot);
    sanitize((void*) (end - pagesize), pagesize, prot);
    ssize_t n = pread(fd, (void*) (start + offset), filesz, p_offset);
    if (n != (ssize_t) filesz) {
        lfi_errno = LFI_ERR_INVALID_ELF;
        return false;
    }
    if (mprotectverify((void*) start, end - start, prot, verifier) < 0)
        return false;
    return true;
}

static bool
load(LFIProc* proc, int fd, uintptr_t base, uintptr_t* plast, uintptr_t* pentry)
{
    uintptr_t last = 0;
    size_t pagesize = proc->lfi->opts.pagesize;

    ElfFileHeader ehdr;
    ssize_t n = pread(fd, &ehdr, sizeof(ehdr), 0);
    if (n != sizeof(ehdr)) {
        lfi_errno = LFI_ERR_INVALID_ELF;
        return false;
    }

    if (!elfcheck(&ehdr)) {
        lfi_errno = LFI_ERR_INVALID_ELF;
        return false;
    }

    ElfProgHeader* phdr = malloc(sizeof(ElfProgHeader) * ehdr.phnum);
    if (!phdr) {
        lfi_errno = LFI_ERR_NOMEM;
        return false;
    }

    n = pread(fd, phdr, sizeof(ElfProgHeader) * ehdr.phnum, ehdr.phoff);
    if (n != sizeof(ElfProgHeader) * ehdr.phnum) {
        lfi_errno = LFI_ERR_INVALID_ELF;
        goto err1;
    }

    if (ehdr.entry >= CODEMAX) {
        lfi_errno = LFI_ERR_INVALID_ELF;
        goto err1;
    }

    // TODO: enforce filesz/memsz limit?

    for (int i = 0; i < ehdr.phnum; i++) {
        ElfProgHeader* p = &phdr[i];
        if (p->type != PT_LOAD)
            continue;
        if (p->memsz == 0)
            continue;

        if (p->align % pagesize != 0) {
            lfi_errno = LFI_ERR_INVALID_ELF;
            goto err1;
        }

        uintptr_t start = truncp(p->vaddr, p->align);
        uintptr_t end = ceilp(p->vaddr + p->memsz, p->align);
        uintptr_t offset = p->vaddr - start;

        if (ehdr.type == ET_EXEC) {
            if (start < base) {
                lfi_errno = LFI_ERR_INVALID_ELF;
                goto err1;
            }
            start = start - (base - proc->base);
            end = end - (base - proc->base);
        }

        if (p->memsz < p->filesz) {
            lfi_errno = LFI_ERR_INVALID_ELF;
            goto err1;
        }
        if (end <= start || start >= CODEMAX || end >= CODEMAX) {
            lfi_errno = LFI_ERR_INVALID_ELF;
            goto err1;
        }

        // TODO: use preadelfseg instead?
        if (!mapelfseg(base + start, offset, end, p->offset, p->filesz, pflags(p->flags), fd, pagesize, proc->lfi->opts.verifier))
            goto err1;

        if (base == 0) {
            base = base + start;
        }
        if (base + end > last) {
            last = base + end;
        }
    }

    *plast = last;
    *pentry = ehdr.type == ET_DYN ? base + ehdr.entry : proc->base + ehdr.entry;

    free(phdr);

    return true;
err1:
    free(phdr);
    return false;
}

static LFISys*
sysalloc(uintptr_t base, int sysexternal, size_t pagesize)
{
    LFISys* sys;
    if (sysexternal) {
        sys = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    } else {
        sys = mmap((void*) base, pagesize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }
    if (sys == (void*) -1)
        return NULL;
    return sys;
}

static void
syssetup(LFISys* table, LFIProc* proc) {
    table->rtcalls[0] = (uintptr_t) &lfi_syscall_entry;
    table->rtcalls[1] = (uintptr_t) &lfi_get_tp;
    table->rtcalls[2] = (uintptr_t) &lfi_set_tp;
    table->base = proc->base;
    mprotect(table, proc->lfi->opts.pagesize, PROT_READ);
}

static void
procclear(LFIProc* proc)
{
    void* p = mmap((void*) proc->base, proc->size, PROT_NONE, MAPANON, -1, 0);
    assert(p != (void*) -1);
}

bool
lfi_proc_loadelf(LFIProc* proc, int elffd, int interpfd, LFIProcInfo* info)
{
    uintptr_t guard1 = proc->base + proc->lfi->opts.pagesize;
    uintptr_t guard2 = proc->base + proc->size - GUARD2SZ;

    void* g1 = mmap((void*) guard1, GUARD1SZ, PROT_NONE, MAPANON, -1, 0);
    if (g1 == (void*) -1)
        goto maperr;
    void* g2 = mmap((void*) guard2, GUARD2SZ, PROT_NONE, MAPANON, -1, 0);
    if (g2 == (void*) -1)
        goto maperr;

    size_t stacksize = proc->lfi->opts.stacksize;
    void* stack = mmap((void*) ((uintptr_t) g2 - stacksize), stacksize, PROT_READ | PROT_WRITE, MAPANON, -1, 0);
    if (stack == (void*) -1)
        goto maperr;
    proc->stack = stack;

    proc->sys = sysalloc(proc->base, proc->lfi->opts.sysexternal, proc->lfi->opts.pagesize);
    if (!proc->sys)
        goto err;
    syssetup(proc->sys, proc);

    // Now we are ready to load.
    uintptr_t base = (uintptr_t) g1 + GUARD1SZ;
    uintptr_t plast, pentry, ilast, ientry;
    bool interp = interpfd >= 0;
    if (!load(proc, elffd, base, &plast, &pentry))
        goto err;
    if (interp)
        if (!load(proc, interpfd, plast, &ilast, &ientry))
            goto err;

    ElfFileHeader ehdr;
    ssize_t n = pread(elffd, &ehdr, sizeof(ehdr), 0);
    assert(n == sizeof(ehdr)); // must succeed since we just read it to load

    *info = (LFIProcInfo) {
        .stack = (void*) proc->stack,
        .stacksize = stacksize,
        .lastva = interp ? ilast : plast,
        .elfentry = pentry,
        .ldentry = interp ? ientry : 0,
        .elfbase = base,
        .ldbase = interp ? plast : base,
        .elfphoff = ehdr.phoff,
        .elfphnum = ehdr.phnum,
        .elfphentsize = ehdr.phentsize,
    };

    return true;

maperr:
    lfi_errno = LFI_ERR_CANNOT_MAP;
err:
    procclear(proc);
    return false;
}

LFIRegs*
lfi_proc_regs(LFIProc* proc)
{
    return &proc->regs;
}

// This function will be called from assembly.
void lfi_syscall_handler(LFIProc* proc) asm ("lfi_syscall_handler");

void
lfi_syscall_handler(LFIProc* proc)
{
    uint64_t sysno = *lfi_regs_sysno(&proc->regs);

    uint64_t a0 = *lfi_regs_sysarg(&proc->regs, 0);
    uint64_t a1 = *lfi_regs_sysarg(&proc->regs, 1);
    uint64_t a2 = *lfi_regs_sysarg(&proc->regs, 2);
    uint64_t a3 = *lfi_regs_sysarg(&proc->regs, 3);
    uint64_t a4 = *lfi_regs_sysarg(&proc->regs, 4);
    uint64_t a5 = *lfi_regs_sysarg(&proc->regs, 5);

    assert(proc->lfi->opts.syshandler);

    uint64_t ret = proc->lfi->opts.syshandler(proc->ctxp, sysno, a0, a1, a2, a3, a4, a5);

    *lfi_regs_sysret(&proc->regs) = ret;
}

void*
lfi_proc_mmap(LFIProc* proc, uintptr_t addr, size_t size, int prot, int flags, int fd, off_t offset)
{
    assert(addr >= proc->base && addr < proc->base + proc->size);
    assert(addr % proc->lfi->opts.pagesize == 0);
    assert(size % proc->lfi->opts.pagesize == 0);
    return mmapverify((void*) addr, size, prot, flags | MAP_FIXED, fd, offset, proc->lfi->opts.verifier);
}

int
lfi_proc_mprotect(LFIProc* proc, uintptr_t addr, size_t size, int prot)
{
    assert(addr >= proc->base && addr < proc->base + proc->size);
    return mprotectverify((void*) addr, size, prot, proc->lfi->opts.verifier);
}

int
lfi_proc_munmap(LFIProc* proc, uintptr_t addr, size_t size)
{
    assert(addr >= proc->base && addr < proc->base + proc->size);
    void* p = mmap((void*) addr, size, PROT_NONE, MAPANON, -1, 0);
    if (p == (void*) -1)
        return -1;
    return 0;
}

void
lfi_proc_free(LFIProc* p)
{
    procclear(p);
    free(p);
}
