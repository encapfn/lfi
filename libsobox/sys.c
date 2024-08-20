// for mremap
#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdalign.h>
#include <sys/mman.h>

#include "sys.h"
#include "proc.h"

#include "stub/stub.h"

enum {
    SYS_ioctl           = 16,
    SYS_archprctl       = 158,
    SYS_fcntl           = 72,
    SYS_openat          = 257,
    SYS_mmap            = 9,
    SYS_munmap          = 11,
    SYS_mremap          = 25,
    SYS_mprotect        = 10,
    SYS_set_tid_address = 218,
    SYS_brk             = 12,
    SYS_read            = 0,
    SYS_write           = 1,
    SYS_readv           = 19,
    SYS_writev          = 20,
};

enum {
    ARCH_SET_FS = 0x1002,
};

static uintptr_t
truncp(uintptr_t addr, size_t align)
{
    size_t align_mask = align - 1;
    return addr & ~align_mask;
}

static bool
procinbrk(SoboxProc* p, uintptr_t addr, size_t size)
{
    return addr >= p->brkbase && size < p->brksize;
}

static uint8_t*
procbufalign(SoboxProc* p, uintptr_t buf, size_t size, size_t align)
{
    buf = procaddr(p, buf);
    if (buf % align != 0)
        return NULL;
    if (size >= PROCSIZE || buf + size >= p->base + PROCSIZE)
        return NULL;
    return (uint8_t*) buf;
}

static uint8_t*
procbuf(SoboxProc* p, uintptr_t buf, size_t size)
{
    buf = procaddr(p, buf);
    if (size >= PROCSIZE || buf + size >= p->base + PROCSIZE)
        return NULL;
    return (uint8_t*) buf;
}

static int
sysarchprctl(SoboxProc* p, int code, uintptr_t addr)
{
    switch (code) {
    case ARCH_SET_FS:
        addr = procaddr(p, addr);
        lfi_proc_get_regs(p->proc)->fs = addr;
        return 0;
    default:
        return -EINVAL;
    }
}

static uintptr_t
sysbrk(SoboxProc* p, uintptr_t addr)
{
    uintptr_t brkp = p->brkbase + p->brksize;
    if (addr != 0)
        brkp = procaddr(p, addr);
    if (brkp < p->brkbase)
        brkp = p->brkbase;
    if (brkp >= p->brkbase + BRKMAXSIZE)
        brkp = p->brkbase + BRKMAXSIZE;

    size_t newsize = brkp - p->brkbase;
    assert(newsize <= BRKMAXSIZE);

    if (newsize == p->brksize)
        return procuseraddr(p, brkp);

    const int mapflags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
    const int mapprot = PROT_READ | PROT_WRITE;

    if (brkp >= p->brkbase + p->brksize) {
        void* map;
        if (p->brksize == 0) {
            map = mmap((void*) p->brkbase, newsize, mapprot, mapflags, -1, 0);
        } else {
            // Since liblfi reserves all sandboxes in one big mmap region, we
            // first need to unmap the piece that we want to expand into,
            // otherwise Linux will decide there is no space for mremap.
            int r = munmap((void*) p->brkbase + p->brksize, newsize - p->brksize);
            assert(r == 0);
            map = mremap((void*) p->brkbase, p->brksize, newsize, 0);
        }
        if (map == (void*) -1)
            return -1;
    }
    p->brksize = newsize;
    return procuseraddr(p, p->brkbase + p->brksize);
}

static uintptr_t
sysmmap(SoboxProc* p, uintptr_t addrp, size_t length, int prot, int flags, int fd, off_t offset)
{
    if (length == 0)
        return -EINVAL;
    if ((prot & PROT_EXEC) != 0)
        return -EPERM;

    fprintf(stderr, "sysmmap(%lx, %ld, %d, %d, %d, %ld)\n", addrp, length, prot, flags, fd, offset);

    // The flags listed are the only allowed flags.
    const int illegal_mask = ~MAP_ANONYMOUS &
        ~MAP_PRIVATE &
        ~MAP_HUGETLB &
        ~MAP_FIXED &
        ~MAP_NORESERVE &
        ~MAP_DENYWRITE;
    if ((flags & illegal_mask) != 0)
        return -EPERM;

    int r;
    if (addrp == 0) {
        // Runtime can pick any location.
        r = procmapany(p, length, prot, flags, fd, offset, &addrp);
    } else {
        addrp = truncp(addrp, getpagesize());
        if (addrp != procaddr(p, addrp))
            return -EINVAL;
        addrp = procaddr(p, addrp);

        if (procinbrk(p, addrp, length))
            return procuseraddr(p, addrp);
        r = procmapat(p, addrp, length, prot, flags, fd, offset);
    }
    if (r < 0)
        return r;
    return procuseraddr(p, addrp);
}

static int
sysmprotect(SoboxProc* p, uintptr_t addrp, size_t length, int prot)
{
    addrp = procaddr(p, addrp);
    // TODO:
    /* int r = mm_protect(&p->mm, procaddr(p, addrp), length, prot); */
    /* if (r < 0) */
    /*     return r; */
    // We are relying on Linux mmap behavior being the same as mm_protect with
    // respect to addrp and length, since we have not truncated/page-aligned
    // them here.
    return lfi_mprotect(p->proc, addrp, length, prot);
}
 
static ssize_t
sysread(SoboxProc* p, int fd, uintptr_t bufp, size_t size)
{
    if (size == 0)
        return 0;
    FDFile* f = fdget(&p->fdtable, fd);
    if (!f)
        return -EBADF;
    if (!f->read)
        return -EPERM;
    uint8_t* buf = procbuf(p, bufp, size);
    if (!buf)
        return -EFAULT;
    return f->read(f->dev, p, buf, size);
}

static ssize_t
syswrite(SoboxProc* p, int fd, uintptr_t bufp, size_t size)
{
    if (size == 0)
        return 0;
    FDFile* f = fdget(&p->fdtable, fd);
    if (!f)
        return -EBADF;
    if (!f->write)
        return -EPERM;
    uint8_t* buf = procbuf(p, bufp, size);
    if (!buf)
        return -EFAULT;
    return f->write(f->dev, p, buf, size);
}

typedef struct {
    uintptr_t base;
    size_t len;
} Iovec;

static ssize_t
sysreadv(SoboxProc* p, int fd, uintptr_t iovp, size_t iovcnt)
{
    uint8_t* iovb = procbufalign(p, iovp, iovcnt * sizeof(Iovec), alignof(Iovec));
    if (!iovb)
        return -EFAULT;
    Iovec* iov = (Iovec*) iovb;
    ssize_t total = 0;

    for (size_t i = 0; i < iovcnt; i++) {
        ssize_t n = sysread(p, fd, iov[i].base, iov[i].len);
        if (n < 0) {
            return n;
        }
        total += n;
    }

    return total;
}

static ssize_t
syswritev(SoboxProc* p, int fd, uintptr_t iovp, ssize_t iovcnt)
{
    uint8_t* iovb = procbufalign(p, iovp, iovcnt * sizeof(Iovec), alignof(Iovec));
    if (!iovb)
        return -EFAULT;
    Iovec* iov = (Iovec*) iovb;
    ssize_t total = 0;

    for (int i = 0; i < iovcnt; i++) {
        ssize_t n = syswrite(p, fd, iov[i].base, iov[i].len);
        if (n < 0) {
            return n;
        }
        total += n;
    }

    return total;
}

static int
syssbxdl(SoboxProc* p, uintptr_t fns)
{
    // Must be aligned correctly.
    if (fns % alignof(SoboxFns) != 0)
        return -EINVAL;
    p->fns = (SoboxFns*) procaddr(p, fns);
    lfi_proc_exit(p->proc, 0);
    assert(!"unreachable");
}

static uintptr_t
syssbxdlret(SoboxProc* p, uintptr_t val)
{
    lfi_proc_return(p->proc, val);
    assert(!"unreachable");
}

uint64_t
syshandler(void* ctxp, uint64_t sysno,
        uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    SoboxProc* p = (SoboxProc*) ctxp;
    uint64_t ret;
    switch (sysno) {
    case SYS_archprctl:
        ret = sysarchprctl(p, a0, a1);
        break;
    case SYS_brk:
        ret = sysbrk(p, a0);
        break;
    case SYS_mmap:
        ret = sysmmap(p, a0, a1, a2, a3, a4, a5);
        break;
    case SYS_mprotect:
        ret = sysmprotect(p, a0, a1, a2);
        break;
    case SYS_read:
        ret = sysread(p, a0, a1, a2);
        break;
    case SYS_write:
        ret = syswrite(p, a0, a1, a2);
        break;
    case SYS_readv:
        ret = sysreadv(p, a0, a1, a2);
        break;
    case SYS_writev:
        ret = syswritev(p, a0, a1, a2);
        break;
    case SYS_SBX_dl:
        ret = syssbxdl(p, a0);
        break;
    case SYS_SBX_dlret:
        ret = syssbxdlret(p, a0);
        break;
    case SYS_set_tid_address:
    case SYS_ioctl:
        ret = 0;
        break;
    default:
        printf("unknown syscall: %ld\n", sysno);
        assert(!"NOSYS");
        return -ENOSYS;
    }
    /* fprintf(stderr, "syscall: %ld = %lx\n", sysno, ret); */
    return ret;
}

int
syserr(int val)
{
    if (val == -1)
        return -errno;
    return val;
}
