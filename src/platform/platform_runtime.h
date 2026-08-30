/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_RUNTIME_H__
#define __PLATFORM_RUNTIME_H__

/* cross-platform thread naming
 * Linux                -- prctl(PR_SET_NAME)               -- 16 char limit including null
 * macOS                -- pthread_setname_np(name)         -- only current thread, 1 arg
 * FreeBSD/DragonFly    -- pthread_setname_np(thread, name) -- 2 args
 * NetBSD               -- pthread_setname_np(thread, fmt, arg) -- 3 args, printf-style
 * OpenBSD              -- pthread_set_name_np(thread, name)
 * Windows MSVC         -- SetThreadDescription (Win10 1607+)
 * Windows MinGW        -- no-op fallback */
#if defined(__linux__)
#include <sys/prctl.h>
#endif
static inline void tdb_set_thread_name(const char *name)
{
    if (!name) return;
#if defined(__linux__)
    prctl(PR_SET_NAME, (unsigned long)name, 0, 0, 0);
#elif defined(__APPLE__)
    pthread_setname_np(name);
#elif defined(__FreeBSD__) || defined(__DragonFly__)
    pthread_setname_np(pthread_self(), name);
#elif defined(__NetBSD__)
    pthread_setname_np(pthread_self(), "%s", (void *)name);
#elif defined(__OpenBSD__)
    pthread_set_name_np(pthread_self(), name);
#elif defined(_MSC_VER)
    /* SetThreadDescription requires wide string */
    wchar_t wname[64];
    size_t i;
    for (i = 0; i < 63 && name[i]; i++) wname[i] = (wchar_t)name[i];
    wname[i] = L'\0';
    SetThreadDescription(GetCurrentThread(), wname);
#else
    (void)name; /* no-op fallback */
#endif
}

/* O_DSYNC/O_SYNC for synchronous writes (must be after all platform includes)
 * POSIX -- O_DSYNC syncs data only, O_SYNC syncs data + metadata
 * windows -- no direct equivalent at open() time, use fdatasync() per-write
 * some BSDs (DragonFlyBSD, older FreeBSD) may not define O_DSYNC */
#ifndef O_DSYNC
#ifdef _WIN32
#define O_DSYNC 0 /* no O_DSYNC, will use fdatasync() fallback */
#elif defined(__APPLE__)
#define O_DSYNC 0x400000 /* macOS -- O_DSYNC = 0x400000 */
#else
#define O_DSYNC 0 /* fallback for BSDs and others without O_DSYNC */
#endif
#endif

/* cross-platform pwritev for scatter-gather I/O
 * Linux and modern BSDs have native pwritev in <sys/uio.h>
 * macOS added pwritev in 10.16/11.0 (Big Sur)
 * older macOS and Windows fall back to sequential pwrite calls */
#ifdef _WIN32
struct iovec
{
    void *iov_base;
    size_t iov_len;
};
#define TDB_NEED_PWRITEV_FALLBACK 1
#else
#include <sys/uio.h>
/* macOS < 11.0 does not have pwritev. MAC_OS_X_VERSION_10_16 == 101600 == Big Sur.
 * check for the availability macro; if it does not exist, assume the platform is old enough
 * to lack pwritev. */
#if defined(__APPLE__)
#include <AvailabilityMacros.h>
#if !defined(MAC_OS_X_VERSION_10_16) || MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_16
#define TDB_NEED_PWRITEV_FALLBACK 1
#endif
#endif
#endif

#ifdef TDB_NEED_PWRITEV_FALLBACK
/*
 * pwritev
 * scatter-gather write at offset (fallback using sequential pwrite)
 * @param fd the file descriptor
 * @param iov array of iovec buffers
 * @param iovcnt number of iovec entries
 * @param offset the file offset to write at
 * @return total bytes written, or -1 on error
 */
static inline ssize_t tdb_pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++)
    {
        ssize_t n = pwrite(fd, iov[i].iov_base, iov[i].iov_len, offset);
        if (n != (ssize_t)iov[i].iov_len) return (total > 0) ? total : -1;
        total += n;
        offset += n;
    }
    return total;
}
#define pwritev tdb_pwritev
#endif

/**
 * tdb_pwritev_safe
 * wrapper around pwritev that blocks SIGALRM/SIGVTALRM/SIGPROF for the duration
 * of the syscall. prevents EINTR from leaving a zero-filled hole in the file when
 * the atomic offset reservation has already been committed.
 * @param fd the file descriptor
 * @param iov array of iovec buffers
 * @param iovcnt number of iovec entries
 * @param offset the file offset to write at
 * @return total bytes written, or -1 on error
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static ssize_t
tdb_pwritev_safe(int fd, const struct iovec *iov, int iovcnt, off_t offset)
{
#ifndef _WIN32
    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGALRM);
    sigaddset(&block_set, SIGVTALRM);
    sigaddset(&block_set, SIGPROF);
    pthread_sigmask(SIG_BLOCK, &block_set, &old_set);
    const ssize_t written = pwritev(fd, iov, iovcnt, offset);
    pthread_sigmask(SIG_SETMASK, &old_set, NULL);
    return written;
#else
    return pwritev(fd, iov, iovcnt, offset);
#endif
}

/* atomic compare exchange for pointers (all platforms with C11 atomics) */
#if !defined(_MSC_VER) || _MSC_VER >= 1930
/*
 * atomic_compare_exchange_strong_ptr
 * @param ptr pointer to atomic pointer
 * @param expected pointer to expected value
 * @param desired new value to store
 * @return 1 if successful, 0 if failed
 */
static inline int atomic_compare_exchange_strong_ptr(_Atomic(void *) *ptr, void **expected,
                                                     void *desired)
{
    return atomic_compare_exchange_strong(ptr, expected, desired);
}
#endif

/*
 * get_available_memory
 * gets available system memory in bytes
 * @return available memory in bytes, or 0 on failure
 */
/* available physical memory in bytes across the platforms, each backend guarded so exactly
 * one compiles */
#ifdef _WIN32
static inline size_t get_available_memory_impl(void)
{
    MEMORYSTATUSEX status;
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status))
    {
        return (size_t)status.ullAvailPhys;
    }
    return 0;
}
#elif defined(__APPLE__)
static inline size_t get_available_memory_impl(void)
{
    vm_size_t page_size;
    mach_port_t mach_port;
    mach_msg_type_number_t count;

    mach_port = mach_host_self();

    /* 32-bit vm statistics on PPC regardless of OS version.
     * host_statistics64 is not available on 10.5 and for PPC 32-bit even on 10.6 */
#if defined(__ppc__) || (MAC_OS_X_VERSION_MIN_REQUIRED < 1060)
    /* PPC always uses 32-bit vm statistics */
    vm_statistics_data_t vm_stats;
    count = HOST_VM_INFO_COUNT;
    if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
        host_statistics(mach_port, HOST_VM_INFO, (host_info_t)&vm_stats, &count) == KERN_SUCCESS)
    {
        return (size_t)((vm_stats.free_count + vm_stats.inactive_count + vm_stats.purgeable_count) *
                        page_size);
    }
#else
    /* try 64-bit first (macOS 10.6+ on x86/x86_64/ARM), fall back to 32-bit */
    vm_statistics64_data_t vm_stats64;
    count = sizeof(vm_stats64) / sizeof(natural_t);
    if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
        host_statistics64(mach_port, HOST_VM_INFO, (host_info64_t)&vm_stats64, &count) ==
            KERN_SUCCESS)
    {
        return (size_t)((vm_stats64.free_count + vm_stats64.inactive_count +
                         vm_stats64.purgeable_count) *
                        page_size);
    }
    else
    {
        /* fallback to 32-bit for older systems or Rosetta edge cases */
        vm_statistics_data_t vm_stats;
        count = HOST_VM_INFO_COUNT;
        if (host_page_size(mach_port, &page_size) == KERN_SUCCESS &&
            host_statistics(mach_port, HOST_VM_INFO, (host_info_t)&vm_stats, &count) ==
                KERN_SUCCESS)
        {
            return (
                size_t)((vm_stats.free_count + vm_stats.inactive_count + vm_stats.purgeable_count) *
                        page_size);
        }
    }
#endif
    return 0;
}
#elif defined(__linux__)
static inline size_t get_available_memory_impl(void)
{
    /* prefer /proc/meminfo MemAvailable -- the kernel's own estimate of memory
     * available for new allocations without swapping (includes free + reclaimable
     * buffers/cache + reclaimable slab). sysinfo.freeram only reports truly free
     * pages which is typically very low on a busy system and triggers false
     * critical memory pressure */
    {
        FILE *f = fopen("/proc/meminfo", "r");
        if (f)
        {
            char line[256];
            while (fgets(line, sizeof(line), f))
            {
                unsigned long long val;
                if (sscanf(line, "MemAvailable: %llu kB", &val) == 1)
                {
                    fclose(f);
                    return (size_t)(val * 1024ULL);
                }
            }
            fclose(f);
        }
    }
    /* fallback to sysinfo.freeram if /proc/meminfo is unavailable */
    {
        struct sysinfo si;
        if (sysinfo(&si) == 0)
        {
            return (size_t)si.freeram * (size_t)si.mem_unit;
        }
    }
    return 0;
}
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
static inline size_t get_available_memory_impl(void)
{
    /* BSD systems use sysctl.. */
    unsigned long free_pages = 0;
    unsigned long page_size = 0;
    size_t len = sizeof(free_pages);

#if defined(__FreeBSD__) || defined(__DragonFly__)
    if (sysctlbyname("vm.stats.vm.v_free_count", &free_pages, &len, NULL, 0) == 0)
    {
        len = sizeof(page_size);
        if (sysctlbyname("vm.stats.vm.v_page_size", &page_size, &len, NULL, 0) == 0)
        {
            return (size_t)(free_pages * page_size);
        }
    }
#elif defined(__OpenBSD__) || defined(__NetBSD__)
    int mib[2];
    struct uvmexp uvmexp;
    len = sizeof(uvmexp);

    mib[0] = CTL_VM;
    mib[1] = VM_UVMEXP;
    if (sysctl(mib, 2, &uvmexp, &len, NULL, 0) == 0)
    {
        return (size_t)((uint64_t)uvmexp.free * (uint64_t)uvmexp.pagesize);
    }
#endif
    return 0;
}
#else
static inline size_t get_available_memory_impl(void)
{
    /* illumos/solaris and other POSIX systems
     * note -- on 32-bit systems, multiplying pages * page_size can overflow
     * so the multiplication casts to 64-bit first */
    long pages = sysconf(_SC_AVPHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0)
    {
        return (size_t)((uint64_t)pages * (uint64_t)page_size);
    }
    return 0;
}
#endif
#endif /* __PLATFORM_RUNTIME_H__ */
