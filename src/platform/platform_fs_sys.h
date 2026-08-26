/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_FS_SYS_H__
#define __PLATFORM_FS_SYS_H__

/*
 * tdb_preallocate_extent
 * extends the logical file size and reserves on-disk blocks for the new region
 * ahead of writes, so that subsequent pwrites within the preallocated extent do
 * not take the kernel's "write extends file" fast path. on Linux ext4 this
 * avoids the per-inode i_rwsem write lock; equivalent locks exist on macOS APFS
 * (vnode write lock) and Windows NTFS (file-extension lock).
 *
 * critical detail the logical EOF (i_size) must advance, not just the on-disk
 * extent allocation. on Linux, fallocate(KEEP_SIZE) reserves blocks but leaves
 * i_size unchanged, and the kernel still treats writes past i_size as extending
 * writes -- delivering no speedup. mode 0 advances i_size, which is what removes
 * the extending-write path.
 *
 * what this does not do on ext4 is initialize the extents. mode 0 leaves them
 * marked unwritten, which is why it is fast, and the first write into one still
 * converts it -- a journalled metadata operation. preallocation therefore trades
 * an inode-size journal entry for an extent-conversion one rather than removing
 * journalling from the write path. a caller that needs writes free of metadata
 * work has to write the region through, not preallocate it.
 *
 * the trailing region is zero-filled. the caller must ftruncate back to the
 * actual data extent on clean close so next-open validation isn't confused by
 * trailing zeros. crash recovery should tolerate trailing zeros as preallocation
 * tail (size_field == 0 marks the boundary between data and preallocated region).
 *
 * platform behavior:
 *   linux           fallocate(fd, 0, off, len) -- advances i_size, initializes extents
 *   macos           fcntl(F_PREALLOCATE) reserves, then ftruncate advances logical EOF
 *   windows         SetFileInformationByHandle(FileAllocationInfo) reserves, then
 *                   FileEndOfFileInfo advances EOF
 *   other posix     posix_fallocate -- already advances EOF
 *   fallback        returns -1, caller falls back to extending writes
 *
 * @param fd the file descriptor
 * @param offset start of the region to preallocate (typically current EOF)
 * @param len    number of bytes to preallocate
 * @return 0 on success, -1 on failure (non-fatal -- caller can continue)
 */
static inline int tdb_preallocate_extent(int fd, off_t offset, off_t len)
{
#if defined(__linux__)
    return fallocate(fd, 0, offset, len);
#elif defined(__APPLE__)
    /* reserve blocks past current EOF (offset param is implicit on macOS) */
    (void)offset;
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG | F_ALLOCATEALL;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = len;
    fst.fst_bytesalloc = 0;
    if (fcntl(fd, F_PREALLOCATE, &fst) == -1)
    {
        /* contiguous request failed, retry allowing fragmentation */
        fst.fst_flags = F_ALLOCATEALL;
        if (fcntl(fd, F_PREALLOCATE, &fst) == -1) return -1;
    }
    /* advance logical EOF so writes within the new region don't take the
     * extending-write lock */
    return ftruncate(fd, offset + len);
#elif defined(_WIN32)
    HANDLE h = (HANDLE)_get_osfhandle(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    FILE_ALLOCATION_INFO fai;
    fai.AllocationSize.QuadPart = (LONGLONG)(offset + len);
    if (!SetFileInformationByHandle(h, FileAllocationInfo, &fai, sizeof(fai))) return -1;
    /* advance logical EOF -- otherwise NTFS still treats writes past EOF as extending */
    FILE_END_OF_FILE_INFO eofi;
    eofi.EndOfFile.QuadPart = (LONGLONG)(offset + len);
    return SetFileInformationByHandle(h, FileEndOfFileInfo, &eofi, sizeof(eofi)) ? 0 : -1;
/* the build probes for posix_fallocate and defines TIDESDB_HAVE_POSIX_FALLOCATE when it exists. the
 * platform list behind it keeps a build that does not run that probe from silently losing
 * preallocation, and names only systems that ship the call -- openbsd does not, and falls through
 */
#elif defined(TIDESDB_HAVE_POSIX_FALLOCATE) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__) || defined(__sun)
    /* posix_fallocate reports its failure as the return code and leaves errno alone */
    const int rc = posix_fallocate(fd, offset, len);
    return rc == 0 ? 0 : -1;
#else
    (void)fd;
    (void)offset;
    (void)len;
    return -1;
#endif
}

/*
 * set_file_sequential_hint
 * hints to the OS that file access will be sequential for read-ahead optimization
 * @param fd the file descriptor
 * @return 0 on success, -1 on failure (non-critical, can be ignored)
 */
static inline int set_file_sequential_hint(int fd)
{
#ifdef __linux__
    return posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#elif defined(__APPLE__)
    return fcntl(fd, F_RDAHEAD, 1);
#elif defined(_WIN32)
    /* _O_SEQUENTIAL flag set at open time via compat.h wrapper */
    (void)fd; /* unused on Windows */
    return 0;
#else
    (void)fd; /* unused on other platforms */
    return 0;
#endif
}

/**
 * tdb_get_available_disk_space
 * get available disk space for a given path
 * @param path the path to check
 * @param available pointer to store available bytes
 * @return 0 on success, -1 on failure
 */
static inline int tdb_get_available_disk_space(const char *path, uint64_t *available)
{
    if (!path || !available) return -1;

#if defined(_WIN32)
    ULARGE_INTEGER free_bytes;
    if (GetDiskFreeSpaceExA(path, &free_bytes, NULL, NULL))
    {
        *available = (uint64_t)free_bytes.QuadPart;
        return 0;
    }
    return -1;
#else
    struct statvfs stat;
    if (statvfs(path, &stat) == 0)
    {
        *available = (uint64_t)stat.f_bavail * (uint64_t)stat.f_frsize;
        return 0;
    }
    return -1;
#endif
}

/* cpu pause for spin-wait loops */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#ifdef _MSC_VER
#include <intrin.h>
#define cpu_pause() _mm_pause()
#else
#define cpu_pause() __builtin_ia32_pause()
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#ifdef _MSC_VER
#include <intrin.h>
#define cpu_pause() __yield()
#else
#define cpu_pause() __asm__ __volatile__("yield" ::: "memory")
#endif
#elif defined(__arm__) || defined(_M_ARM)
#ifdef _MSC_VER
#include <intrin.h>
#define cpu_pause() __yield()
#else
#define cpu_pause() __asm__ __volatile__("yield" ::: "memory")
#endif
#else
#define cpu_pause() ((void)0)
#endif

/* cpu yield for longer waits -- gives up time slice to scheduler */
#ifdef _WIN32
#include <windows.h>
#define cpu_yield() SwitchToThread()
#else
#include <sched.h>
#define cpu_yield() sched_yield()
#endif

/*
 * tdb_hardlink
 * portable hard link creation
 * @param src existing file path
 * @param dst new hard link path
 * @return 0 on success, -1 on failure
 */
static inline int tdb_hardlink(const char *src, const char *dst)
{
    if (!src || !dst) return -1;
#ifdef _WIN32
    return CreateHardLinkA(dst, src, NULL) ? 0 : -1;
#else
    return link(src, dst);
#endif
}

/*
 * tdb_unlink
 * portable file deletion
 * @param path the file path to delete
 * @return 0 on success, -1 on failure
 */
static inline int tdb_unlink(const char *path)
{
    if (!path) return -1;
#ifdef _WIN32
    /* clear read-only attribute that might prevent deletion */
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    return _unlink(path);
#else
    return unlink(path);
#endif
}

/**
 * is_directory_empty
 * checks if a directory is empty (contains only . and ..)
 * @param path the directory path to check
 * @return 1 if empty, 0 if not empty or error
 */
static inline int is_directory_empty(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return 0;

    struct dirent *entry;
    int count = 0;

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        count++;
        break; /* found at least one entry */
    }

    closedir(dir);
    return count == 0;
}

/* the deepest nesting a removal walks. a database directory is two levels -- the root and one
 * directory per column family -- so this is far past any layout the engine produces, and bounding
 * it is what keeps the walk iterative with a fixed amount of state */
#define TDB_REMOVE_DIR_MAX_DEPTH 32

/* the removal path buffer; a component that would not fit is left in place and reported rather than
 * truncated into a path naming something else */
#define TDB_REMOVE_DIR_PATH_MAX 4096

/**
 * remove_directory_once
 * single pass of directory removal, depth first so a directory is removed only once it is empty.
 * the walk is iterative over an explicit stack rather than recursive, both because the code rules
 * exclude recursion and because a recursive walk's depth is whatever the filesystem holds -- one
 * open descriptor and one stack frame per level, neither of them bounded by anything this process
 * controls
 * @param path the directory path to remove
 * @return 0 on success, -1 if any entry, or the directory itself, could not be removed
 */
static inline int remove_directory_once(const char *path)
{
    char buf[TDB_REMOVE_DIR_PATH_MAX];
    DIR *dirs[TDB_REMOVE_DIR_MAX_DEPTH];
    size_t lens[TDB_REMOVE_DIR_MAX_DEPTH];

    const size_t root_len = strlen(path);
    if (root_len >= sizeof(buf)) return -1;
    memcpy(buf, path, root_len + 1);

    dirs[0] = opendir(buf);
    if (!dirs[0]) return -1;
    lens[0] = root_len;

    int depth = 0;
    int result = 0;

    /* every iteration either consumes one directory entry or pops a level, and both the entry count
     * and the depth are finite, so the walk terminates */
    while (depth >= 0)
    {
        const struct dirent *entry = readdir(dirs[depth]);
        if (!entry)
        {
            /* the level is exhausted, so its directory is now empty and can go */
            closedir(dirs[depth]);
            buf[lens[depth]] = '\0';
#ifdef _WIN32
            if (_rmdir(buf) != 0) result = -1;
#else
            if (rmdir(buf) != 0) result = -1;
#endif
            depth--;
            if (depth >= 0) buf[lens[depth]] = '\0';
            continue;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        const size_t base = lens[depth];
        const int n =
            snprintf(buf + base, sizeof(buf) - base, "%s%s", PATH_SEPARATOR, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(buf) - base)
        {
            buf[base] = '\0';
            result = -1;
            continue;
        }

        struct STAT_STRUCT st;
        if (STAT_FUNC(buf, &st) != 0)
        {
            buf[base] = '\0';
            continue;
        }

        if (S_ISDIR(st.st_mode))
        {
            if (depth + 1 >= TDB_REMOVE_DIR_MAX_DEPTH)
            {
                /* deeper than the walk carries state for; the tree is left rather than partly
                 * removed, and the caller is told the removal did not complete */
                buf[base] = '\0';
                result = -1;
                continue;
            }
            DIR *sub = opendir(buf);
            if (!sub)
            {
                buf[base] = '\0';
                result = -1;
                continue;
            }
            depth++;
            dirs[depth] = sub;
            lens[depth] = base + (size_t)n;
            continue;
        }

#ifdef _WIN32
        /* clear read-only and other attributes that might prevent deletion */
        SetFileAttributesA(buf, FILE_ATTRIBUTE_NORMAL);
        if (_unlink(buf) != 0) result = -1;
#else
        if (unlink(buf) != 0) result = -1;
#endif
        buf[base] = '\0';
    }

    return result;
}

/* a removal retries this many times, pausing this long between attempts. the retry is for windows,
 * where a file another handle still has open cannot be unlinked and the directory stays non-empty
 * until that handle closes; on posix the first pass succeeds and the loop exits immediately */
#define TDB_REMOVE_DIR_MAX_ATTEMPTS 16
#define TDB_REMOVE_DIR_RETRY_MS     128

/**
 * remove_directory
 * removes a directory and all its contents, retrying while entries remain
 * @param path the directory path to remove
 * @return 0 on success, including when the directory was already gone, -1 if it survived every
 *         attempt
 */
static inline int remove_directory(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return 0; /* already gone, success */
    closedir(dir);

    for (int attempt = 0; attempt < TDB_REMOVE_DIR_MAX_ATTEMPTS; attempt++)
    {
        /* attempt removal */
        (void)remove_directory_once(path);

        /* check if directory is gone or empty */
        dir = opendir(path);
        if (!dir)
        {
            /* directory successfully removed */
            return 0;
        }

        /* directory still exists, check if empty */
        if (is_directory_empty(path))
        {
            closedir(dir);
            /* empty but not removed, try rmdir directly */
#ifdef _WIN32
            if (_rmdir(path) == 0) return 0;
#else
            if (rmdir(path) == 0) return 0;
#endif
        }
        else
        {
            closedir(dir);
        }

        /* directory not empty or removal failed, wait and retry */
        if (attempt < TDB_REMOVE_DIR_MAX_ATTEMPTS - 1)
        {
#ifdef _WIN32
            Sleep(TDB_REMOVE_DIR_RETRY_MS);
#else
            usleep(TDB_REMOVE_DIR_RETRY_MS * 1000);
#endif
        }
    }

    dir = opendir(path);
    if (!dir) return 0; /* success */
    closedir(dir);
    return -1; /* failed after all retries */
}

/**
 * tdb_sync_directory
 * syncs a directory to ensure directory entries (new files/subdirs) are persisted
 * on POSIX systems, directory entries must be explicitly synced after mkdir/file creation
 * on Windows, directory entries are immediately durable, so this is a no-op
 * @param dir_path path to the directory to sync
 * @return 0 on success, -1 on error (errors are non-fatal, just logged)
 */
static inline int tdb_sync_directory(const char *dir_path)
{
#ifdef _WIN32
    /* Windows -- directory entries are immediately durable, no sync needed */
    (void)dir_path;
    return 0;
#else
    /* POSIX -- must fsync directory to persist directory entries */
    const int fd = open(dir_path, O_RDONLY);
    if (fd < 0)
    {
        /* non-fatal -- directory might not support fsync (e.g., some network filesystems) */
        return -1;
    }
    const int result = fsync(fd);
    close(fd);
    return result;
#endif
}

/*
 * tdb_fsync_parent_dir
 * fsync the parent directory of path so a rename's directory entry is durable on a crash. the
 * directory portion is copied into a heap buffer when it does not fit the stack one, so a very long
 * path flushes rather than silently skipping the fsync (a fixed stack buffer with a length guard
 * used to drop the flush for paths longer than the buffer). best-effort -- a directory that cannot
 * be opened or an allocation failure just skips the flush, which is the pre-existing behavior for
 * an unfsyncable directory.
 * @param path a file path whose parent directory should be flushed
 */
static inline void tdb_fsync_parent_dir(const char *path)
{
    const char *last_sep = strrchr(path, '/');
#ifdef _WIN32
    const char *last_bsep = strrchr(path, '\\');
    if (last_bsep && (!last_sep || last_bsep > last_sep)) last_sep = last_bsep;
#endif
    if (!last_sep) return;

    const size_t dir_len = (size_t)(last_sep - path);
    char stack_buf[4096];
    char *dir_path = stack_buf;
    char *heap_buf = NULL;
    if (dir_len >= sizeof(stack_buf))
    {
        heap_buf = (char *)malloc(dir_len + 1);
        if (!heap_buf) return;
        dir_path = heap_buf;
    }
    memcpy(dir_path, path, dir_len);
    dir_path[dir_len] = '\0';

#ifdef _WIN32
    HANDLE dir_handle = CreateFile(dir_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dir_handle != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(dir_handle);
        CloseHandle(dir_handle);
    }
#else
    const int dir_fd = open(dir_path, O_RDONLY);
    if (dir_fd >= 0)
    {
        fsync(dir_fd);
        close(dir_fd);
    }
#endif
    free(heap_buf);
}

/**
 * atomic_rename_file
 * atomically renames a file from old_path to new_path
 * on POSIX systems, rename() is atomic and replaces existing files
 * on windows rename() fails if the target exists, so it is removed first
 * @param old_path the current path of the file
 * @param new_path the new path for the file
 * @return 0 on success, -1 on failure
 */
static inline int atomic_rename_file(const char *old_path, const char *new_path)
{
    if (!old_path || !new_path) return -1;

#ifdef _WIN32
    /* MoveFileEx with MOVEFILE_REPLACE_EXISTING for atomic rename on Windows
     * this is truly atomic and replaces the target file if it exists */
    if (!MoveFileEx(old_path, new_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        errno = GetLastError();
        return -1;
    }

    /* flush parent directory to ensure rename is durable */
    tdb_fsync_parent_dir(new_path);

    return 0;
#else
    /* POSIX rename() is atomic and replaces existing files */
    if (rename(old_path, new_path) != 0)
    {
        return -1;
    }

    /* sync the parent directory so the rename metadata is durable
     * this is critical for crash safety on non-journaling filesystems
     * https://groups.google.com/g/comp.unix.programmer/c/AM2V83RCOVE?pli=1
     * https://man7.org/linux/man-pages/man2/rename.2.html
     */
    tdb_fsync_parent_dir(new_path);

    return 0;
#endif
}

/**
 * atomic_rename_dir
 * renames a directory from old_path to new_path
 * on POSIX systems, rename() works for directories
 * on windows rename() fails if the target exists, so this uses MoveFileEx
 * this does not replace an existing directory, so the caller must ensure the target is absent
 * @param old_path the current path of the directory
 * @param new_path the new path for the directory
 * @return 0 on success, -1 on failure
 */
static inline int atomic_rename_dir(const char *old_path, const char *new_path)
{
    if (!old_path || !new_path) return -1;

#ifdef _WIN32
    /* MoveFileEx works for directories on Windows. MOVEFILE_REPLACE_EXISTING does not work for
     * non-empty directories, so it is not used here and the caller must ensure the target does not
     * exist */
    if (!MoveFileEx(old_path, new_path, MOVEFILE_WRITE_THROUGH))
    {
        errno = GetLastError();
        return -1;
    }

    return 0;
#else
    /* POSIX rename() works for directories */
    if (rename(old_path, new_path) != 0)
    {
        return -1;
    }

    /* sync parent directory for durability */
    tdb_fsync_parent_dir(new_path);

    return 0;
#endif
}

/**
 * tdb_get_cpu_count
 * gets the number of available CPU cores
 * @return number of CPU cores, or 4 as fallback
 */
static inline int tdb_get_cpu_count(void)
{
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return (int)sysinfo.dwNumberOfProcessors;
#elif defined(__APPLE__)
    int count;
    size_t count_len = sizeof(count);
    if (sysctlbyname("hw.logicalcpu", &count, &count_len, NULL, 0) == 0)
    {
        return count;
    }
    return 4; /* fallback */
#else
    /* POSIX systems (Linux, BSD, etc.) */
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count > 0)
    {
        return (int)count;
    }
    return 4; /* fallback */
#endif
}

/**
 * tdb_get_cpu_id
 * gets the current CPU core ID the calling thread is running on
 * used for NUMA-aware partition routing
 * @return current CPU ID, or 0 as fallback
 */
static inline int tdb_get_cpu_id(void)
{
#if defined(__linux__) && (defined(__GLIBC__) || defined(__GNU_LIBRARY__))
    /* sched_getcpu() is a fast vDSO call (~5ns) on modern Linux, declared by <sched.h> under
     * _GNU_SOURCE which the build defines; re-declaring it here would shadow that one */
    const int cpu = sched_getcpu();
    return cpu >= 0 ? cpu : 0;
#elif defined(_WIN32)
    return (int)GetCurrentProcessorNumber();
#else
    return 0; /* fallback -- no CPU detection */
#endif
}

/*
 * tdb_get_current_time
 * cross-platform function to get current Unix timestamp in seconds
 * @return current Unix timestamp in seconds
 */
static inline time_t tdb_get_current_time(void)
{
#if defined(_WIN32)
    SYSTEMTIME st;
    FILETIME ft;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER ui;
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    return (time_t)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);
#else
    return time(NULL);
#endif
}

/**
 * tdb_gmtime_r
 * cross-platform thread-safe gmtime
 * @param timep pointer to time_t value
 * @param result pointer to struct tm to fill
 * @return pointer to result on success, NULL on failure
 */
static inline struct tm *tdb_gmtime_r(const time_t *timep, struct tm *result)
{
#if defined(_WIN32)
    return (gmtime_s(result, timep) == 0) ? result : NULL;
#else
    return gmtime_r(timep, result);
#endif
}

/**
 * tdb_fmemopen
 * cross-platform fmemopen
 * opens a memory buffer as a FILE stream for reading
 * @param buf pointer to memory buffer
 * @param size size of buffer in bytes
 * @param mode fopen mode string (e.g. "rb")
 * @return FILE pointer or NULL on failure
 */
static inline FILE *tdb_fmemopen(void *buf, size_t size, const char *mode)
{
#if defined(_WIN32)
    /* windows has no fmemopen, so this writes to a temp file and reopens */
    (void)mode;
    char temp_path[MAX_PATH];
    char temp_file[MAX_PATH];
    if (GetTempPathA(MAX_PATH, temp_path) == 0) return NULL;
    if (GetTempFileNameA(temp_path, "tdb", 0, temp_file) == 0) return NULL;

    FILE *fp = fopen(temp_file, "wb");
    if (!fp) return NULL;

    if (size > 0 && buf)
    {
        if (fwrite(buf, 1, size, fp) != size)
        {
            fclose(fp);
            DeleteFileA(temp_file);
            return NULL;
        }
    }
    fclose(fp);

    fp = fopen(temp_file, "rb");
    DeleteFileA(temp_file); /* the file stays open until fclose */
    return fp;
#else
    return fmemopen(buf, size, mode);
#endif
}

#ifndef _WIN32
#include <sys/resource.h> /* getrlimit / RLIMIT_NOFILE, getrusage for the resource shims below */
#endif

/**
 * tdb_process_rss
 * this process's resident set size in bytes, or 0 when the platform has no supported source, so a
 * caller such as a benchmark's resource sampler can plot memory over a run
 * @return the resident bytes, or 0 when unavailable
 */
static inline uint64_t tdb_process_rss(void)
{
#if defined(_WIN32)
    /* querying working-set size needs psapi, an extra link dependency, so the process rss is left
     * unsampled on windows rather than forcing that link on every consumer */
    return 0;
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) ==
        KERN_SUCCESS)
        return (uint64_t)info.resident_size;
    return 0;
#else
    /* linux and other proc-fs systems expose the resident page count in /proc/self/statm */
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return 0;
    unsigned long size_pages = 0, rss_pages = 0;
    const int n = fscanf(f, "%lu %lu", &size_pages, &rss_pages);
    fclose(f);
    if (n != 2) return 0;
    return (uint64_t)rss_pages * (uint64_t)sysconf(_SC_PAGESIZE);
#endif
}

/**
 * tdb_process_cpu_seconds
 * cumulative process cpu time (user plus system) in seconds, or 0 when unavailable; a sampler
 * differences successive readings against wall time to derive a cpu-utilization percentage
 * @return the cpu seconds, or 0 when unavailable
 */
static inline double tdb_process_cpu_seconds(void)
{
#if defined(_WIN32)
    FILETIME creation, exit_time, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit_time, &kernel, &user)) return 0.0;
    ULARGE_INTEGER k, u;
    k.LowPart = kernel.dwLowDateTime;
    k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime;
    u.HighPart = user.dwHighDateTime;
    return (double)(k.QuadPart + u.QuadPart) * 1e-7; /* 100-nanosecond ticks to seconds */
#else
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) != 0) return 0.0;
    return (double)ru.ru_utime.tv_sec + (double)ru.ru_utime.tv_usec * 1e-6 +
           (double)ru.ru_stime.tv_sec + (double)ru.ru_stime.tv_usec * 1e-6;
#endif
}

/* fallback open-file ceilings used when the OS limit cannot be queried */
#define TDB_FALLBACK_MAX_OPEN_FILES_POSIX 1024 /* POSIX-typical default RLIMIT_NOFILE soft cap */
#define TDB_FALLBACK_MAX_OPEN_FILES_WIN \
    2048 /* conservative floor for the Windows CRT low-IO layer */

/**
 * tdb_max_open_files
 * report the process's maximum number of simultaneously open file descriptors, so callers can
 * size their fd budgets (e.g. max_open_sstables) to fit the OS limit. returns a conservative
 * fallback when the limit cannot be determined or is unlimited.
 * @return the open-file ceiling as a long
 */
static inline long tdb_max_open_files(void)
{
#if defined(_WIN32)
    /* windows has no RLIMIT_NOFILE. the CRT low-IO layer permits a large but not directly
     * queryable number of _open handles; _getmaxstdio reports the (smaller) stdio stream cap.
     * use the larger of that and a conservative floor so it neither over- nor under-budgets. */
    const int stdio_cap = _getmaxstdio();
    const long win_floor = TDB_FALLBACK_MAX_OPEN_FILES_WIN;
    return (stdio_cap > win_floor) ? (long)stdio_cap : win_floor;
#else
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur > 0)
        return (long)rl.rlim_cur;
    return TDB_FALLBACK_MAX_OPEN_FILES_POSIX;
#endif
}

/**
 * tdb_max_open_files_exact
 * the process open-file ceiling when it is genuinely known and finite, for a caller that lowers a
 * budget to fit it. reports 0 rather than a guess when there is no real ceiling to fit -- an
 * unlimited soft limit, a limit that could not be read, or Windows, whose low-IO layer permits a
 * large but not directly queryable number of handles. a budget may only be cut against a ceiling
 * that is real, so tdb_max_open_files's conservative fallback is the wrong figure here: cutting to
 * a guessed 1024 would penalise exactly the process that had no limit at all
 * @return the ceiling, or 0 when there is none to fit
 */
static inline long tdb_max_open_files_exact(void)
{
#if defined(_WIN32)
    return 0;
#else
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur > 0)
        return (long)rl.rlim_cur;
    return 0;
#endif
}

/**
 * tdb_raise_max_open_files
 * raise this process's open-file ceiling toward `desired` descriptors and return the ceiling in
 * effect afterwards. POSIX raises the RLIMIT_NOFILE soft limit toward the hard limit (never
 * lowering it, clamped to the hard limit); Windows raises the CRT stdio cap via _setmaxstdio
 * (clamped to its 8192 maximum). an explicit, opt-in action -- tidesdb never raises the limit on
 * its own. a partial or failed raise is non-fatal-- the prior ceiling simply stands.
 * @param desired target descriptor count; <= 0 just reports the current ceiling without raising
 * @return the open-file ceiling after the attempt
 */
static inline long tdb_raise_max_open_files(long desired)
{
    if (desired <= 0) return tdb_max_open_files();
#if defined(_WIN32)
    if (desired > 8192) desired = 8192; /* _setmaxstdio hard maximum */
    if (desired > _getmaxstdio()) _setmaxstdio((int)desired);
#else
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0)
    {
        rlim_t target = (rlim_t)desired;
        if (rl.rlim_max != RLIM_INFINITY && target > rl.rlim_max) target = rl.rlim_max;
        /* macOS (and some BSDs) reject a soft limit above a kernel per-process cap even when the
         * hard limit reads higher/unlimited, so back off and retry rather than giving up -- this
         * lands the soft limit near the real ceiling instead of leaving it at the low default. */
        const rlim_t floor = rl.rlim_cur;
        while (target > rl.rlim_cur)
        {
            struct rlimit attempt = rl;
            attempt.rlim_cur = target;
            if (setrlimit(RLIMIT_NOFILE, &attempt) == 0)
            {
                rl.rlim_cur = target;
                break;
            }
            if (target <= floor + 1) break; /* even the smallest raise was refused */
            target = floor + (target - floor) / 2;
        }
    }
#endif
    return tdb_max_open_files();
}

/**
 * tdb_addressable_memory_limit
 * report the largest span of memory this process could address, so callers can keep a budget
 * derived from physical RAM from exceeding the virtual address space. on a 64-bit process the
 * space dwarfs physical RAM and this never constrains anything; on an ILP32 process the whole
 * space is at most 4 GiB, and less after the kernel split, code, thread stacks and any sanitizer
 * shadow, so an unclamped budget can arm a memory-pressure valve above the ceiling that never
 * fires before allocation fails. returns the smaller of the pointer-width ceiling and, when it is
 * finite, the process address-space rlimit (on Windows, the top of the user-mode address range).
 * @return the address-space ceiling in bytes
 */
static inline size_t tdb_addressable_memory_limit(void)
{
    size_t ceiling = SIZE_MAX; /* pointer-width max, which is 4 GiB on an ILP32 process */
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    /* lpMaximumApplicationAddress is the highest user-mode address; its magnitude is the size of
     * the usable range (2 GiB on Win32, 3 GiB with /LARGEADDRESSAWARE, ~128 TiB on Win64) */
    const uintptr_t hi = (uintptr_t)si.lpMaximumApplicationAddress;
    if (hi > 0 && (size_t)hi < ceiling) ceiling = (size_t)hi;
#elif defined(RLIMIT_AS)
    /* RLIMIT_AS caps the process virtual size on most unices; openbsd and a few others omit it,
     * where the pointer-width ceiling above already bounds what the process can map */
    struct rlimit rl;
    if (getrlimit(RLIMIT_AS, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur > 0 &&
        (size_t)rl.rlim_cur < ceiling)
        ceiling = (size_t)rl.rlim_cur;
#endif
    return ceiling;
}

#endif /* __PLATFORM_FS_SYS_H__ */
