/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
#ifndef __PLATFORM_WINDOWS_MSVC_H__
#define __PLATFORM_WINDOWS_MSVC_H__

#if defined(_MSC_VER)
#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
};

struct dirent
{
    char d_name[MAX_PATH];
};

typedef struct
{
    HANDLE hFind;
    WIN32_FIND_DATA findFileData;
    struct dirent dirent;
} DIR;

/* mkdir */
/*
 * mkdir
 * @param path the path to create the directory at
 * @param mode the mode to create the directory with (unused on windows)
 * @return 0 on success, -1 on failure
 */
static inline int mkdir(const char *path, mode_t mode)
{
    (void)mode; /* unused on windows */
    return _mkdir(path);
}

/* opendir */
/*
 * opendir
 * @param name the name of the directory to open
 * @return a pointer to the directory stream, or NULL on failure
 */
static inline DIR *opendir(const char *name)
{
    DIR *dir = (DIR *)malloc(sizeof(DIR));
    if (dir == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    char search_path[MAX_PATH];
    snprintf(search_path, MAX_PATH, "%s\\*", name);
    dir->hFind = FindFirstFile(search_path, &dir->findFileData);
    if (dir->hFind == INVALID_HANDLE_VALUE)
    {
        free(dir);
        return NULL;
    }
    return dir;
}

/* readdir */
/*
 * readdir
 * @param dir the directory stream to read from
 * @return a pointer to the next directory entry, or NULL on failure
 */
static inline struct dirent *readdir(DIR *dir)
{
    if (dir == NULL || dir->hFind == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }
    if (dir->findFileData.cFileName[0] == '\0')
    {
        if (!FindNextFile(dir->hFind, &dir->findFileData))
        {
            return NULL;
        }
    }
    /* strncpy leaves the destination unterminated if the source fills all MAX_PATH bytes, so copy
     * at most MAX_PATH-1 and terminate explicitly rather than relying on the source's terminator */
    strncpy(dir->dirent.d_name, dir->findFileData.cFileName, MAX_PATH - 1);
    dir->dirent.d_name[MAX_PATH - 1] = '\0';
    dir->findFileData.cFileName[0] = '\0'; /* reset */
    return &dir->dirent;
}

/* closedir */
/*
 * closedir
 * @param dir the directory stream to close
 * @return 0 on success, -1 on failure
 */
static inline int closedir(DIR *dir)
{
    if (dir == NULL)
    {
        return -1;
    }
    if (dir->hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(dir->hFind);
    }
    free(dir);
    return 0;
}

typedef struct
{
    HANDLE handle;
} sem_t;

/* sem_init */
/*
 * sem_init
 * @param sem the semaphore to initialize
 * @param pshared whether the semaphore is shared between processes (unused on windows)
 * @param value the initial value of the semaphore
 * @return 0 on success, -1 on failure
 */
static inline int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    (void)pshared;
    sem->handle = CreateSemaphore(NULL, value, LONG_MAX, NULL);
    if (sem->handle == NULL)
    {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

/* sem_destroy */
/*
 * sem_destroy
 * @param sem the semaphore to destroy
 * @return 0 on success, -1 on failure
 */
static inline int sem_destroy(sem_t *sem)
{
    if (sem->handle != NULL)
    {
        CloseHandle(sem->handle);
        sem->handle = NULL;
    }
    return 0;
}

/* sem_wait */
/*
 * sem_wait
 * @param sem the semaphore to wait on
 * @return 0 on success, -1 on failure
 */
static inline int sem_wait(sem_t *sem)
{
    DWORD result = WaitForSingleObject(sem->handle, INFINITE);
    return (result == WAIT_OBJECT_0) ? 0 : -1;
}

/* sem_post */
/*
 * sem_post
 * @param sem the semaphore to post
 * @return 0 on success, -1 on failure
 */
static inline int sem_post(sem_t *sem)
{
    return ReleaseSemaphore(sem->handle, 1, NULL) ? 0 : -1;
}

/* file operations macros for cross-platform compatibility */
#ifndef S_ISDIR
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#endif
#define sleep(seconds) Sleep((seconds)*1000)

/* usleep for windows, rounded up so a sub millisecond request still sleeps.
 *
 * Sleep takes milliseconds, so dividing rounds every request under one down to zero and the caller
 * spins where it meant to pace. that is not only a lost sleep -- write admission asks for two
 * hundred microseconds between polls, its throttle is two hundred microseconds a slot and its ring
 * dwell caps at a hundred and fifty, so every figure the backpressure policy produces rounded to
 * nothing and the whole of it did nothing on this platform. rounding up costs a caller asking for
 * two hundred microseconds a full millisecond instead, which is the direction that paces */
#define usleep(microseconds) Sleep((DWORD)(((microseconds) + 999) / 1000))
#define access               _access
#define ftell                _ftelli64
#define fseek                _fseeki64

/* fopen wrapper for windows */
/*
 * tdb_fopen
 * @param filename the filename to open
 * @param mode the mode to open the file in
 * @return a pointer to the opened file, or NULL on failure
 */
static inline FILE *tdb_fopen(const char *filename, const char *mode)
{
    return _fsopen(filename, mode, _SH_DENYNO);
}
#define fopen tdb_fopen

/* clock_gettime for MSVC */
/*
 * clock_gettime
 * @param clk_id the clock ID (unused)
 * @param tp the timespec struct to fill
 * @return 0 on success, -1 on failure
 */
static inline int clock_gettime(int clk_id, struct timespec *tp)
{
    if (clk_id == CLOCK_MONOTONIC)
    {
        /* a steady counter, immune to wall-clock steps -- the cond timedwait deadlines use it */
        LARGE_INTEGER freq, ctr;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&ctr);
        tp->tv_sec = (long)(ctr.QuadPart / freq.QuadPart);
        tp->tv_nsec = (long)(((ctr.QuadPart % freq.QuadPart) * 1000000000ULL) / freq.QuadPart);
        return 0;
    }

    FILETIME ft;
    ULARGE_INTEGER ui;

    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;

    /* convert 100-nanosecond intervals to seconds and nanoseconds */
    tp->tv_sec = (long)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);
    tp->tv_nsec = (long)((ui.QuadPart % 10000000ULL) * 100);

    return 0;
}

/* gettimeofday for MSVC */
/*
 * gettimeofday
 * @param tp the timeval struct to fill
 * @param tzp the timezone struct (unused)
 * @return 0 on success, -1 on failure
 */
static inline int gettimeofday(struct timeval *tp, struct timezone *tzp)
{
    (void)tzp;
    FILETIME ft;
    ULARGE_INTEGER ui;

    GetSystemTimeAsFileTime(&ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;

    /* convert to microseconds */
    tp->tv_sec = (long)((ui.QuadPart - 116444736000000000ULL) / 10000000ULL);
    tp->tv_usec = (long)((ui.QuadPart % 10000000ULL) / 10);

    return 0;
}

/* ===== native Win32 threading backend (MSVC) =====
 * implements the subset of the pthread API the engine uses on top of Win32 primitives, so the MSVC
 * build needs no pthreads-win32 library. mutexes and rwlocks are SRWLOCK based (non-recursive,
 * matching the engine's lock discipline), condition variables are CONDITION_VARIABLE, threads use
 * _beginthreadex, and thread-local storage uses fiber-local storage so destructors run on thread
 * exit. placed after clock_gettime because the cond timedwait shim converts an absolute deadline
 * with it. */
#include <errno.h>
#include <process.h>
#include <stdint.h>
#include <stdlib.h>

/* mutex -- SRWLOCK held exclusively (non-recursive, like a default pthread mutex) */
typedef SRWLOCK pthread_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER SRWLOCK_INIT

static inline int pthread_mutex_init(pthread_mutex_t *m, const void *attr)
{
    (void)attr;
    InitializeSRWLock(m);
    return 0;
}
static inline int pthread_mutex_destroy(pthread_mutex_t *m)
{
    (void)m;
    return 0;
}
static inline int pthread_mutex_lock(pthread_mutex_t *m)
{
    AcquireSRWLockExclusive(m);
    return 0;
}
static inline int pthread_mutex_unlock(pthread_mutex_t *m)
{
    ReleaseSRWLockExclusive(m);
    return 0;
}
static inline int pthread_mutex_trylock(pthread_mutex_t *m)
{
    return TryAcquireSRWLockExclusive(m) ? 0 : EBUSY;
}

/* rwlock -- SRWLOCK plus a mode flag so a single unlock releases the right mode. only the exclusive
 * owner writes the flag, and readers and the writer are mutually exclusive, so a reader always
 * reads it as 0 (the writer clears it before releasing, which happens-before any later shared
 * acquire). */
typedef struct
{
    SRWLOCK lock;
    volatile LONG exclusive;
} pthread_rwlock_t;

static inline int pthread_rwlock_init(pthread_rwlock_t *rw, const void *attr)
{
    (void)attr;
    InitializeSRWLock(&rw->lock);
    rw->exclusive = 0;
    return 0;
}
static inline int pthread_rwlock_destroy(pthread_rwlock_t *rw)
{
    (void)rw;
    return 0;
}
static inline int pthread_rwlock_rdlock(pthread_rwlock_t *rw)
{
    AcquireSRWLockShared(&rw->lock);
    return 0;
}
static inline int pthread_rwlock_wrlock(pthread_rwlock_t *rw)
{
    AcquireSRWLockExclusive(&rw->lock);
    rw->exclusive = 1;
    return 0;
}
static inline int pthread_rwlock_unlock(pthread_rwlock_t *rw)
{
    if (rw->exclusive)
    {
        rw->exclusive = 0;
        ReleaseSRWLockExclusive(&rw->lock);
    }
    else
    {
        ReleaseSRWLockShared(&rw->lock);
    }
    return 0;
}

/* condition variable -- stores the clock its deadlines are expressed in so timedwait can convert an
 * absolute deadline to the relative timeout SleepConditionVariable expects */
typedef struct
{
    int clock_id;
} pthread_condattr_t;
typedef struct
{
    CONDITION_VARIABLE cv;
    int clock_id;
} pthread_cond_t;

static inline int pthread_condattr_init(pthread_condattr_t *a)
{
    a->clock_id = CLOCK_REALTIME;
    return 0;
}
static inline int pthread_condattr_destroy(pthread_condattr_t *a)
{
    (void)a;
    return 0;
}
static inline int pthread_condattr_setclock(pthread_condattr_t *a, int clk)
{
    a->clock_id = clk;
    return 0;
}
static inline int pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a)
{
    InitializeConditionVariable(&c->cv);
    c->clock_id = a ? a->clock_id : CLOCK_REALTIME;
    return 0;
}
static inline int pthread_cond_destroy(pthread_cond_t *c)
{
    (void)c;
    return 0;
}
static inline int pthread_cond_signal(pthread_cond_t *c)
{
    WakeConditionVariable(&c->cv);
    return 0;
}
static inline int pthread_cond_broadcast(pthread_cond_t *c)
{
    WakeAllConditionVariable(&c->cv);
    return 0;
}
static inline int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{
    SleepConditionVariableSRW(&c->cv, m, INFINITE, 0);
    return 0;
}
static inline int pthread_cond_timedwait(pthread_cond_t *c, pthread_mutex_t *m,
                                         const struct timespec *abstime)
{
    struct timespec now;
    LONGLONG ms;
    DWORD wait;

    clock_gettime(c->clock_id, &now);
    ms = (LONGLONG)(abstime->tv_sec - now.tv_sec) * 1000 +
         (abstime->tv_nsec - now.tv_nsec) / 1000000;
    if (ms <= 0)
        wait = 0;
    else if (ms >= INFINITE)
        wait = INFINITE - 1;
    else
        wait = (DWORD)ms;

    if (SleepConditionVariableSRW(&c->cv, m, wait, 0)) return 0;
    return (GetLastError() == ERROR_TIMEOUT) ? ETIMEDOUT : 0;
}

/* threads -- _beginthreadex with a trampoline. pthread_t is a heap control block holding the thread
 * handle and the function's void* return, so pthread_join can hand it back (callers that pass a
 * non-NULL retval, such as the queue tests, rely on it). join frees the block, so every created
 * thread must be joined (the engine has no detached threads). */
typedef struct
{
    HANDLE handle;
    void *(*fn)(void *);
    void *arg;
    void *retval;
} tdb_win_thread_t;
typedef tdb_win_thread_t *pthread_t;

static inline unsigned __stdcall tdb_win_thread_trampoline(void *p)
{
    tdb_win_thread_t *t = (tdb_win_thread_t *)p;
    t->retval = t->fn(t->arg);
    return 0;
}

/* thread attributes. nothing in the engine, the tests or the tools sets one -- every pthread_create
 * here passes a null attr and takes the default stack -- so these exist to keep the shim a complete
 * substitute for the posix header rather than to serve an in-tree caller. of the attributes, only
 * the stack size is carried through to _beginthreadex; the rest are no-ops, and a zero stack size
 * means the default. */
typedef struct
{
    size_t stacksize;
} pthread_attr_t;
static inline int pthread_attr_init(pthread_attr_t *a)
{
    if (a) a->stacksize = 0;
    return 0;
}
static inline int pthread_attr_destroy(pthread_attr_t *a)
{
    (void)a;
    return 0;
}
static inline int pthread_attr_setstacksize(pthread_attr_t *a, size_t stacksize)
{
    if (!a) return EINVAL;
    a->stacksize = stacksize;
    return 0;
}
static inline int pthread_attr_getstacksize(const pthread_attr_t *a, size_t *stacksize)
{
    if (!a || !stacksize) return EINVAL;
    *stacksize = a->stacksize;
    return 0;
}

static inline int pthread_create(pthread_t *th, const void *attr, void *(*fn)(void *), void *arg)
{
    tdb_win_thread_t *t;
    uintptr_t h;
    unsigned stacksize = attr ? (unsigned)((const pthread_attr_t *)attr)->stacksize : 0;

    t = (tdb_win_thread_t *)malloc(sizeof(*t));
    if (!t) return EAGAIN;
    t->fn = fn;
    t->arg = arg;
    t->retval = NULL;
    h = _beginthreadex(NULL, stacksize, tdb_win_thread_trampoline, t, 0, NULL);
    if (h == 0)
    {
        free(t);
        return EAGAIN;
    }
    t->handle = (HANDLE)h;
    *th = t;
    return 0;
}
static inline int pthread_join(pthread_t th, void **retval)
{
    if (!th) return EINVAL;
    WaitForSingleObject(th->handle, INFINITE);
    if (retval) *retval = th->retval; /* the trampoline stored it before the thread exited */
    CloseHandle(th->handle);
    free(th);
    return 0;
}

/* sched_yield -- the engine itself yields via cpu_yield, but direct POSIX callers (e.g. tests)
 * still expect this symbol on MSVC, so shim it onto SwitchToThread */
static inline int sched_yield(void)
{
    SwitchToThread();
    return 0;
}

/* thread-local storage -- fiber-local storage runs its callback on thread exit (TlsAlloc does not),
 * giving pthread_key destructor semantics. the key carries its destructor so the value can be
 * wrapped and one NTAPI callback can invoke the per-key cdecl destructor; this also keeps the key
 * self-contained across translation units. */
typedef struct
{
    DWORD fls;
    void (*dtor)(void *);
} pthread_key_t;

typedef struct
{
    void (*dtor)(void *);
    void *val;
} tdb_win_tls_slot_t;

static inline void NTAPI tdb_win_tls_callback(void *p)
{
    tdb_win_tls_slot_t *s = (tdb_win_tls_slot_t *)p;
    if (s)
    {
        if (s->dtor && s->val) s->dtor(s->val);
        free(s);
    }
}
static inline int pthread_key_create(pthread_key_t *key, void (*dtor)(void *))
{
    DWORD k = FlsAlloc((PFLS_CALLBACK_FUNCTION)tdb_win_tls_callback);
    if (k == FLS_OUT_OF_INDEXES) return EAGAIN;
    key->fls = k;
    key->dtor = dtor;
    return 0;
}
/* the engine's one thread-local key lives for the process, so nothing here deletes one. present for
 * the same reason the thread attributes above are -- the shim stands in for the posix header whole,
 * rather than only for the calls this tree happens to make */
static inline int pthread_key_delete(pthread_key_t key)
{
    return FlsFree(key.fls) ? 0 : EINVAL;
}
static inline void *pthread_getspecific(pthread_key_t key)
{
    tdb_win_tls_slot_t *s = (tdb_win_tls_slot_t *)FlsGetValue(key.fls);
    return s ? s->val : NULL;
}
static inline int pthread_setspecific(pthread_key_t key, const void *val)
{
    tdb_win_tls_slot_t *s = (tdb_win_tls_slot_t *)FlsGetValue(key.fls);
    if (!s)
    {
        if (!val) return 0;
        s = (tdb_win_tls_slot_t *)malloc(sizeof(*s));
        if (!s) return ENOMEM;
        s->dtor = key.dtor;
        FlsSetValue(key.fls, s);
    }
    s->val = (void *)val;
    return 0;
}

/* one-time init */
typedef INIT_ONCE pthread_once_t;
#define PTHREAD_ONCE_INIT INIT_ONCE_STATIC_INIT

static inline BOOL CALLBACK tdb_win_once_trampoline(PINIT_ONCE once, PVOID param, PVOID *ctx)
{
    (void)once;
    (void)ctx;
    ((void (*)(void))(uintptr_t)param)();
    return TRUE;
}
static inline int pthread_once(pthread_once_t *once, void (*fn)(void))
{
    InitOnceExecuteOnce(once, tdb_win_once_trampoline, (PVOID)(uintptr_t)fn, NULL);
    return 0;
}
/* ===== end native Win32 threading backend ===== */

#endif /* _MSC_VER */

/* fileno for all Windows (MSVC and MinGW) */
/*
 * tdb_fileno
 * portable file descriptor extraction from FILE*
 * @param stream the FILE* to get descriptor from
 * @return file descriptor, or -1 on failure
 */
static inline int tdb_fileno(FILE *stream)
{
    if (!stream) return -1;
    return _fileno(stream);
}

#endif /* __PLATFORM_WINDOWS_MSVC_H__ */
