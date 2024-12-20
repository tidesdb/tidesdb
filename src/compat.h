/*
 *
 * Copyright (C) TidesDB
 *
 * Original Author: Alex Gaetano Padula
 *
 * Licensed under the Mozilla Public License, v. 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.mozilla.org/en-US/MPL/2.0/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __COMPAT_H__
#define __COMPAT_H__

/* for multi-platform compatibility */

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <tchar.h>
#include <windows.h>
typedef HANDLE thread_t;
typedef HANDLE mutex_t;
typedef CONDITION_VARIABLE cond_t;
typedef CRITICAL_SECTION crit_section_t;

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

DIR *opendir(const char *name)
{
    DIR *dir = (DIR *)malloc(sizeof(DIR));
    if (dir == NULL)
    {
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

struct dirent *readdir(DIR *dir)
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
    strncpy(dir->dirent.d_name, dir->findFileData.cFileName, MAX_PATH);
    return &dir->dirent;
}

int closedir(DIR *dir)
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

/* semaphores */
typedef HANDLE sem_t;

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    *sem = CreateSemaphore(NULL, value, LONG_MAX, NULL);
    return (*sem == NULL) ? -1 : 0;
}

int sem_wait(sem_t *sem)
{
    return (WaitForSingleObject(*sem, INFINITE) == WAIT_OBJECT_0) ? 0 : -1;
}

int sem_post(sem_t *sem)
{
    return (ReleaseSemaphore(*sem, 1, NULL) == 0) ? -1 : 0;
}

int sem_destroy(sem_t *sem)
{
    return (CloseHandle(*sem) == 0) ? -1 : 0;
}

/* file ops */
#define access _access
#define mkdir  _mkdir
#define remove _unlink

#else
#include <dirent.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <unistd.h>
typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_mutex_t crit_section_t;
#endif

/* thread creation and management */
#ifdef _WIN32
#define thread_create(thread, func, arg) \
    (*(thread) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(func), (arg), 0, NULL))
#define thread_join(thread) (WaitForSingleObject((thread), INFINITE), CloseHandle(thread))
#else
#define thread_create(thread, func, arg) pthread_create((thread), NULL, (func), (arg))
#define thread_join(thread)              pthread_join(*(thread), NULL)
#endif

/* mutex and synchronization */
#ifdef _WIN32
#define mutex_init(mutex)    (*(mutex) = CreateMutex(NULL, FALSE, NULL))
#define mutex_lock(mutex)    WaitForSingleObject(*(mutex), INFINITE)
#define mutex_unlock(mutex)  ReleaseMutex(*(mutex))
#define mutex_destroy(mutex) CloseHandle(*(mutex))
#else
#define mutex_init(mutex)    pthread_mutex_init((mutex), NULL)
#define mutex_lock(mutex)    pthread_mutex_lock((mutex))
#define mutex_unlock(mutex)  pthread_mutex_unlock((mutex))
#define mutex_destroy(mutex) pthread_mutex_destroy((mutex))
#endif

/* conditions vars */
#ifdef _WIN32
#define cond_init(cond)        InitializeConditionVariable(cond)
#define cond_wait(cond, mutex) SleepConditionVariableCS((cond), (mutex), INFINITE)
#define cond_signal(cond)      WakeConditionVariable(cond)
#else
#define cond_init(cond)        pthread_cond_init((cond), NULL)
#define cond_wait(cond, mutex) pthread_cond_wait((cond), (mutex))
#define cond_signal(cond)      pthread_cond_signal((cond))
#endif

/* critical sections */
#ifdef _WIN32
#define crit_section_init(cs)    InitializeCriticalSection(cs)
#define crit_section_enter(cs)   EnterCriticalSection(cs)
#define crit_section_leave(cs)   LeaveCriticalSection(cs)
#define crit_section_destroy(cs) DeleteCriticalSection(cs)
#else
#define crit_section_init(cs)    pthread_mutex_init((cs), NULL)
#define crit_section_enter(cs)   pthread_mutex_lock((cs))
#define crit_section_leave(cs)   pthread_mutex_unlock((cs))
#define crit_section_destroy(cs) pthread_mutex_destroy((cs))
#endif

#endif /* __COMPAT_H__ */