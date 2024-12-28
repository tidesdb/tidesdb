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

/* compat header for multi-platform support (Windows, POSIX, posix includes macOS) */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#include <windows.h>

typedef HANDLE pthread_t;
typedef HANDLE pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef CRITICAL_SECTION crit_section_t;
typedef SRWLOCK pthread_rwlock_t;

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
    DIR *dir = malloc(sizeof(DIR));
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
    dir->findFileData.cFileName[0] = '\0'; /* reset */
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

/* semaphore functions for Windows */
typedef HANDLE sem_t;

int sem_init(sem_t *sem, int pshared, unsigned int value)
{
    *sem = CreateSemaphore(NULL, value, LONG_MAX, NULL);
    if (*sem == NULL)
    {
        errno = GetLastError();
        return -1;
    }
    return 0;
}

/* file operations macros for cross-platform compatibility */
#define access         _access
#define mkdir          _mkdir
#define stat           _stat
#define S_ISDIR(m)     (((m)&S_IFMT) == S_IFDIR)
#define rmdir          _rmdir
#define unlink         _unlink
#define remove         _unlink
#define fclose         _fclose
#define truncate       _chsize
#define sleep(seconds) Sleep((seconds)*1000)
#define fsync          _commit
#define fileno         _fileno
#define fseek          _fseek
#define fread          _fread
#define feof           _feof
#define ftell          _ftell

#else /* posix systems */
#include <dirent.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/stat.h>

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
typedef pthread_cond_t cond_t;
typedef pthread_mutex_t crit_section_t;
typedef pthread_rwlock_t rwlock_t;
#endif

#endif /* __COMPAT_H__ */