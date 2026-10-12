/**
 *
 * Copyright (c) 2022-2026 TidesDB Corp. and/or its affiliates.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
/* loads a plugin that links the library, reads through it, unloads the plugin and only then lets
 * the reading thread finish, which is what a database server does at shutdown. the read leaves the
 * library's thread-specific destructor armed on that thread, so the module holding the library's
 * code has to stay mapped past the unload or the thread's exit calls into unmapped code. the test
 * asserts the module is still mapped rather than waiting for a crash, since a platform can unmap it
 * without the exit happening to fault.
 *
 * the read runs on a worker thread, or with "main" on the main thread, the form a server hits on
 * every shutdown, where the destructor runs as the process exits */
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
typedef HMODULE unload_lib_t;
#else
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
typedef void *unload_lib_t;
#endif

#define UNLOAD_DIR_SUFFIX   "_library_unload_plugin_db"
#define UNLOAD_PATH_MAX     4096
#define UNLOAD_PAUSE_MS     1
#define UNLOAD_EXIT_FAILED  1
#define UNLOAD_EXIT_SKIPPED 77

typedef int (*unload_open_t)(const char *);
typedef int (*unload_void_t)(void);
typedef int (*unload_path_t)(char *, size_t);

/**
 * unload_plugin_t
 * the plugin's entry points, resolved after it is loaded
 * @param open opens the database and seeds the key
 * @param read reads the key on the calling thread
 * @param close closes the database
 * @param library_path reports the module holding the library's code
 */
typedef struct
{
    unload_open_t open;
    unload_void_t read;
    unload_void_t close;
    unload_path_t library_path;
} unload_plugin_t;

static unload_plugin_t plugin;
static atomic_int read_rc;
static atomic_int read_done;
static atomic_int unloaded;

static void unload_pause(void)
{
#ifdef _WIN32
    Sleep(UNLOAD_PAUSE_MS);
#else
    usleep(UNLOAD_PAUSE_MS * 1000);
#endif
}

static unload_lib_t unload_load(const char *path)
{
#ifdef _WIN32
    /* the altered search path finds the plugin's own dependencies beside it */
    return LoadLibraryExA(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
#else
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void *unload_symbol(unload_lib_t lib, const char *name)
{
#ifdef _WIN32
    void *sym = (void *)(uintptr_t)GetProcAddress(lib, name);
#else
    void *sym = dlsym(lib, name);
#endif
    if (!sym) fprintf(stderr, "library_unload_plugin missing symbol %s\n", name);
    return sym;
}

static int unload_unload(unload_lib_t lib)
{
#ifdef _WIN32
    return FreeLibrary(lib) ? 0 : -1;
#else
    return dlclose(lib);
#endif
}

/* whether the module at path is mapped, asked without loading it */
static int unload_still_mapped(const char *path)
{
#ifdef _WIN32
    return GetModuleHandleA(path) != NULL;
#elif defined(RTLD_NOLOAD)
    void *h = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
    if (h) (void)dlclose(h);
    return h != NULL;
#else
    (void)path;
    return 0;
#endif
}

/* reads through the plugin, then holds the thread until the plugin is unloaded, so its exit runs
 * the destructor afterwards */
#ifdef _WIN32
static DWORD WINAPI unload_reader(LPVOID arg)
#else
static void *unload_reader(void *arg)
#endif
{
    (void)arg;
    atomic_store(&read_rc, plugin.read());
    atomic_store(&read_done, 1);
    while (!atomic_load(&unloaded)) unload_pause();
    return 0;
}

static int unload_resolve(unload_lib_t lib)
{
    *(void **)&plugin.open = unload_symbol(lib, "unload_plugin_open");
    *(void **)&plugin.read = unload_symbol(lib, "unload_plugin_read");
    *(void **)&plugin.close = unload_symbol(lib, "unload_plugin_close");
    *(void **)&plugin.library_path = unload_symbol(lib, "unload_plugin_library_path");
    return plugin.open && plugin.read && plugin.close && plugin.library_path ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 3 || (strcmp(argv[2], "thread") != 0 && strcmp(argv[2], "main") != 0))
    {
        fprintf(stderr, "usage %s <plugin> thread|main\n", argv[0]);
        return UNLOAD_EXIT_FAILED;
    }
#if !defined(_WIN32) && !defined(RTLD_NOLOAD)
    /* without RTLD_NOLOAD the loader can neither pin a module nor be asked whether one is mapped */
    printf("library_unload_plugin skipped, the loader has no RTLD_NOLOAD\n");
    return UNLOAD_EXIT_SKIPPED;
#endif
    const int on_main = strcmp(argv[2], "main") == 0;
    char db_path[UNLOAD_PATH_MAX], library[UNLOAD_PATH_MAX];
    (void)snprintf(db_path, sizeof(db_path), "%s%s_%s", argv[0], UNLOAD_DIR_SUFFIX, argv[2]);

    unload_lib_t lib = unload_load(argv[1]);
    if (!lib || unload_resolve(lib) != 0 || plugin.open(db_path) != 0 ||
        plugin.library_path(library, sizeof(library)) != 0)
    {
        fprintf(stderr, "library_unload_plugin could not load or open %s\n", argv[1]);
        return UNLOAD_EXIT_FAILED;
    }

#ifdef _WIN32
    HANDLE thread = NULL;
#else
    pthread_t thread;
#endif
    if (on_main)
        atomic_store(&read_rc, plugin.read());
    else
    {
#ifdef _WIN32
        thread = CreateThread(NULL, 0, unload_reader, NULL, 0, NULL);
        if (!thread) return UNLOAD_EXIT_FAILED;
#else
        if (pthread_create(&thread, NULL, unload_reader, NULL) != 0) return UNLOAD_EXIT_FAILED;
#endif
        while (!atomic_load(&read_done)) unload_pause();
    }

    const int close_rc = plugin.close();
    const int unload_rc = unload_unload(lib);
    const int mapped = unload_still_mapped(library);
    atomic_store(&unloaded, 1);
    if (!on_main)
    {
#ifdef _WIN32
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
#else
        (void)pthread_join(thread, NULL);
#endif
    }

    if (atomic_load(&read_rc) != 0 || close_rc != 0 || unload_rc != 0 || !mapped)
    {
        fprintf(stderr, "library_unload_plugin read %d close %d unload %d %s still mapped %d\n",
                atomic_load(&read_rc), close_rc, unload_rc, library, mapped);
        return UNLOAD_EXIT_FAILED;
    }
    printf("library_unload_plugin %s read, unloaded, %s still mapped\n", argv[2], library);
    /* returning runs the main thread's exit, and with it any destructor its read left armed */
    return 0;
}
