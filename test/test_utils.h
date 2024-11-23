#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * remove_directory
 * Recursively remove a directory and its contents
 */
int remove_directory(const char *path) {
    struct dirent *entry;
    DIR *dir = opendir(path);

    if (dir == NULL) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char full_path[1024];
        struct stat statbuf;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);

        if (stat(full_path, &statbuf) == -1) {
            perror("stat");
            closedir(dir);
            return -1;
        }

        if (S_ISDIR(statbuf.st_mode)) {
            if (remove_directory(full_path) == -1) {
                closedir(dir);
                return -1;
            }
        } else {
            if (remove(full_path) == -1) {
                perror("remove");
                closedir(dir);
                return -1;
            }
        }
    }

    closedir(dir);

    if (rmdir(path) == -1) {
        perror("rmdir");
        return -1;
    }

    return 0;
}