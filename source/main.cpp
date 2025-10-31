#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <netinet/tcp.h>

extern "C" {
#include <ps5/kernel.h>
}



#include <sys/stat.h>
#include <dirent.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define PATH_MAX 4096

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;

extern "C" {
	int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
}


#define printf_notification(fmt, ...) \
{   notify_request_t req; \
	bzero(&req, sizeof req); \
	snprintf(req.message, sizeof req.message, fmt, ##__VA_ARGS__); \
	sceKernelSendNotificationRequest(0, &req, sizeof req, 0); \
} while(0);

void change_permissions_recursive(const char *path) {
    struct stat statbuf;
    struct dirent *entry;
    DIR *dir;

    // Get file/directory status
    if (lstat(path, &statbuf) != 0) {
        perror("lstat");
        return;
    }

    // Change permissions
    if (chmod(path, 0777) != 0) {
        perror("chmod");
        return;
    }

    // If it's not a directory, return
    if (!S_ISDIR(statbuf.st_mode))
        return;

    dir = opendir(path);
    if (!dir) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Build the new path
        char newpath[PATH_MAX];
        snprintf(newpath, sizeof(newpath), "%s/%s", path, entry->d_name);

        // Recurse
        change_permissions_recursive(newpath);
    }

    closedir(dir);
}


int main(){
	
	pid_t pid;
	
	pid = getpid();
	kernel_set_ucred_authid(pid, 0x4801000000000013L);
    
	
	// Jailbreak
    kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());

	printf_notification("CHMOD RECURSIVE STARTED!");
  
	change_permissions_recursive("/data/");
	
	change_permissions_recursive("/mnt/ext1/");

	printf_notification("CHMOD RECURSIVE COMPLETE!");
  
	return 0;
}
