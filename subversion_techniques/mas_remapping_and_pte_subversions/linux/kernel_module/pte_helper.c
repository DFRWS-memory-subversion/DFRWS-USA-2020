/* pte_helper.c -- helper functions and definitions for PTE modification
 *
 * Copyright (C) 2019 Patrick Reichenberger
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
 * ********************************************************************************
 * Parts of this code are released under Apache 2.0 license.
 *
 * Copyright 2012 Google Inc. All Rights Reserved.
 * Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ********************************************************************************
 */
#include <linux/pagemap.h>
#include <asm/pgtable.h>

#include "pte_helper.h"
#include "helper.h"
#include "debug.h"

/* Returns pointer to page struct for given PTE */
struct page *get_pte_page(PTE *pte) {
    struct page *page;
    page = virt_to_page(phys_to_virt(pte->page_frame << 12));
    return page;
}


/** Read the CR3 register.
 *
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap_linux.c
 */
static CR3 get_cr3(void) {
    CR3 cr3;
    __asm__ __volatile__("mov %%cr3, %0;": "=r"(cr3.value));
    return cr3;
}

/** flush_tlb_page - flushes tlb entry for a specific page
 * @addr: address to flush
 *
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap_linux.c
 */
static void flush_tlb_page(void *addr) {
    __asm__ __volatile__("invlpg (%0);"
    :
    : "r"(addr)
    : );
}


/** flush_caches - flushes all L1/L2/... etc. caches
 *
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap_linux.c
 */
static void flush_caches(void) {
    __asm__ __volatile__("wbinvd;" : : );
}


/** pte_from_virt - determines PTE for virtual address
 *
 * @vaddr: virtual address
 *
 * The content was modified and is based on function of: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.c
 */
PTE_STATUS pte_from_virt(void *addr, PTE **pte, CR3 *cr3) {
    PML4E *pml4;
    PML4E *pml4e;
    PDPTE *pdpt;
    PDPTE *pdpte;
    PDE *pd;
    PDE *pde;
    PTE *pt;
    VIRT_ADDR vaddr;
    PTE_STATUS status = PTE_ERROR;

    vaddr.pointer = addr;

    log_print(LOG_DEBUG,
              "Resolving PTE for Address:%#016llx",
              vaddr.value);

    log_print(LOG_DEBUG, "CR3 is %p", cr3->value);
    log_print(LOG_DEBUG, "Kernel PML4 is at %p physical", cr3->pml4_p << PAGE_SHIFT);

    // PML4
    pml4 = (PML4E *) phys_to_virt(cr3->pml4_p << 12);
    log_print(LOG_DEBUG, "Kernel PML4 is at %p virtual", pml4);

    // PDPT
    pml4e = (pml4 + vaddr.pml4_index);
    if(!pml4e->present) {
        log_print(LOG_ERR, "Error, address %#016llx has no valid mapping in PML4:",
                  vaddr.value);

        goto error;
    }
    log_print(LOG_DEBUG, "PML4 entry: %p)", pml4e->value);

    pdpt = (PDPTE *) phys_to_virt(pml4e->pdpt_p << PAGE_SHIFT);
    log_print(LOG_DEBUG, "Points to PDPT: %p)", pdpt);

    // PDT
    pdpte = (pdpt + vaddr.pdpt_index);
    if(!pdpte->present) {
        log_print(LOG_ERR, "Error, address %#016llx has no valid mapping in PDPT:",
                  vaddr.value);
        goto error;
    }
    if(pdpte->page_size) {
        log_print(LOG_ERR, "Error, address %#016llx belongs to a 1GB page:",
                  vaddr.value);
        goto error;
    }
    log_print(LOG_DEBUG, "PDPT entry: %p)", pdpte->value);

    pd = (PDE *) phys_to_virt(pdpte->pd_p << PAGE_SHIFT);
    log_print(LOG_DEBUG, "Points to PD:     %p)", pd);

    // PT
    pde = (pd + vaddr.pd_index);
    if(!pde->present) {
        log_print(LOG_ERR, "Error, address %#016llx has no valid mapping in PD:",
                  vaddr.value);
        goto error;
    }
    if(pde->page_size) {
        log_print(LOG_ERR, "Error, address %#016llx belongs to a 2MB page:",
                  vaddr.value);
        goto error;
    }

    log_print(LOG_DEBUG, "PD entry: %p)", pde->value);
    pt = (PTE *) phys_to_virt(pde->pt_p << PAGE_SHIFT);
    log_print(LOG_DEBUG, "Points to PT:     %p)", pt);

    // Get the PTE and Page Frame
    *pte = (pt + vaddr.pt_index);

    if(!(*pte)->present) {
        /* The error handling is done by the calling function, because sometimes it is intended only to
         * get the pointer to the PTE where it is known it is invalid. */
        status = PTE_ERROR_NO_PT_MAP;
        goto error;
    }
    log_print(LOG_DEBUG, "PTE: %p)", (*pte)->value);

    status = PTE_SUCCESS;
    error:
        return status;
}

/** pte_from_virt_for_pid - determines PTE for virtual address of process
 *  @addr: virtual address
 *  @pte: location to store PTE
 *  @pid: PID of process
 *
 * Wraps pte_from_virt function to specify from which process to use the PGD value
 */
PTE_STATUS pte_from_virt_for_pid(void *addr, PTE **pte, int pid) {
    CR3 cr3;

    if (pid == 0) {
        /* If kernel address, pid does not matter */
        cr3 = get_cr3();
    } else {
        /* In any other case, take the CR3 for the given PID */
        cr3 = cr3_for_pid(pid);
        if(cr3.value) {
            log_print(LOG_DEBUG, "CR3 for PID %d is %#016llx", pid, cr3.value);
        } else {
            log_print(LOG_ERR, "Task struct not available for PID %d.", pid);
            return PTE_ERROR;
        }
    }

    if (cr3.value == 0) {
        return PTE_ERROR;
    }

    return pte_from_virt(addr, pte, &cr3);
}


/** remap_page - remap a page's PTE to point to other physical address
 *
 * @vaddr: virtual address
 * @target: physical address
 * @pid: PID
 *
 * NOTE: Released under Apache 2.0 license
 * The function was modified and is based on function of: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.c
 */
PTE_STATUS remap_page(VIRT_ADDR vaddr, PHYS_ADDR target, int pid) {
    PTE *pte;

    // If the physical target or the virtual address of the page is not
    // at a page boundary.
    if(((!target) & PAGE_MASK) || vaddr.offset) {
        log_print(LOG_ERR, "Failed to map %#016llx, only page aligned remapping is supported!", target);
        return PTE_ERROR;
    }

    // Call the find pte function with the virtual address and the address of
    // the pte pointer as argument to point the pte pointer to the pte and use
    // it in the subsequent instructions pte points to a PTE
    if (pte_from_virt_for_pid(vaddr.pointer, &pte, pid)) {
        log_print(LOG_ERR, "Failed to find the PTE for the page, might be inside huge page, aborting...", 0);
        return PTE_ERROR;
    }
    log_print(LOG_INFO, "Remapping %#016llx to %#016llx", vaddr.value, target);

    // Change the pte to point to the new offset
    pte->page_frame = target >> 12;
    // Flush the old pte from the TLBs in the system.
    flush_tlb_page(vaddr.pointer);
    // Flush L1/L2/L3 caches
    flush_caches();

    return PTE_SUCCESS;
}

/** cr3_for_pid - get PGD/CR3 for task with pid
 * @pid: PID
 *
 */
CR3 cr3_for_pid(int pid) {
    struct mm_struct *mm = find_mm(pid);

    VIRT_ADDR cr3_virt;
    CR3 cr3;
    cr3.value = 0;

    if(mm) {
        cr3_virt.pointer = mm->pgd;
        cr3.value = virt_to_phys(cr3_virt.pointer);
    }

    return cr3;
}

