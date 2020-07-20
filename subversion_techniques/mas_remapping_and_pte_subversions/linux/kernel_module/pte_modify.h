/* pte_modify.h -- invalidating or remapping PTEs
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
#ifndef MATHESIS_PTE_HIDE_H
#define MATHESIS_PTE_HIDE_H

/* Loads helper functions for manipulating PTE entries */
#include "pte_helper.h"
#include "helper.h"

/* Declarations for the linked list of virtual address to PTE mappings */
struct va_pte_entry_ll {
    unsigned long int va_val;
    unsigned long int pte_val;
    struct list_head va_pte_list;
};

/* Functions for linked list */
struct va_pte_entry_ll *create_va_pte_entry(pte_uint64, pte_uint64);
int insert_ll_va_pte(VIRT_ADDR, PTE *);
struct va_pte_entry_ll *lookup_ll_va_pte(VIRT_ADDR);

/* Declaration of functions to invalidate pages */
int invalidate_restore_pte(int, VIRT_ADDR, int);
void pte_invalidate_handler(char *, int, int);
void pte_invalidate_anon_handler(unsigned long long, int, int);


/* Declaration of functions to remap pages */
void remap_pte(struct vm_area_struct *, struct vm_area_struct *, int, MemoryMode);
void reset_pte(struct vm_area_struct *, int, MemoryMode );
void pte_remap_handler(char *, int, int);
void pte_remap_handler_anon(unsigned long long, int, int, MemoryMode);
void mas_remapping_handler(unsigned long long, int, int);
struct vm_area_struct *get_fitting_benign_vma(struct vm_area_struct *, int);
struct vm_area_struct *find_vma_with_size(unsigned long long);

#endif //MATHESIS_PTE_HIDE_H
