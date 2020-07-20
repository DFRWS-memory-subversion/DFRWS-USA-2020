/* vma_modify.h -- deleting the VMAs and modifying the limits of the VMAs
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
#ifndef MATHESIS_VMA_MODIFY_H_H
#define MATHESIS_VMA_MODIFY_H_H
#include "pte_helper.h"


/* Linked list */
struct vma_ident {
    const char *filepath;
    int access_rights;
};

struct vma_backup_entry_ll {
    struct vma_ident vma_id;
    struct vm_area_struct *vma;
    unsigned long int vm_start;
    unsigned long int vm_end;
    struct list_head vma_bck_list;
};

struct vma_backup_entry_ll *create_vma_backup_entry(const char *, int, struct vm_area_struct *, pte_uint64, pte_uint64);
struct vma_backup_entry_ll *lookup_ll_vma_backup(const char *, int);
int insert_ll_vmabound_backup(const char *, int, struct vm_area_struct *, pte_uint64, pte_uint64);


int delete_vma(struct vm_area_struct *, int);
struct vm_area_struct *restore_vma(char *, int, int);
void vma_delete_handler(char *, int, int);

int tamper_vma_bounds(struct vm_area_struct *, struct vm_area_struct *, int);
int reset_vma_bounds(struct vm_area_struct *);
void vma_modify_handler(char *, char *, int, int);

#endif //MATHESIS_VMA_MODIFY_H_H