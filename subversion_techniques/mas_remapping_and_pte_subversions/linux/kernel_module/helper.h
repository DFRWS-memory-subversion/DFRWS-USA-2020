/* helper.h -- general helper functions
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
#ifndef MATHESIS_HELPER_H
#define MATHESIS_HELPER_H
#include "pte_helper.h"

/* Helps to track the nr_ptes */
struct nr_ptes_vma_track {
    int nr_ptes;
    unsigned long last_included;
};

struct mm_struct *find_mm(int);
struct vm_area_struct *find_vma_mmap(int);
struct vm_area_struct *find_vma_path_rights(const char *, int, int);
struct page *own_delete_from_page_cache(PTE *);
void modify_rss_stat_count(struct mm_struct *, int, int, int);
void modify_rss_stat_countpteremap(struct mm_struct *, int, int);
struct nr_ptes_vma_track adjust_nr_ptes(struct vm_area_struct *, unsigned long);
unsigned long get_section_address(char *);

#endif //MATHESIS_HELPER_H
