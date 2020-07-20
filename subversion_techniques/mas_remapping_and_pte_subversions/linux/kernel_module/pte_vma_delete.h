/* pte_vma_delete.h -- invalidate the PTEs and delete the VMAs
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
#ifndef MATHESIS_PTE_VMA_DELETE_H
#define MATHESIS_PTE_VMA_DELETE_H

/* Loads helper functions for manipulating PTE entries */
#include "pte_helper.h"
#include "helper.h"

void pte_vma_delete_handler(char *, int, int);

#endif //MATHESIS_PTE_VMA_DELETE_H
