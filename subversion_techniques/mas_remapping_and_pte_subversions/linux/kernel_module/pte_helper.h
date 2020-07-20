/* pte_helper.h -- header for helper functions and definitions for PTE modification
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
#ifndef MATHESIS_PTE_HELPER_H
#define MATHESIS_PTE_HELPER_H


/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef unsigned long int pte_uint64;

/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef union __attribute__ ((__packed__)) CR3_ {
    pte_uint64 value;
    struct {
        pte_uint64 ignored_1	 : 3;
        pte_uint64 write_through : 1;
        pte_uint64 cache_disable : 1;
        pte_uint64 ignored_2	 : 7;
        pte_uint64 pml4_p        :40;
        pte_uint64 reserved	     :12;
    };
} CR3;


/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef union __attribute__ ((__packed__)) VIRT_ADDR {
    pte_uint64 value;
    void *pointer;
    struct {
        pte_uint64 offset	:12;
        pte_uint64 pt_index	: 9;
        pte_uint64 pd_index	: 9;
        pte_uint64 pdpt_index	: 9;
        pte_uint64 pml4_index	: 9;
        pte_uint64 reserved	    :16;
    };
} VIRT_ADDR;

/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef pte_uint64 PHYS_ADDR;


/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef union __attribute__ ((__packed__)) PML4E_ {
    pte_uint64 value;
    struct {
        pte_uint64 present  	: 1;
        pte_uint64 rw	    	: 1;
        pte_uint64 user_svsr	: 1;
        pte_uint64 write_through: 1;
        pte_uint64 cache_disable: 1;
        pte_uint64 accessed 	: 1;
        pte_uint64 ignored_1	: 1;
        pte_uint64 reserved_1	: 1;
        pte_uint64 ignored_2	: 4;
        pte_uint64 pdpt_p   	:40;
        pte_uint64 ignored_3	:11;
        pte_uint64 xd	    	: 1;
    };
} PML4E;

/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef union __attribute__ ((__packed__)) PDPTE_ {
    pte_uint64 value;
    struct {
        pte_uint64 present  	: 1;
        pte_uint64 rw	    	: 1;
        pte_uint64 user_svsr	: 1;
        pte_uint64 write_through: 1;
        pte_uint64 cache_disable: 1;
        pte_uint64 accessed 	: 1;
        pte_uint64 dirty    	: 1;
        pte_uint64 page_size	: 1;
        pte_uint64 ignore_2 	: 4;
        pte_uint64 pd_p 		:40;
        pte_uint64 ignored_3	:11;
        pte_uint64 xd   		: 1;
    };
} PDPTE;


/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef union __attribute__ ((__packed__)) PDE_ {
    pte_uint64 value;
    struct {
        pte_uint64 present  	: 1;
        pte_uint64 rw	    	: 1;
        pte_uint64 user_svsr	: 1;
        pte_uint64 write_through: 1;
        pte_uint64 cache_disable: 1;
        pte_uint64 accessed	    : 1;
        pte_uint64 dirty	    : 1;
        pte_uint64 page_size	: 1;
        pte_uint64 ignore_2	    : 4;
        pte_uint64 pt_p		    :40;
        pte_uint64 ignored_3	:11;
        pte_uint64 xd	    	: 1;
    };
} PDE;


/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef union __attribute__ ((__packed__)) PTE_ {
    pte_uint64 value;
    VIRT_ADDR vaddr;
    struct {
        pte_uint64 present  	: 1;
        pte_uint64 rw	    	: 1;
        pte_uint64 user_svsr	: 1;
        pte_uint64 write_through: 1;
        pte_uint64 cache_disable: 1;
        pte_uint64 accessed	    : 1;
        pte_uint64 dirty	    : 1;
        pte_uint64 pat		    : 1;
        pte_uint64 global	    : 1;
        pte_uint64 ignored_1	: 3;
        pte_uint64 page_frame	:40;
        pte_uint64 ignored_3	:11;
        pte_uint64 xd	    	: 1;
    };
} PTE;


/**
 * NOTE: Released under Apache 2.0 license
 * Author: Johannes Stüttgen
 * https://github.com/google/rekall/blob/master/tools/linux/lmap/minpmem/pte_mmap.h
 */
typedef enum PTE_STATUS_ {
    PTE_SUCCESS = 0,
    PTE_ERROR,
    PTE_ERROR_HUGE_PAGE,
    PTE_ERROR_RO_PTE,
    PTE_ERROR_NO_PT_MAP
} PTE_STATUS;


CR3 (cr3_for_pid)(int);


PTE_STATUS (remap_page)(VIRT_ADDR, PHYS_ADDR, int);
struct page *get_pte_page(PTE *);
PTE_STATUS (pte_from_virt_for_pid)(void *, PTE **, int);

#endif //MATHESIS_PTE_HELPER_H
