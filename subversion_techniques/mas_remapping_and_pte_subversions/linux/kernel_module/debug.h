/* debug.h -- debug for rootkit
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
 */
#ifndef _ROOTKIT_DEBUG_H_
#define _ROOTKIT_DEBUG_H_
#include <linux/kernel.h>

// Disable debug prints by commenting out the definition
#define DEBUG

#ifdef DEBUG

#define DEBUG_PRINT(fmt, ...) \
   vprintk(fmt, __VA_ARGS__);
#else
  #define DEBUG_PRINT(...)
#endif

typedef enum _LOGLEVEL {
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} LOGLEVEL;

void (log_print)(LOGLEVEL, const char *, ...);


#endif //_ROOTKIT_DEBUG_H_
