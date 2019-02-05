/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @author Martin Schanzenbach
 *
 * @file include/compat.h
 * Definitions for macOS and Win32
 */

#ifndef _COMPAT_H
#define _COMPAT_H

#ifdef __cplusplus
extern "C"
{
#endif

  /**
 * memrchr as defined in glibc
 *
 * @param s pointer to memory
 * @param c character to search for
 * @param n search character limit
 */
void*
GN_memrchr_ (const void *s,
             int c,
             size_t n);
#ifndef HAVE_MEMRCHR
#define memrchr(s,c,n) GN_memrchr_(s,c,n)
#endif

#ifdef __cplusplus
}
#endif

#endif
