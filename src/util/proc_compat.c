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
#include "platform.h"

/**
 * @author Martin Schanzenbach
 *
 * @file util/proc_compat.c
 * Definitions for macOS and Win32
 */


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
             size_t n)
{
  const unsigned char *ucs = s;
  ssize_t i;

  for (i = n - 1; i >= 0; i--)
    if (c == (int) ucs[i])
      return (void *) &ucs[i];
  return NULL;
}
