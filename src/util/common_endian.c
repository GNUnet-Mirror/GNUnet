/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file util/common_endian.c
 * @brief endian conversion helpers
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util",__VA_ARGS__)

unsigned long long
GNUNET_ntohll (unsigned long long n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#else
  return (((unsigned long long) ntohl (n)) << 32) + ntohl (n >> 32);
#endif
}

unsigned long long
GNUNET_htonll (unsigned long long n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#else
  return (((unsigned long long) htonl (n)) << 32) + htonl (n >> 32);
#endif
}



/* end of common_endian.c */
