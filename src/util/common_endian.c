/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2006, 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file util/common_endian.c
 * @brief endian conversion helpers
 * @author Christian Grothoff
 * @author Gabor X Toth
 */

#include "platform.h"
#include "gnunet_crypto_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-common-endian",__VA_ARGS__)


uint64_t
GNUNET_htonll (uint64_t n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  return (((uint64_t) htonl (n)) << 32) + htonl (n >> 32);
#else
  #error byteorder undefined
#endif
}


uint64_t
GNUNET_ntohll (uint64_t n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  return n;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  return (((uint64_t) ntohl (n)) << 32) + ntohl (n >> 32);
#else
  #error byteorder undefined
#endif
}


/**
 * Convert double to network-byte-order.
 * @param d the value in network byte order
 * @return the same value in host byte order
 */
double
GNUNET_hton_double (double d)
{
  double res;
  uint64_t *in = (uint64_t *) &d;
  uint64_t *out = (uint64_t *) &res;

  out[0] = GNUNET_htonll(in[0]);

  return res;
}


/**
 * Convert double to host-byte-order
 * @param d the value in network byte order
 * @return the same value in host byte order
 */
double
GNUNET_ntoh_double (double d)
{
  double res;
  uint64_t *in = (uint64_t *) &d;
  uint64_t *out = (uint64_t *) &res;

  out[0] = GNUNET_ntohll(in[0]);

  return res;
}


/* end of common_endian.c */
