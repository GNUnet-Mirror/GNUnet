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

     For the actual CRC-32 code:
     Copyright abandoned; this code is in the public domain.
     Provided to GNUnet by peter@horizon.com
*/

/**
 * @file util/crypto_crc.c
 * @brief implementation of CRC16 and CRC32
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/* Avoid wasting space on 8-byte longs. */
#if UINT_MAX >= 0xffffffff
typedef unsigned int uLong;
#elif ULONG_MAX >= 0xffffffff
typedef unsigned long uLong;
#else
#error This compiler is not ANSI-compliant!
#endif

#define Z_NULL  0


#define POLYNOMIAL (uLong)0xedb88320
static uLong crc_table[256];

/*
 * This routine writes each crc_table entry exactly once,
 * with the ccorrect final value.  Thus, it is safe to call
 * even on a table that someone else is using concurrently.
 */
static void
crc_init ()
{
  static int once;
  unsigned int i, j;
  uLong h = 1;

  if (once)
    return;
  once = 1;
  crc_table[0] = 0;
  for (i = 128; i; i >>= 1)
  {
    h = (h >> 1) ^ ((h & 1) ? POLYNOMIAL : 0);
    /* h is now crc_table[i] */
    for (j = 0; j < 256; j += 2 * i)
      crc_table[i + j] = crc_table[j] ^ h;
  }
}

/*
 * This computes the standard preset and inverted CRC, as used
 * by most networking standards.  Start by passing in an initial
 * chaining value of 0, and then pass in the return value from the
 * previous crc32() call.  The final return value is the CRC.
 * Note that this is a little-endian CRC, which is best used with
 * data transmitted lsbit-first, and it should, itself, be appended
 * to data in little-endian byte and bit order to preserve the
 * property of detecting all burst errors of length 32 bits or less.
 */
static uLong
crc32 (uLong crc, const char *buf, size_t len)
{
  crc_init ();
  GNUNET_assert (crc_table[255] != 0);
  crc ^= 0xffffffff;
  while (len--)
    crc = (crc >> 8) ^ crc_table[(crc ^ *buf++) & 0xff];
  return crc ^ 0xffffffff;
}


/**
 * Compute the CRC32 checksum for the first len bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer
 * @return the resulting CRC32 checksum
 */
int32_t
GNUNET_CRYPTO_crc32_n (const void *buf, size_t len)
{
  uLong crc;

  crc = crc32 (0L, Z_NULL, 0);
  crc = crc32 (crc, (char *) buf, len);
  return crc;
}


/**
 * Perform an incremental step in a CRC16 (for TCP/IP) calculation.
 *
 * @param sum current sum, initially 0
 * @param buf buffer to calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in hdr, must be multiple of 2
 * @return updated crc sum (must be subjected to GNUNET_CRYPTO_crc16_finish to get actual crc16)
 */
uint32_t
GNUNET_CRYPTO_crc16_step (uint32_t sum, const void *buf, size_t len)
{
  const uint16_t *hdr = buf;
  for (; len >= 2; len -= 2)
    sum += *(hdr++);
  if (len == 1)
    sum += (*hdr) & ntohs(0xFF00);
  return sum;
}


/**
 * Convert results from GNUNET_CRYPTO_crc16_step to final crc16.
 *
 * @param sum cummulative sum
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_finish (uint32_t sum)
{
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  return ~sum;
}


/**
 * Calculate the checksum of a buffer in one step.
 *
 * @param buf buffer to  calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in hdr, must be multiple of 2
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_n (const void *buf, size_t len)
{
  const uint16_t *hdr = buf;
  uint32_t sum = GNUNET_CRYPTO_crc16_step (0, hdr, len);

  return GNUNET_CRYPTO_crc16_finish (sum);
}



/* end of crypto_crc.c */
