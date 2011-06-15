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

     For the actual CRC code:
     Copyright abandoned; this code is in the public domain.
     Provided to GNUnet by peter@horizon.com
*/

/**
 * @file monkey/bug_crypto_crc.c
 * @brief implementation of CRC32 (this code has been copied from GNUnet util source directory, and modified to be Seaspider friendly)
 * @author Christian Grothoff, Safey A.Halim
 */

#include "assert.h"
#include "stdlib.h"
#include "stdio.h"

#define Z_NULL  0


#define POLYNOMIAL (unsigned long)0xedb88320
static unsigned long crc_table[256];

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
  unsigned long h = 1;

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
static unsigned long
crc_go (unsigned long crc, const char *buf, size_t len)
{
  crc_init ();
  assert (crc_table[255] != 0);
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
crc32_n (const void *buf, size_t len)
{
  unsigned long crc;
  crc = crc_go (0L, Z_NULL, 0);
  crc = crc_go (crc, (char *) buf, len);
  return crc;
}


int main ()
{
  char buf[1024];
  int i;
  for (i = 0; i < 1024; i++)
  {
     buf[i] = (char) i;
  }
  for (i = 0; i < 1024; i++)
  {
    printf("%d\n", crc32_n (&buf[i], 1024 - i));
  }
  return 0;
}

/* end of bug_crypto_crc.c */
