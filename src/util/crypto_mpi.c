/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
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
 * @file util/crypto_mpi.c
 * @brief Helper functions for libgcrypt MPIs
 * @author Christian Grothoff
 * @author Florian Dold
 */
#include "platform.h"
#include <gcrypt.h>
#include "gnunet_util_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0)


/**
 * If target != size, move @a target bytes to the end of the size-sized
 * buffer and zero out the first @a target - @a size bytes.
 *
 * @param buf original buffer
 * @param size number of bytes in @a buf
 * @param target target size of the buffer
 */
static void
adjust (void *buf,
	size_t size,
	size_t target)
{
  char *p = buf;

  if (size < target)
  {
    memmove (&p[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}


/**
 * Output the given MPI value to the given buffer in
 * network byte order.
 * The MPI @a val may not be negative.
 *
 * @param buf where to output to
 * @param size number of bytes in @a buf
 * @param val value to write to @a buf
 */
void
GNUNET_CRYPTO_mpi_print_unsigned (void *buf,
                                  size_t size,
                                  gcry_mpi_t val)
{
  size_t rsize;

  if (gcry_mpi_get_flag (val, GCRYMPI_FLAG_OPAQUE))
  {
    /* Store opaque MPIs left aligned into the buffer.  */
    unsigned int nbits;
    const void *p;

    p = gcry_mpi_get_opaque (val, &nbits);
    GNUNET_assert (p);
    rsize = (nbits+7)/8;
    if (rsize > size)
      rsize = size;
    memcpy (buf, p, rsize);
    if (rsize < size)
      memset (buf+rsize, 0, size - rsize);
  }
  else
  {
    /* Store regular MPIs as unsigned integers right aligned into
       the buffer.  */
    rsize = size;
    GNUNET_assert (0 ==
                   gcry_mpi_print (GCRYMPI_FMT_USG, buf, rsize, &rsize,
                                   val));
    adjust (buf, rsize, size);
  }
}


/**
 * Convert data buffer into MPI value.
 * The buffer is interpreted as network
 * byte order, unsigned integer.
 *
 * @param result where to store MPI value (allocated)
 * @param data raw data (GCRYMPI_FMT_USG)
 * @param size number of bytes in @a data
 */
void
GNUNET_CRYPTO_mpi_scan_unsigned (gcry_mpi_t *result,
                                 const void *data,
                                 size_t size)
{
  int rc;

  if (0 != (rc = gcry_mpi_scan (result,
				GCRYMPI_FMT_USG,
				data, size, &size)))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
    GNUNET_assert (0);
  }
}

/* end of crypto_mpi.c */
