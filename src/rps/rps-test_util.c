/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/rps-test_util.c
 * @brief Some utils faciliating the view into the internals for the sampler
 *        needed for evaluation
 *
 * @author Julius Bünger
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log_from(kind,"rps-sampler",__VA_ARGS__)

#ifndef TO_FILE
#define TO_FILE
#endif /* TO_FILE */

#ifdef TO_FILE
void
to_file_ (char *file_name, char *line)
{
  struct GNUNET_DISK_FileHandle *f;
  char output_buffer[512];
  //size_t size;
  int size;
  size_t size2;


  if (NULL == (f = GNUNET_DISK_file_open (file_name,
                                          GNUNET_DISK_OPEN_APPEND |
                                          GNUNET_DISK_OPEN_WRITE |
                                          GNUNET_DISK_OPEN_CREATE,
                                          GNUNET_DISK_PERM_USER_WRITE)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not able to open file %s\n",
         file_name);
    return;
  }
  size = GNUNET_snprintf (output_buffer,
                          sizeof (output_buffer),
                          "%llu %s\n",
                          GNUNET_TIME_absolute_get ().abs_value_us,
                          line);
  if (0 > size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to write string to buffer (size: %i)\n",
         size);
    return;
  }

  size2 = GNUNET_DISK_file_write (f, output_buffer, size);
  if (size != size2)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to write to file! (Size: %u, size2: %u)\n",
         size,
         size2);
    return;
  }

  if (GNUNET_YES != GNUNET_DISK_file_close (f))
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to close file\n");
}

char *
auth_key_to_string (struct GNUNET_CRYPTO_AuthKey auth_key)
{
  int size;
  size_t name_buf_size;
  char *end;
  char *buf;
  char *name_buf;
  size_t keylen = (sizeof (struct GNUNET_CRYPTO_AuthKey)) * 8;

  name_buf_size = 512 * sizeof (char);
  name_buf = GNUNET_malloc (name_buf_size);

  if (keylen % 5 > 0)
    keylen += 5 - keylen % 5;
  keylen /= 5;
  buf = GNUNET_malloc (keylen + 1);

  end = GNUNET_STRINGS_data_to_string (&(auth_key.key),
      sizeof (struct GNUNET_CRYPTO_AuthKey),
      buf,
      keylen);

  if (NULL == end)
  {
    GNUNET_free (buf);
    GNUNET_break (0);
  }
  else
  {
    *end = '\0';
  }

  size = GNUNET_snprintf (name_buf, name_buf_size, "sampler_el-%s-", buf);
  if (0 > size)
    LOG (GNUNET_ERROR_TYPE_WARNING, "Failed to create name_buf\n");

  GNUNET_free (buf);

  return name_buf;
}

char *
create_file (const char *name)
{
  int size;
  size_t name_buf_size;
  char *name_buf;
  char *prefix;
  char *file_name;

  prefix = "/tmp/rps/";
  name_buf_size = (strlen (prefix) + strlen (name) + 2) * sizeof (char);
  name_buf = GNUNET_malloc (name_buf_size);

  size = GNUNET_snprintf (name_buf, name_buf_size, "%s%s-", prefix, name);
  if (0 > size)
    LOG (GNUNET_ERROR_TYPE_WARNING, "Failed to create name_buf\n");

  GNUNET_DISK_directory_create (prefix);

  file_name = GNUNET_malloc (strlen (name_buf) + 6);

  if (NULL == (file_name = GNUNET_DISK_mktemp (name_buf)))
        LOG (GNUNET_ERROR_TYPE_WARNING, "Could not create file\n");

  GNUNET_free (name_buf);

  return file_name;
}

#endif /* TO_FILE */

/* end of gnunet-service-rps.c */
