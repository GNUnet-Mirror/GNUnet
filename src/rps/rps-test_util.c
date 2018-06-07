/*
     This file is part of GNUnet.
     Copyright (C)

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
to_file_ (const char *file_name, char *line)
{
  struct GNUNET_DISK_FileHandle *f;
  char output_buffer[512];
  size_t output_buffer_size = 512;
  char *output_buffer_p;
  //size_t size;
  int size;
  size_t size2;


  if (NULL == (f = GNUNET_DISK_file_open (file_name,
                                          GNUNET_DISK_OPEN_APPEND |
                                          GNUNET_DISK_OPEN_WRITE |
                                          GNUNET_DISK_OPEN_CREATE,
                                          GNUNET_DISK_PERM_USER_READ |
                                          GNUNET_DISK_PERM_USER_WRITE |
                                          GNUNET_DISK_PERM_GROUP_READ |
                                          GNUNET_DISK_PERM_OTHER_READ)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not able to open file %s\n",
         file_name);
    return;
  }
  output_buffer_size = strlen (line) + 18;
  if (512 < output_buffer_size)
  {
    output_buffer_p = GNUNET_malloc ((output_buffer_size) * sizeof (char));
  } else {
    output_buffer_p = &output_buffer[0];
  }
  size = GNUNET_snprintf (output_buffer_p,
                          output_buffer_size,
                          "%llu %s\n",
                          (GNUNET_TIME_absolute_get ().abs_value_us) / 1000000, // microsec -> sec
                          line);
  if (0 > size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Failed to write string to buffer (size: %i)\n",
         size);
    return;
  }

  size2 = GNUNET_DISK_file_write (f, output_buffer_p, size);
  if (size != size2)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to write to file! (Size: %u, size2: %u)\n",
         size,
         size2);

    if (GNUNET_YES != GNUNET_DISK_file_close (f))
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Unable to close file\n");

    return;
  }

  if (512 < output_buffer_size)
  {
    GNUNET_free (output_buffer_p);
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

  size = GNUNET_snprintf (name_buf, name_buf_size, "sampler_el-%s", buf);
  if (0 > size)
    LOG (GNUNET_ERROR_TYPE_WARNING, "Failed to create name_buf\n");

  GNUNET_free (buf);

  return name_buf;
}


struct GNUNET_CRYPTO_AuthKey
string_to_auth_key (const char *str)
{
  struct GNUNET_CRYPTO_AuthKey auth_key;

  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (str,
                                     strlen (str),
                                     &auth_key.key,
                                     sizeof (struct GNUNET_CRYPTO_AuthKey)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Failed to convert string to data\n");
  }

  return auth_key;
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

  size = GNUNET_snprintf (name_buf, name_buf_size, "%s%s", prefix, name);
  if (0 > size)
    LOG (GNUNET_ERROR_TYPE_WARNING, "Failed to create name_buf\n");

  if (GNUNET_YES != GNUNET_DISK_directory_create (prefix))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Could not create directory %s.\n",
         prefix);
  }

  if (NULL == strstr (name, "sampler_el"))
  {/* only append random string to sampler */
    if (NULL == (file_name = GNUNET_DISK_mktemp (name_buf)))
          LOG (GNUNET_ERROR_TYPE_WARNING, "Could not create file\n");

  GNUNET_free (name_buf);
  return file_name;
  }

  return name_buf;
}

#endif /* TO_FILE */

/**
 * @brief Try to ensure that `/tmp/rps` exists.
 *
 * @return #GNUNET_YES on success
 *         #GNUNET_SYSERR on failure
 */
static int ensure_folder_exist (void)
{
  if (GNUNET_NO == GNUNET_DISK_directory_test ("/tmp/rps/", GNUNET_NO))
  {
    GNUNET_DISK_directory_create ("/tmp/rps");
  }
  if (GNUNET_YES != GNUNET_DISK_directory_test ("/tmp/rps/", GNUNET_NO))
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}

const char *
store_prefix_file_name (const struct GNUNET_PeerIdentity *peer,
    const char *prefix)
{
  unsigned int len_file_name;
  unsigned int out_size;
  char *file_name;
  const char *pid_long;

  if (GNUNET_SYSERR == ensure_folder_exist()) return NULL;
  pid_long = GNUNET_i2s_full (peer);
  len_file_name = (strlen (prefix) +
                   strlen (pid_long) +
                   11)
                     * sizeof (char);
  file_name = GNUNET_malloc (len_file_name);
  out_size = GNUNET_snprintf (file_name,
                              len_file_name,
                              "/tmp/rps/%s-%s",
                              prefix,
                              pid_long);
  if (len_file_name < out_size ||
      0 > out_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
               "Failed to write string to buffer (size: %i, out_size: %i)\n",
               len_file_name,
               out_size);
  }
  return file_name;
}

/* end of gnunet-service-rps.c */
