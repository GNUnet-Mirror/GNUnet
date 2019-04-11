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

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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
#include "rps-test_util.h"

#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log_from(kind,"rps-test_util",__VA_ARGS__)

#define B2B_PAT "%c%c%c%c%c%c%c%c"
#define B2B(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')

#ifdef TO_FILE


/**
 * @brief buffer for storing the unaligned bits for the next write
 */
static char buf_unaligned;

/**
 * @brief number of bits in unaligned buffer
 */
static unsigned num_bits_buf_unaligned;

static struct GNUNET_CONTAINER_MultiHashMap *open_files;



/**
 * @brief Get file handle
 *
 * If necessary, create file handle and store it with the other file handles.
 *
 * @param name Name of the file
 *
 * @return File handle
 */
struct GNUNET_DISK_FileHandle *
get_file_handle (const char *name)
{
  struct GNUNET_HashCode hash;
  struct GNUNET_DISK_FileHandle *fh;

  if (NULL == open_files)
  {
    open_files = GNUNET_CONTAINER_multihashmap_create (16,
						       GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Created map of open files.\n");
  }
  GNUNET_CRYPTO_hash (name,
                      strlen (name),
                      &hash);
  if (NULL != (fh = GNUNET_CONTAINER_multihashmap_get (open_files,
						       &hash)))
    return fh;
  fh = GNUNET_DISK_file_open (name,
			      GNUNET_DISK_OPEN_WRITE |
			      GNUNET_DISK_OPEN_CREATE |
			      GNUNET_DISK_OPEN_APPEND,
			      GNUNET_DISK_PERM_USER_READ |
			      GNUNET_DISK_PERM_USER_WRITE |
			      GNUNET_DISK_PERM_GROUP_READ);
  if (NULL == fh)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 "Opening file `%s' failed.\n",
	 name);
    GNUNET_assert (0);
  }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_put (open_files,
						    &hash,
						    fh,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return fh;
}


/**
 * @brief Closes the file of the current entry
 *
 * Implements #GNUNET_CONTAINER_HashMapIterator
 *
 * @param cls unused
 * @param key unused
 * @param value the file handle
 *
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
int
close_files_iter (void *cls,
                  const struct GNUNET_HashCode *key,
                  void *value)
{
  (void) cls;
  (void) key;
  struct GNUNET_DISK_FileHandle *fh = value;

  if (NULL != fh)
  {
    GNUNET_DISK_file_close (fh);
  }
  return GNUNET_YES;
}


/**
 * @brief Close all files that were opened with #get_file_handle
 *
 * @return Success of iterating over files
 */
int
close_all_files ()
{
  int ret;

  ret = GNUNET_CONTAINER_multihashmap_iterate (open_files,
                                               close_files_iter,
                                               NULL);
  GNUNET_CONTAINER_multihashmap_destroy (open_files);
  open_files = NULL;
  return ret;
}



void
to_file_raw (const char *file_name, const char *buf, size_t size_buf)
{
  struct GNUNET_DISK_FileHandle *f;
  size_t size_written;

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

  size_written = GNUNET_DISK_file_write (f, buf, size_buf);
  if (size_buf != size_written)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to write to file! (Size: %u, size_written: %u)\n",
         size_buf,
         size_written);

    if (GNUNET_YES != GNUNET_DISK_file_close (f))
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Unable to close file\n");

    return;
  }
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Wrote %u bytes raw.\n",
       size_written);
  if (GNUNET_YES != GNUNET_DISK_file_close (f))
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unable to close file\n");
}

void
to_file_raw_unaligned (const char *file_name,
                       const char *buf,
                       size_t size_buf,
                       unsigned bits_needed)
{
  // TODO endianness!
  GNUNET_assert (size_buf >= (bits_needed/8));
  //if (0 == num_bits_buf_unaligned)
  //{
  //  if (0 == (bits_needed % 8))
  //  {
  //    to_file_raw (file_name, buf, size_buf);
  //    return;
  //  }
  //  to_file_raw (file_name, buf, size_buf - 1);
  //  buf_unaligned = buf[size_buf - 1];
  //  num_bits_buf_unaligned = bits_needed % 8;
  //  return;
  //}
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Was asked to write %u bits\n", bits_needed);

  char buf_write[size_buf + 1];
  const unsigned bytes_iter = (0 != bits_needed % 8?
                               (bits_needed/8)+1:
                               bits_needed/8);
  // TODO what if no iteration happens?
  unsigned size_buf_write = 0;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "num_bits_buf_unaligned: %u\n",
       num_bits_buf_unaligned);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "ua args: size_buf: %u, bits_needed: %u -> iter: %u\n",
       size_buf,
       bits_needed,
       bytes_iter);
  buf_write[0] = buf_unaligned;
  /* Iterate over input bytes */
  for (unsigned i = 0; i < bytes_iter; i++)
  {
    /* Number of bits needed in this iteration - 8 for all except last iter */
    unsigned num_bits_needed_iter;
    /* Mask for bits to actually use */
    unsigned mask_bits_needed_iter;
    char byte_input;
    /* Number of bits needed to align unaligned byte */
    unsigned num_bits_to_align;
    /* Number of bits that are to be moved */
    unsigned num_bits_to_move;
    /* Mask for bytes to be moved */
    char mask_input_to_move;
    /* Masked bits to be moved */
    char bits_to_move;
    /* The amount of bits needed to fit the bits to shift to the nearest spot */
    unsigned distance_shift_bits;
    /* Shifted bits on the move */
    char bits_moving;
    /* (unaligned) byte being filled with bits */
    char byte_to_fill;
    /* mask for needed bits of the input byte that have not been moved */
    char mask_input_leftover;
    /* needed bits of the input byte that have not been moved */
    char byte_input_leftover;
    unsigned num_bits_leftover;
    //unsigned num_bits_discard;
    char byte_unaligned_new;

    if ( (bits_needed - (i * 8)) <= 8)
    {
      /* last iteration */
      num_bits_needed_iter = bits_needed - (i * 8);
    }
    else
    {
      num_bits_needed_iter = 8;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "number of bits needed in this iteration: %u\n",
         num_bits_needed_iter);
    mask_bits_needed_iter = ((char) 1 << num_bits_needed_iter) - 1;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "mask needed bits (current iter): "B2B_PAT"\n",
         B2B(mask_bits_needed_iter));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Unaligned byte: "B2B_PAT" (%u bits)\n",
         B2B(buf_unaligned),
         num_bits_buf_unaligned);
    byte_input = buf[i];
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "next whole input byte: "B2B_PAT"\n",
         B2B(byte_input));
    byte_input &= mask_bits_needed_iter;
    num_bits_to_align = 8 - num_bits_buf_unaligned;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "input byte, needed bits: "B2B_PAT"\n",
         B2B(byte_input));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "number of bits needed to align unaligned bit: %u\n",
         num_bits_to_align);
    num_bits_to_move  = GNUNET_MIN (num_bits_to_align, num_bits_needed_iter);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "number of bits of new byte to move: %u\n",
         num_bits_to_move);
    mask_input_to_move = ((char) 1 << num_bits_to_move) - 1;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "mask of bits of new byte to take for moving: "B2B_PAT"\n",
         B2B(mask_input_to_move));
    bits_to_move = byte_input & mask_input_to_move;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "masked bits of new byte to take for moving: "B2B_PAT"\n",
         B2B(bits_to_move));
    distance_shift_bits = num_bits_buf_unaligned;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "distance needed to shift bits to their correct spot: %u\n",
         distance_shift_bits);
    bits_moving = bits_to_move << distance_shift_bits;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "shifted, masked bits of new byte being moved: "B2B_PAT"\n",
         B2B(bits_moving));
    byte_to_fill = buf_unaligned | bits_moving;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "byte being filled: "B2B_PAT"\n",
         B2B(byte_to_fill));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "pending bytes: %u\n",
         num_bits_buf_unaligned + num_bits_needed_iter);
    if (num_bits_buf_unaligned + num_bits_needed_iter >= 8)
    {
      /* buf_unaligned was aligned by filling
       * -> can be written to storage */
      buf_write[i] = byte_to_fill;
      size_buf_write++;

      /* store the leftover, unaligned bits in buffer */
      mask_input_leftover = mask_bits_needed_iter & (~ mask_input_to_move);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "mask of leftover bits of new byte: "B2B_PAT"\n",
           B2B(mask_input_leftover));
      byte_input_leftover = byte_input & mask_input_leftover;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "masked, leftover bits of new byte: "B2B_PAT"\n",
           B2B(byte_input_leftover));
      num_bits_leftover = num_bits_needed_iter - num_bits_to_move;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "number of unaligned bits left: %u\n",
           num_bits_leftover);
      //num_bits_discard = 8 - num_bits_needed_iter;
      byte_unaligned_new = byte_input_leftover >> num_bits_to_move;
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "new unaligned byte: "B2B_PAT"\n",
           B2B(byte_unaligned_new));
      buf_unaligned = byte_unaligned_new;
      num_bits_buf_unaligned = num_bits_leftover % 8;
    }
    else
    {
      /* unaligned buffer still unaligned but 'fuller' */
      buf_unaligned = byte_to_fill;
      num_bits_buf_unaligned = (num_bits_buf_unaligned + bits_needed) % 8;
    }
  }
  to_file_raw (file_name, buf_write, size_buf_write);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
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

#endif /* TO_FILE */


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


/**
 * @brief Try to ensure that `/tmp/rps` exists.
 *
 * @return #GNUNET_YES on success
 *         #GNUNET_SYSERR on failure
 */
static int
ensure_folder_exist (void)
{
  if (GNUNET_OK !=
      GNUNET_DISK_directory_create ("/tmp/rps"))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Could not create directory `/tmp/rps'\n");
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


char *
store_prefix_file_name (const unsigned int index,
                        const char *prefix)
{
  int len_file_name;
  int out_size;
  char *file_name;
  char index_str[64];

  if (GNUNET_SYSERR == ensure_folder_exist()) return NULL;
  out_size = GNUNET_snprintf (index_str,
                              64,
                              "%u",
                              index);
  if (64 < out_size ||
      0 > out_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
               "Failed to write string to buffer (size: %i, out_size: %i)\n",
               64,
               out_size);
  }
  len_file_name = (strlen (prefix) +
                   strlen (index_str) +
                   11)
                     * sizeof (char);
  file_name = GNUNET_malloc (len_file_name);
  out_size = GNUNET_snprintf (file_name,
                              len_file_name,
                              "/tmp/rps/%s-%s",
                              prefix,
                              index_str);
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


/**
 * @brief Factorial
 *
 * @param x Number of which to compute the factorial
 *
 * @return Factorial of @a x
 */
uint32_t fac (uint32_t x)
{
  if (1 >= x)
  {
    return x;
  }
  return x * fac (x - 1);
}

/**
 * @brief Binomial coefficient (n choose k)
 *
 * @param n
 * @param k
 *
 * @return Binomial coefficient of @a n and @a k
 */
uint32_t binom (uint32_t n, uint32_t k)
{
  //GNUNET_assert (n >= k);
  if (k > n) return 0;
  /* if (0 > n) return 0;  - always false */
  /* if (0 > k) return 0;  - always false */
  if (0 == k) return 1;
  return fac (n)
    /
    fac(k) * fac(n - k);
}


/* end of gnunet-service-rps.c */
