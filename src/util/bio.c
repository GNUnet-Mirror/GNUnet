/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2013 GNUnet e.V.

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
 * @file util/bio.c
 * @brief functions for buffering IO
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util-bio", __VA_ARGS__)

#ifndef PATH_MAX
/**
 * Assumed maximum path length (for source file names).
 */
#define PATH_MAX 4096
#endif


/**
 * Size for I/O buffers.
 */
#define BIO_BUFFER_SIZE 65536

/**
 * Maximum size allowed for meta data written/read from disk.
 * File-sharing limits to 64k, so this should be rather generous.
 */
#define MAX_META_DATA (1024 * 1024)


/**
 * Enum used internally to know how buffering is handled.
 *
 * The idea is that by using an enum, BIO can be extended to support other
 * kinds of "backend" for buffering (or just formatted I/O.)
 */
enum IOType
{
  /**
   * The handle uses a file to read/write data.
   */
  IO_FILE = 0,

  /**
   * The data is stored entirely in memory.
   */
  IO_BUFFER,
};


/**
 * Handle for buffered reading.
 */
struct GNUNET_BIO_ReadHandle
{
  /**
   * The "backend" type.
   */
  enum IOType type;

  /**
   * Handle to a file on disk, if @e type is #IO_FILE.
   */
  struct GNUNET_DISK_FileHandle *fd;

  /**
   * Error message, NULL if there were no errors.
   */
  char *emsg;

  /**
   * I/O buffer.  Do @b not free!
   */
  char *buffer;

  /**
   * Number of bytes available in @e buffer.
   */
  size_t have;

  /**
   * Total size of @e buffer.
   */
  size_t size;

  /**
   * Current read offset in @e buffer.
   */
  off_t pos;
};


/**
 * Open a file for reading.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_ReadHandle *
GNUNET_BIO_read_open_file (const char *fn)
{
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_BIO_ReadHandle *h;

  fd = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_NONE);
  if (NULL == fd)
    return NULL;
  h = GNUNET_malloc (sizeof(struct GNUNET_BIO_ReadHandle) + BIO_BUFFER_SIZE);
  h->type = IO_FILE;
  h->buffer = (char *) &h[1];
  h->size = BIO_BUFFER_SIZE;
  h->fd = fd;
  return h;
}


/**
 * Create a handle from an existing allocated buffer.
 *
 * @param buffer the buffer to use as source
 * @param size the total size in bytes of the buffer
 * @return IO handle on sucess, NULL on error
 */
struct GNUNET_BIO_ReadHandle *
GNUNET_BIO_read_open_buffer (void *buffer, size_t size)
{
  struct GNUNET_BIO_ReadHandle *h;

  h = GNUNET_new (struct GNUNET_BIO_ReadHandle);
  h->type = IO_BUFFER;
  h->buffer = buffer;
  h->size = size;
  return h;
}


/**
 * Close an open handle.  Reports if any errors reading
 * from the file were encountered.
 *
 * @param h file handle
 * @param emsg set to the (allocated) error message
 *        if the handle has an error message, the return value is #GNUNET_SYSERR
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_read_close (struct GNUNET_BIO_ReadHandle *h, char **emsg)
{
  int err;

  err = (NULL == h->emsg) ? GNUNET_OK : GNUNET_SYSERR;
  if (NULL != emsg)
    *emsg = h->emsg;
  else
    GNUNET_free_non_null (h->emsg);
  switch (h->type)
  {
  case IO_FILE:
    GNUNET_DISK_file_close (h->fd);
    break;
  case IO_BUFFER:
    break;
  default:
    break;
  }
  GNUNET_free (h);
  return err;
}


/**
 * Function used internally to read the contents of a file into a buffer.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to write the data to
 * @param len the number of bytes to read
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
read_from_file (struct GNUNET_BIO_ReadHandle *h,
                const char *what,
                char *result,
                size_t len)
{
  size_t pos = 0;
  size_t min;
  ssize_t ret;

  do
  {
    min = h->have - h->pos;
    if (0 < min)
    {
      if (len - pos < min)
        min = len - pos;
      GNUNET_memcpy (&result[pos], &h->buffer[h->pos], min);
      h->pos += min;
      pos += min;
    }
    if (len == pos)
      return GNUNET_OK;
    GNUNET_assert (((off_t) h->have) == h->pos);
    ret = GNUNET_DISK_file_read (h->fd, h->buffer, h->size);
    if (-1 == ret)
    {
      GNUNET_asprintf (&h->emsg,
                       _ ("Error reading `%s' from file: %s"),
                       what,
                       strerror (errno));
      return GNUNET_SYSERR;
    }
    if (0 == ret)
    {
      GNUNET_asprintf (&h->emsg,
                       _ ("Error reading `%s' from file: %s"),
                       what,
                       _ ("End of file"));
      return GNUNET_SYSERR;
    }
    h->pos = 0;
    h->have = ret;
  }
  while (pos < len);
  return GNUNET_OK;
}


/**
 * Function used internally to read the content of a buffer into a buffer.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to write the result to
 * @param len the number of bytes to read
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
read_from_buffer (struct GNUNET_BIO_ReadHandle *h,
                  const char *what,
                  char *result,
                  size_t len)
{
  if (h->size < len || h->size - h->pos < len)
  {
    GNUNET_asprintf (&h->emsg,
                     _ ("Error while reading `%s' from buffer: %s"),
                     what,
                     _ ("Not enough data left"));
    return GNUNET_SYSERR;
  }
  GNUNET_memcpy (result, h->buffer + h->pos, len);
  h->pos += len;
  return GNUNET_OK;
}


/**
 * Read some contents into a buffer.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to write the result to
 * @param len the number of bytes to read
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read (struct GNUNET_BIO_ReadHandle *h,
                 const char *what,
                 void *result,
                 size_t len)
{
  char *dst = result;

  if (NULL != h->emsg)
    return GNUNET_SYSERR;

  if (0 == len)
    return GNUNET_OK;

  switch (h->type)
  {
  case IO_FILE:
    return read_from_file (h, what, dst, len);
  case IO_BUFFER:
    return read_from_buffer (h, what, dst, len);
  default:
    GNUNET_asprintf (&h->emsg,
                     _ ("Invalid handle type while reading `%s'"),
                     what);
    return GNUNET_SYSERR;
  }
}


/**
 * Read 0-terminated string.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param result where to store the pointer to the (allocated) string
 *        (note that *result could be set to NULL as well)
 * @param max_length maximum allowed length for the string
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read_string (struct GNUNET_BIO_ReadHandle *h,
                        const char *what,
                        char **result,
                        size_t max_length)
{
  char *buf;
  uint32_t big;

  if (GNUNET_OK != GNUNET_BIO_read_int32 (h,
                                          _ ("string length"),
                                          (int32_t *) &big))
  {
    char *tmp = h->emsg;
    if (NULL != tmp)
      GNUNET_asprintf (&h->emsg,
                       _ ("%s (while reading `%s')"),
                       tmp,
                       what);
    else
      GNUNET_asprintf (&h->emsg,
                       _ ("Error reading length of string `%s'"),
                       what);
    GNUNET_free_non_null (tmp);
    return GNUNET_SYSERR;
  }
  if (0 == big)
  {
    *result = NULL;
    return GNUNET_OK;
  }
  if (big > max_length)
  {
    GNUNET_asprintf (&h->emsg,
                     _ ("String `%s' longer than allowed (%u > %u)"),
                     what,
                     big,
                     max_length);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (big);
  *result = buf;
  buf[--big] = '\0';
  if (0 == big)
    return GNUNET_OK;
  if (GNUNET_OK != GNUNET_BIO_read (h, what, buf, big))
  {
    GNUNET_free (buf);
    *result = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Read a metadata container.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read_meta_data (struct GNUNET_BIO_ReadHandle *h,
                           const char *what,
                           struct GNUNET_CONTAINER_MetaData **result)
{
  uint32_t size;
  char *buf;
  struct GNUNET_CONTAINER_MetaData *meta;

  if (GNUNET_OK != GNUNET_BIO_read_int32 (h,
                                          _ ("metadata length"),
                                          (int32_t *) &size))
    return GNUNET_SYSERR;
  if (0 == size)
  {
    *result = NULL;
    return GNUNET_OK;
  }
  if (MAX_META_DATA < size)
  {
    GNUNET_asprintf (
      &h->emsg,
      _ ("Serialized metadata `%s' larger than allowed (%u > %u)"),
      what,
      size,
      MAX_META_DATA);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (size);
  if (GNUNET_OK != GNUNET_BIO_read (h, what, buf, size))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  meta = GNUNET_CONTAINER_meta_data_deserialize (buf, size);
  if (NULL == meta)
  {
    GNUNET_free (buf);
    GNUNET_asprintf (&h->emsg, _ ("Failed to deserialize metadata `%s'"), what);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  *result = meta;
  return GNUNET_OK;
}

/**
 * Read a float.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param f address of float to read
 */
int
GNUNET_BIO_read_float(struct GNUNET_BIO_ReadHandle *h,
                      const char *what,
                      float *f)
{
  int32_t *i = (int32_t *) f;
  return GNUNET_BIO_read_int32 (h, what, i);
}


/**
 * Read a double.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param f address of double to read
 */
int
GNUNET_BIO_read_double(struct GNUNET_BIO_ReadHandle *h,
                       const char *what,
                       double *f)
{
  int64_t *i = (int64_t *) f;
  return GNUNET_BIO_read_int64 (h, what, i);
}


/**
 * Read an (u)int32_t.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param i where to store the data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_read_int32 (struct GNUNET_BIO_ReadHandle *h,
                       const char *what,
                       int32_t *i)
{
  int32_t big;

  if (GNUNET_OK != GNUNET_BIO_read (h, what, &big, sizeof(int32_t)))
    return GNUNET_SYSERR;
  *i = ntohl (big);
  return GNUNET_OK;
}


/**
 * Read an (u)int64_t.
 *
 * @param h the IO handle to read from
 * @param what describes what is being read (for error message creation)
 * @param i where to store the data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_read_int64 (struct GNUNET_BIO_ReadHandle *h,
                       const char *what,
                       int64_t *i)
{
  int64_t big;

  if (GNUNET_OK != GNUNET_BIO_read (h, what, &big, sizeof(int64_t)))
    return GNUNET_SYSERR;
  *i = GNUNET_ntohll (big);
  return GNUNET_OK;
}


/**
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle
{
  /**
   * The "backend" type.
   */
  enum IOType type;

  /**
   * Handle to a file on disk, if @e type is #IO_FILE.
   */
  struct GNUNET_DISK_FileHandle *fd;

  /**
   * Error message, NULL if there were no errors.
   */
  char *emsg;

  /**
   * I/O buffer.
   * This field is a void * because it is used to hold pointers to allocated
   * structures or arrays and will be casted to the appropriate type.
   */
  void *buffer;

  /**
   * Number of bytes available in @e buffer.
   */
  size_t have;

  /**
   * Total size of @e buffer.
   */
  size_t size;
};


/**
 * Open a file for writing.
 *
 * @param fn name of the file to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *
GNUNET_BIO_write_open_file (const char *fn)
{
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_BIO_WriteHandle *h;

  fd =
    GNUNET_DISK_file_open (fn,
                           GNUNET_DISK_OPEN_WRITE
                           | GNUNET_DISK_OPEN_TRUNCATE
                           | GNUNET_DISK_OPEN_CREATE,
                           GNUNET_DISK_PERM_USER_READ
                           | GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == fd)
    return NULL;
  h = GNUNET_malloc (sizeof(struct GNUNET_BIO_WriteHandle) + BIO_BUFFER_SIZE);
  h->buffer = &h[1];
  h->size = BIO_BUFFER_SIZE;
  h->fd = fd;
  return h;
}


/**
 * Create a handle backed by an in-memory buffer.
 *
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *
GNUNET_BIO_write_open_buffer (void)
{
  struct GNUNET_BIO_WriteHandle *h;

  h = GNUNET_new (struct GNUNET_BIO_WriteHandle);
  h->type = IO_BUFFER;
  h->buffer = (void *) GNUNET_malloc (sizeof (struct GNUNET_Buffer));
  return h;
}


/**
 * Close an IO handle.
 * If the handle was using a file, the file will be closed.
 *
 * @param h file handle
 * @param emsg set to the (allocated) error message
 *        if the handle has an error message, the return value is #GNUNET_SYSERR
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_write_close (struct GNUNET_BIO_WriteHandle *h, char **emsg)
{
  int err;

  err = (NULL == h->emsg) ? GNUNET_OK : GNUNET_SYSERR;
  if (NULL != emsg)
    *emsg = h->emsg;
  else
    GNUNET_free_non_null (h->emsg);
  switch (h->type)
  {
  case IO_FILE:
    if (NULL == h->fd)
      return GNUNET_SYSERR;
    if (GNUNET_OK != GNUNET_BIO_flush (h))
    {
      if (NULL != emsg)
        *emsg = h->emsg;
      else
        GNUNET_free_non_null (h->emsg);
      err = GNUNET_SYSERR;
    }
    else
    {
      GNUNET_DISK_file_close (h->fd);
    }
    break;
  case IO_BUFFER:
    GNUNET_buffer_clear ((struct GNUNET_Buffer *) h->buffer);
    GNUNET_free (h->buffer);
    break;
  }
  GNUNET_free (h);
  return err;
}


/**
 * Force a file-based buffered writer to flush its buffer.
 * If the handle does not use a file, this function returs #GNUNET_OK
 * without doing anything.
 *
 * @param h the IO handle
 * @return #GNUNET_OK upon success.  Upon failure #GNUNET_SYSERR is returned
 *         and the file is closed
 */
int
GNUNET_BIO_flush (struct GNUNET_BIO_WriteHandle *h)
{
  ssize_t ret;

  if (IO_FILE != h->type)
    return GNUNET_OK;

  ret = GNUNET_DISK_file_write (h->fd, h->buffer, h->have);
  if (ret != (ssize_t) h->have)
  {
    GNUNET_DISK_file_close (h->fd);
    h->fd = NULL;
    GNUNET_free_non_null (h->emsg);
    GNUNET_asprintf (&h->emsg, _ ("Unable to flush buffer to file"));
    return GNUNET_SYSERR;
  }
  h->have = 0;
  return GNUNET_OK;
}


/**
 * Get the IO handle's contents.
 * If the handle doesn't use an in-memory buffer, this function returns
 * #GNUNET_SYSERR.
 *
 * @param h the IO handle
 * @param emsg set to the (allocated) error message
 *        if the handle has an error message the return value is #GNUNET_SYSERR
 * @param contents where to store the pointer to the handle's contents
 * @param size where to store the size of @e contents
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_get_buffer_contents (struct GNUNET_BIO_WriteHandle *h,
                                char **emsg,
                                void **contents,
                                size_t *size)
{
  if (IO_BUFFER != h->type)
    return GNUNET_SYSERR;
  if (NULL == contents || NULL == size)
    return GNUNET_SYSERR;
  int ret = (NULL != h->emsg) ? GNUNET_SYSERR : GNUNET_OK;
  if (NULL != emsg)
    *emsg = h->emsg;
  else
    GNUNET_free_non_null (h->emsg);
  *contents = GNUNET_buffer_reap ((struct GNUNET_Buffer *) h->buffer, size);
  return ret;
}


/**
 * Function used internally to write the contents of a buffer into a file.
 *
 * @param h the IO handle to write to
 * @param what describes what is being written (for error message creation)
 * @param source the buffer to write
 * @param len the number of bytes to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_to_file (struct GNUNET_BIO_WriteHandle *h,
               const char *what,
               const char *source,
               size_t len)
{
  size_t min;
  size_t pos = 0;
  char *buffer = (char *) h->buffer;

  if (NULL == h->fd)
  {
    GNUNET_asprintf (&h->emsg,
                     _ ("Error while writing `%s' to file: %s"),
                     what,
                     _ ("No associated file"));
    return GNUNET_SYSERR;
  }

  do
  {
    min = h->size - h->have;
    if (len - pos < min)
      min = len - pos;
    GNUNET_memcpy (&buffer[h->have], &source[pos], min);
    pos += min;
    h->have += min;
    if (len == pos)
      return GNUNET_OK;
    GNUNET_assert (h->have == h->size);
    if (GNUNET_OK != GNUNET_BIO_flush (h))
    {
      char *tmp = h->emsg;
      GNUNET_asprintf (&h->emsg,
                       _ ("Error while writing `%s' to file: %s"),
                       what,
                       tmp);
      GNUNET_free_non_null (tmp);
      return GNUNET_SYSERR;
    }
  }
  while (pos < len);
  GNUNET_break (0);
  return GNUNET_OK;
}


/**
 * Function used internally to write the contents of a buffer to another buffer.
 *
 * @param h the IO handle to write to
 * @param what describes what is being written (for error message creation)
 * @param source the buffer to write
 * @param len the number of bytes to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_to_buffer (struct GNUNET_BIO_WriteHandle *h,
                 const char *what,
                 const char *source,
                 size_t len)
{
  GNUNET_buffer_write ((struct GNUNET_Buffer *) h->buffer, source, len);
  h->have += len;
  return GNUNET_OK;
}


/**
 * Write a buffer to a handle.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write (struct GNUNET_BIO_WriteHandle *h,
                  const char *what,
                  const void *buffer,
                  size_t n)
{
  const char *src = buffer;

  if (NULL != h->emsg)
    return GNUNET_SYSERR;

  if (0 == n)
    return GNUNET_OK;

  switch (h->type)
  {
  case IO_FILE:
    return write_to_file (h, what, src, n);
  case IO_BUFFER:
    return write_to_buffer (h, what, src, n);
  default:
    GNUNET_asprintf (&h->emsg,
                     _ ("Invalid handle type while writing `%s'"),
                     what);
    return GNUNET_SYSERR;
  }
}


/**
 * Write a 0-terminated string.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param s string to write (can be NULL)
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_string (struct GNUNET_BIO_WriteHandle *h,
                         const char *what,
                         const char *s)
{
  uint32_t slen;

  slen = (uint32_t) ((s == NULL) ? 0 : strlen (s) + 1);
  if (GNUNET_OK != GNUNET_BIO_write_int32 (h, _ ("string length"), slen))
    return GNUNET_SYSERR;
  if (0 != slen)
    return GNUNET_BIO_write (h, what, s, slen - 1);
  return GNUNET_OK;
}


/**
 * Write a metadata container.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param m metadata to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_meta_data (struct GNUNET_BIO_WriteHandle *h,
                            const char *what,
                            const struct GNUNET_CONTAINER_MetaData *m)
{
  ssize_t size;
  char *buf;

  if (m == NULL)
    return GNUNET_BIO_write_int32 (h, _ ("metadata length"), 0);
  buf = NULL;
  size = GNUNET_CONTAINER_meta_data_serialize (
    m,
    &buf,
    MAX_META_DATA,
    GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (-1 == size)
  {
    GNUNET_free (buf);
    GNUNET_free_non_null (h->emsg);
    GNUNET_asprintf (&h->emsg,
                     _ ("Failed to serialize metadata `%s'"),
                     what);
    return GNUNET_SYSERR;
  }
  if ((GNUNET_OK != GNUNET_BIO_write_int32 (h,
                                            _ ("metadata length"),
                                            (uint32_t) size))
      || (GNUNET_OK != GNUNET_BIO_write (h, what, buf, size)))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Write a float.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param f float to write
 */
int
GNUNET_BIO_write_float(struct GNUNET_BIO_WriteHandle *h,
                       const char *what,
                       float f)
{
  int32_t i = f;
  return GNUNET_BIO_write_int32 (h, what, i);
}


/**
 * Write a double.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param f double to write
 */
int
GNUNET_BIO_write_double(struct GNUNET_BIO_WriteHandle *h,
                        const char *what,
                        double f)
{
  int64_t i = f;
  return GNUNET_BIO_write_int64 (h, what, i);
}


/**
 * Write an (u)int32_t.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param i 32-bit integer to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_int32 (struct GNUNET_BIO_WriteHandle *h,
                        const char *what,
                        int32_t i)
{
  int32_t big;

  big = htonl (i);
  return GNUNET_BIO_write (h, what, &big, sizeof(int32_t));
}


/**
 * Write an (u)int64_t.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param i 64-bit integer to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_int64 (struct GNUNET_BIO_WriteHandle *h,
                        const char *what,
                        int64_t i)
{
  int64_t big;

  big = GNUNET_htonll (i);
  return GNUNET_BIO_write (h, what, &big, sizeof(int64_t));
}


/**
 * Function used internally to read some bytes from within a read spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size how many bytes to read
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
read_spec_handler_object (void *cls,
                          struct GNUNET_BIO_ReadHandle *h,
                          const char *what,
                          void *target,
                          size_t target_size)
{
  return GNUNET_BIO_read (h, what, target, target_size);
}


/**
 * Create the specification to read a certain amount of bytes.
 *
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to write the result to
 * @param len the number of bytes to read
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_object (const char *what,
                             void *result,
                             size_t len)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_object,
    .cls = NULL,
    .what = what,
    .target = result,
    .size = len,
  };

  return rs;
}


/**
 * Function used interally to read a string from within a read spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size how many bytes to read
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
read_spec_handler_string (void *cls,
                          struct GNUNET_BIO_ReadHandle *h,
                          const char *what,
                          void *target,
                          size_t target_size)
{
  char **result = target;
  return GNUNET_BIO_read_string (h, what, result, target_size);
}


/**
 * Create the specification to read a 0-terminated string.
 *
 * @param what describes what is being read (for error message creation)
 * @param result where to store the pointer to the (allocated) string
 *        (note that *result could be set to NULL as well)
 * @param max_length maximum allowed length for the string
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_string (const char *what,
                             char **result,
                             size_t max_length)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_string,
    .cls = NULL,
    .target = result,
    .size = max_length,
  };

  return rs;
}


/**
 * Function used internally to read a metadata container from within a read
 * spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
read_spec_handler_meta_data (void *cls,
                             struct GNUNET_BIO_ReadHandle *h,
                             const char *what,
                             void *target,
                             size_t target_size)
{
  struct GNUNET_CONTAINER_MetaData **result = target;
  return GNUNET_BIO_read_meta_data (h, what, result);
}


/**
 * Create the specification to read a metadata container.
 *
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_meta_data (const char *what,
                                struct GNUNET_CONTAINER_MetaData **result)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_meta_data,
    .cls = NULL,
    .target = result,
    .size = 0,
  };

  return rs;
}


/**
 * Function used internally to read an (u)int32_t from within a read spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size ignored
 * @retun #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
read_spec_handler_int32 (void *cls,
                         struct GNUNET_BIO_ReadHandle *h,
                         const char *what,
                         void *target,
                         size_t target_size)
{
  int32_t *result = target;
  return GNUNET_BIO_read_int32 (h, what, result);
}


/**
 * Create the specification to read an (u)int32_t.
 *
 * @param what describes what is being read (for error message creation)
 * @param i where to store the data
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_int32 (const char *what,
                            int32_t *i)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_int32,
    .cls = NULL,
    .target = i,
    .size = 0,
  };

  return rs;
}


/**
 * Function used internally to read an (u)int64_t from within a read spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size ignored
 * @retun #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
read_spec_handler_int64 (void *cls,
                         struct GNUNET_BIO_ReadHandle *h,
                         const char *what,
                         void *target,
                         size_t target_size)
{
  int64_t *result = target;
  return GNUNET_BIO_read_int64 (h, what, result);
}


/**
 * Create the specification to read an (u)int64_t.
 *
 * @param what describes what is being read (for error message creation)
 * @param i where to store the data
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_int64 (const char *what,
                            int64_t *i)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_int64,
    .cls = NULL,
    .target = i,
    .size = 0,
  };

  return rs;
}


/**
 * Create the specification to read a float.
 *
 * @param what describes what is being read (for error message creation)
 * @param f address of float to read
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_float(const char *what, float *f)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_int32,
    .cls = NULL,
    .target = (int32_t *) f,
    .size = 0,
  };

  return rs;
}


/**
 * Create the specification to read a double.
 *
 * @param what describes what is being read (for error message creation)
 * @param f address of double to read
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_double(const char *what, double *f)
{
  struct GNUNET_BIO_ReadSpec rs = {
    .rh = &read_spec_handler_int64,
    .cls = NULL,
    .target = (int64_t *) f,
    .size = 0,
  };

  return rs;
}


/**
 * Execute the read specifications in order.
 *
 * @param h the IO handle to read from
 * @param rs array of read specs
 *        the last element must be #GNUNET_BIO_read_spec_end
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_read_spec_commit (struct GNUNET_BIO_ReadHandle *h,
                             struct GNUNET_BIO_ReadSpec *rs)
{
  int ret = GNUNET_OK;

  for (size_t i=0; NULL!=rs[i].rh; ++i)
  {
    ret = rs[i].rh (rs[i].cls, h, rs[i].what, rs[i].target, rs[i].size);
    if (GNUNET_OK != ret)
      return ret;
  }

  return ret;
}


/**
 * Function used internally to write some bytes from within a write spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size how many bytes to write
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_spec_handler_object (void *cls,
                           struct GNUNET_BIO_WriteHandle *h,
                           const char *what,
                           void *source,
                           size_t source_size)
{
  return GNUNET_BIO_write (h, what, source, source_size);
}


/**
 * Create the specification to read some bytes.
 *
 * @param what describes what is being written (for error message creation)
 * @param source the data to write
 * @param size how many bytes should be written
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_object (const char *what,
                              void *source,
                              size_t size)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_object,
    .cls = NULL,
    .what = what,
    .source = source,
    .source_size = size,
  };

  return ws;
}


/**
 * Function used internally to write a 0-terminated string from within a write
 * spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_spec_handler_string (void *cls,
                           struct GNUNET_BIO_WriteHandle *h,
                           const char *what,
                           void *source,
                           size_t source_size)
{
  const char *s = source;
  return GNUNET_BIO_write_string (h, what, s);
}


/**
 * Create the specification to write a 0-terminated string.
 *
 * @param what describes what is being read (for error message creation)
 * @param s string to write (can be NULL)
 * @return the read spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_string (const char *what,
                              const char *s)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_string,
    .cls = NULL,
    .what = what,
    .source = (void *) s,
    .source_size = 0,
  };

  return ws;
}


/**
 * Function used internally to write a metadata container from within a write
 * spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_spec_handler_meta_data (void *cls,
                              struct GNUNET_BIO_WriteHandle *h,
                              const char *what,
                              void *source,
                              size_t source_size)
{
  const struct GNUNET_CONTAINER_MetaData *m = source;
  return GNUNET_BIO_write_meta_data (h, what, m);
}


/**
 * Create the specification to write a metadata container.
 *
 * @param what what is being written (for error message creation)
 * @param m metadata to write
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_meta_data (const char *what,
                                 const struct GNUNET_CONTAINER_MetaData *m)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_meta_data,
    .cls = NULL,
    .what = what,
    .source = (void *) m,
    .source_size = 0,
  };

  return ws;
}


/**
 * Function used internally to write an (u)int32_t from within a write spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_spec_handler_int32 (void *cls,
                          struct GNUNET_BIO_WriteHandle *h,
                          const char *what,
                          void *source,
                          size_t source_size)
{
  int32_t i = *(int32_t *) source;
  return GNUNET_BIO_write_int32 (h, what, i);
}


/**
 * Create the specification to write an (u)int32_t.
 *
 * @param what describes what is being written (for error message creation)
 * @param i pointer to a 32-bit integer
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_int32 (const char *what,
                             int32_t *i)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_int32,
    .cls = NULL,
    .what = what,
    .source = i,
    .source_size = 0,
  };

  return ws;
}


/**
 * Function used internally to write an (u)int64_t from within a write spec.
 *
 * @param cls ignored, always NULL
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size ignored
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
write_spec_handler_int64 (void *cls,
                          struct GNUNET_BIO_WriteHandle *h,
                          const char *what,
                          void *source,
                          size_t source_size)
{
  int64_t i = *(int64_t *) source;
  return GNUNET_BIO_write_int64 (h, what, i);
}


/**
 * Create the specification to write an (u)int64_t.
 *
 * @param what describes what is being written (for error message creation)
 * @param i pointer to a 64-bit integer
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_int64 (const char *what,
                             int64_t *i)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_int64,
    .cls = NULL,
    .what = what,
    .source = i,
    .source_size = 0,
  };

  return ws;
}


/**
 * Create the specification to write a float.
 *
 * @param what describes what is being written (for error message creation)
 * @param f pointer to a float
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_float(const char *what, float *f)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_int32,
    .cls = NULL,
    .what = what,
    .source = (int32_t *) f,
    .source_size = 0,
  };

  return ws;
}


/**
 * Create the specification to write an double.
 *
 * @param what describes what is being written (for error message creation)
 * @param f pointer to a double
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_double(const char *what, double *f)
{
  struct GNUNET_BIO_WriteSpec ws = {
    .wh = &write_spec_handler_int64,
    .cls = NULL,
    .what = what,
    .source = (int64_t *) f,
    .source_size = 0,
  };

  return ws;
}


/**
 * Execute the write specifications in order.
 *
 * @param h the IO handle to write to
 * @param ws array of write specs
 *        the last element must be #GNUNET_BIO_write_spec_end
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_write_spec_commit (struct GNUNET_BIO_WriteHandle *h,
                              struct GNUNET_BIO_WriteSpec *ws)
{
  int ret = GNUNET_OK;

  for (size_t i=0; NULL!=ws[i].wh; ++i)
  {
    ret = ws[i].wh (ws[i].cls, h, ws[i].what, ws[i].source, ws[i].source_size);
    if (GNUNET_OK != ret)
      return ret;
  }

  /* If it's a file-based handle, the flush makes sure that the data in the
     buffer is actualy written to the disk. */
  if (IO_FILE == h->type)
    ret = GNUNET_BIO_flush (h);

  return ret;
}


/* end of bio.c */
