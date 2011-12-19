/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/bio.c
 * @brief functions for buffering IO
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_bio_lib.h"
#include "gnunet_disk_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util",__VA_ARGS__)

#define BIO_BUFFER_SIZE 65536

#define MAX_META_DATA (1024 * 1024)

/**
 * Handle for buffered reading.
 */
struct GNUNET_BIO_ReadHandle
{
  struct GNUNET_DISK_FileHandle *fd;
  char *emsg;
  char *buffer;
  size_t have;
  size_t size;
  off_t pos;
};


/**
 * Open a file for reading.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_ReadHandle *
GNUNET_BIO_read_open (const char *fn)
{
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_BIO_ReadHandle *h;

  fd = GNUNET_DISK_file_open (fn, GNUNET_DISK_OPEN_READ, GNUNET_DISK_PERM_NONE);
  if (NULL == fd)
    return NULL;
  h = GNUNET_malloc (sizeof (struct GNUNET_BIO_ReadHandle) + BIO_BUFFER_SIZE);
  h->buffer = (char *) &h[1];
  h->size = BIO_BUFFER_SIZE;
  h->fd = fd;
  return h;
}


/**
 * Close an open file.  Reports if any errors reading
 * from the file were encountered.
 *
 * @param h file handle
 * @param emsg set to the error message
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_read_close (struct GNUNET_BIO_ReadHandle *h, char **emsg)
{
  int err;

  err = (NULL == h->emsg) ? GNUNET_OK : GNUNET_SYSERR;
  if (emsg != NULL)
    *emsg = h->emsg;
  else
    GNUNET_free_non_null (h->emsg);
  GNUNET_DISK_file_close (h->fd);
  GNUNET_free (h);
  return err;
}


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to write the result to
 * @param len the number of bytes to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read (struct GNUNET_BIO_ReadHandle *h, const char *what,
                 void *result, size_t len)
{
  char *dst = result;
  size_t min;
  size_t pos;
  ssize_t ret;

  if (h->emsg != NULL)
    return GNUNET_SYSERR;
  pos = 0;
  do
  {
    /* first, use buffer */
    min = h->have - h->pos;
    if (min > 0)
    {
      if (min > len - pos)
        min = len - pos;
      memcpy (&dst[pos], &h->buffer[h->pos], min);
      h->pos += min;
      pos += min;
    }
    if (pos == len)
      return GNUNET_OK;         /* done! */
    GNUNET_assert (h->have == h->pos);
    /* fill buffer */
    ret = GNUNET_DISK_file_read (h->fd, h->buffer, h->size);
    if (ret == -1)
    {
      GNUNET_asprintf (&h->emsg, _("Error reading `%s': %s"), what,
                       STRERROR (errno));
      return GNUNET_SYSERR;
    }
    if (ret == 0)
    {
      GNUNET_asprintf (&h->emsg, _("Error reading `%s': %s"), what,
                       _("End of file"));
      return GNUNET_SYSERR;
    }
    h->pos = 0;
    h->have = ret;
  }
  while (pos < len);            /* should always be true */
  return GNUNET_OK;
}


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param h handle to an open file
 * @param file name of the source file
 * @param line line number in the source file
 * @param result the buffer to write the result to
 * @param len the number of bytes to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read_fn (struct GNUNET_BIO_ReadHandle *h, const char *file, int line,
                    void *result, size_t len)
{
  char what[1024];

  GNUNET_snprintf (what, sizeof (what), "%s:%d", file, line);
  return GNUNET_BIO_read (h, what, result, len);
}


/**
 * Read 0-terminated string from a file.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) string to
 *        (note that *result could be set to NULL as well)
 * @param maxLen maximum allowed length for the string
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read_string (struct GNUNET_BIO_ReadHandle *h, const char *what,
                        char **result, size_t maxLen)
{
  char *buf;
  uint32_t big;

  if (GNUNET_OK != GNUNET_BIO_read_int32 (h, &big))
  {
    GNUNET_free_non_null (h->emsg);
    GNUNET_asprintf (&h->emsg, _("Error reading length of string `%s'"), what);
    return GNUNET_SYSERR;
  }
  if (big == 0)
  {
    *result = NULL;
    return GNUNET_OK;
  }
  if (big > maxLen)
  {
    GNUNET_asprintf (&h->emsg, _("String `%s' longer than allowed (%u > %u)"),
                     what, big, maxLen);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (big);
  *result = buf;
  buf[--big] = '\0';
  if (big == 0)
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
 * Read metadata container from a file.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_BIO_read_meta_data (struct GNUNET_BIO_ReadHandle *h, const char *what,
                           struct GNUNET_CONTAINER_MetaData **result)
{
  uint32_t size;
  char *buf;
  struct GNUNET_CONTAINER_MetaData *meta;

  if (GNUNET_BIO_read_int32 (h, (int32_t *) & size) != GNUNET_OK)
    return GNUNET_SYSERR;
  if (size == 0)
  {
    *result = NULL;
    return GNUNET_OK;
  }
  if (size > MAX_META_DATA)
  {
    GNUNET_asprintf (&h->emsg,
                     _("Serialized metadata `%s' larger than allowed (%u>%u)"),
                     what, size, MAX_META_DATA);
    return GNUNET_SYSERR;
  }
  buf = GNUNET_malloc (size);
  if (GNUNET_OK != GNUNET_BIO_read (h, what, buf, size))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  meta = GNUNET_CONTAINER_meta_data_deserialize (buf, size);
  if (meta == NULL)
  {
    GNUNET_free (buf);
    GNUNET_asprintf (&h->emsg, _("Metadata `%s' failed to deserialize"), what);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  *result = meta;
  return GNUNET_OK;
}


/**
 * Read an (u)int32_t.
 *
 * @param h hande to open file
 * @param file name of the source file
 * @param line line number in the source file
 * @param i address of 32-bit integer to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_read_int32__ (struct GNUNET_BIO_ReadHandle *h, const char *file,
                         int line, int32_t * i)
{
  int32_t big;

  if (GNUNET_OK != GNUNET_BIO_read_fn (h, file, line, &big, sizeof (int32_t)))
    return GNUNET_SYSERR;
  *i = ntohl (big);
  return GNUNET_OK;
}


/**
 * Read an (u)int64_t.
 *
 * @param h hande to open file
 * @param file name of the source file
 * @param line line number in the source file
 * @param i address of 64-bit integer to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_read_int64__ (struct GNUNET_BIO_ReadHandle *h, const char *file,
                         int line, int64_t * i)
{
  int64_t big;

  if (GNUNET_OK != GNUNET_BIO_read_fn (h, file, line, &big, sizeof (int64_t)))
    return GNUNET_SYSERR;
  *i = GNUNET_ntohll (big);
  return GNUNET_OK;
}


/**
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle
{
  struct GNUNET_DISK_FileHandle *fd;
  char *buffer;
  size_t have;
  size_t size;
};


/**
 * Open a file for writing.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *
GNUNET_BIO_write_open (const char *fn)
{
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_BIO_WriteHandle *h;

  fd = GNUNET_DISK_file_open (fn,
                              GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_TRUNCATE
                              | GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  if (NULL == fd)
    return NULL;
  h = GNUNET_malloc (sizeof (struct GNUNET_BIO_WriteHandle) + BIO_BUFFER_SIZE);
  h->buffer = (char *) &h[1];
  h->size = BIO_BUFFER_SIZE;
  h->fd = fd;

  return h;
}


/**
 * Close an open file for writing.
 *
 * @param h file handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_write_close (struct GNUNET_BIO_WriteHandle *h)
{
  ssize_t wrt;
  int ret;

  if (NULL == h->fd)
  {
    ret = GNUNET_SYSERR;
  }
  else
  {
    wrt = GNUNET_DISK_file_write (h->fd, h->buffer, h->have);
    if (wrt == h->have)
      ret = GNUNET_OK;
    else
      ret = GNUNET_SYSERR;
    GNUNET_DISK_file_close (h->fd);
  }
  GNUNET_free (h);
  return ret;
}


/**
 * Write a buffer to a file.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write (struct GNUNET_BIO_WriteHandle *h, const void *buffer,
                  size_t n)
{
  const char *src = buffer;
  size_t min;
  size_t pos;
  ssize_t ret;

  if (NULL == h->fd)
    return GNUNET_SYSERR;
  pos = 0;
  do
  {
    /* first, just use buffer */
    min = h->size - h->have;
    if (min > n - pos)
      min = n - pos;
    memcpy (&h->buffer[h->have], &src[pos], min);
    pos += min;
    h->have += min;
    if (pos == n)
      return GNUNET_OK;         /* done */
    GNUNET_assert (h->have == h->size);
    ret = GNUNET_DISK_file_write (h->fd, h->buffer, h->size);
    if (ret != h->size)
    {
      GNUNET_DISK_file_close (h->fd);
      h->fd = NULL;
      return GNUNET_SYSERR;     /* error */
    }
    h->have = 0;
  }
  while (pos < n);              /* should always be true */
  GNUNET_break (0);
  return GNUNET_OK;
}


/**
 * Write a string to a file.
 *
 * @param h handle to open file
 * @param s string to write (can be NULL)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_string (struct GNUNET_BIO_WriteHandle *h, const char *s)
{
  uint32_t slen;

  slen = (uint32_t) ((s == NULL) ? 0 : strlen (s) + 1);
  if (GNUNET_OK != GNUNET_BIO_write_int32 (h, slen))
    return GNUNET_SYSERR;
  if (0 != slen)
    return GNUNET_BIO_write (h, s, slen - 1);
  return GNUNET_OK;
}


/**
 * Write metadata container to a file.
 *
 * @param h handle to open file
 * @param m metadata to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_meta_data (struct GNUNET_BIO_WriteHandle *h,
                            const struct GNUNET_CONTAINER_MetaData *m)
{
  ssize_t size;
  char *buf;

  if (m == NULL)
    return GNUNET_BIO_write_int32 (h, 0);
  buf = NULL;
  size =
      GNUNET_CONTAINER_meta_data_serialize (m, &buf, MAX_META_DATA,
                                            GNUNET_CONTAINER_META_DATA_SERIALIZE_PART);
  if (size == -1)
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  if ((GNUNET_OK != GNUNET_BIO_write_int32 (h, (uint32_t) size)) ||
      (GNUNET_OK != GNUNET_BIO_write (h, buf, size)))
  {
    GNUNET_free (buf);
    return GNUNET_SYSERR;
  }
  GNUNET_free (buf);
  return GNUNET_OK;
}


/**
 * Write an (u)int32_t.
 *
 * @param h hande to open file
 * @param i 32-bit integer to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_int32 (struct GNUNET_BIO_WriteHandle *h, int32_t i)
{
  int32_t big;

  big = htonl (i);
  return GNUNET_BIO_write (h, &big, sizeof (int32_t));
}


/**
 * Write an (u)int64_t.
 *
 * @param h hande to open file
 * @param i 64-bit integer to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_int64 (struct GNUNET_BIO_WriteHandle *h, int64_t i)
{
  int64_t big;

  big = GNUNET_htonll (i);
  return GNUNET_BIO_write (h, &big, sizeof (int64_t));
}


/* end of bio.c */
