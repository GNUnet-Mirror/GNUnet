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


/**
 * Handle for buffered reading.
 */
struct GNUNET_BIO_ReadHandle
{
};


/**
 * Open a file for reading.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_ReadHandle *GNUNET_BIO_read_open (const char *fn)
{
  return NULL;
}


/**
 * Close an open file.  Reports if any errors reading
 * from the file were encountered.
 *
 * @param h file handle
 * @param emsg set to the error message
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int GNUNET_BIO_read_close (struct GNUNET_BIO_ReadHandle *h,
			   char **emsg)
{
  return GNUNET_SYSERR;
}


/**
 * Read the contents of a binary file into a buffer.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to write the result to
 * @param len the number of bytes to read
 * @return len on success, GNUNET_SYSERR on failure
 */
ssize_t GNUNET_BIO_read (struct GNUNET_BIO_ReadHandle *h, 
			 const char *what,
			 void *result, 
			 size_t len)
{
}


/**
 * Read 0-terminated string from a file.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) string to
 *        (note that *result could be set to NULL as well)
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int GNUNET_BIO_read_string (struct GNUNET_BIO_ReadHandle *h, 
			    const char *what,
			    char **result)
{
}


/**
 * Read metadata container from a file.
 *
 * @param h handle to an open file
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int GNUNET_BIO_read_meta_data (struct GNUNET_BIO_ReadHandle *h, 
			       const char *what,
			       struct GNUNET_CONTAINER_MetaData **result)
{
}


/**
 * Read an (u)int32_t.
 *
 * @param h hande to open file
 * @param what describes what is being read (for error message creation)
 * @param i address of 32-bit integer to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */ 
int GNUNET_BIO_read_int32__ (struct GNUNET_BIO_ReadHandle *h, 
			     const char *what,
			     int32_t *i);


/**
 * Read an (u)int64_t.
 *
 * @param h hande to open file
 * @param what describes what is being read (for error message creation)
 * @param i address of 64-bit integer to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */ 
int GNUNET_BIO_read_int64__ (struct GNUNET_BIO_ReadHandle *h, 
			     const char *what,
			     int64_t *i);

/**
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle
{
};


/**
 * Open a file for writing.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *GNUNET_BIO_write_open (const char *fn)
{
  return NULL;
}


/**
 * Close an open file for writing.
 *
 * @param h file handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int GNUNET_BIO_write_close (struct GNUNET_BIO_WriteHandle *h);


/**
 * Write a buffer to a file.
 *
 * @param h handle to open file
 * @param buffer the data to write
 * @param n number of bytes to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
ssize_t GNUNET_BIO_write (struct GNUNET_BIO_WriteHandle *h, 
			  const void *buffer,
			  size_t n);


/**
 * Write a string to a file.
 *
 * @param h handle to open file
 * @param s string to write (can be NULL)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_BIO_write_string (struct GNUNET_BIO_WriteHandle *h, 
			     const char *s);




/**
 * Write metadata container to a file.
 *
 * @param h handle to open file
 * @param m metadata to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_BIO_write_meta_data (struct GNUNET_BIO_WriteHandle *h, 
				const struct GNUNET_CONTAINER_MetaData *m);



/**
 * Write a float.
 *
 * @param h hande to open file
 * @param f float to write (must be a variable)
 */ 
#define GNUNET_BIO_write_float(h, f) (sizeof(float) == GNUNET_BIO_write (h, &f, sizeof(float)))



/**
 * Write a double.
 *
 * @param h hande to open file
 * @param f double to write (must be a variable)
 */ 
#define GNUNET_BIO_write_float(h, f) (sizeof(double) == GNUNET_BIO_write (h, &f, sizeof(double)))


/**
 * Write an (u)int32_t.
 *
 * @param h hande to open file
 * @param i address of 32-bit integer to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */ 
int GNUNET_BIO_write_int32 (struct GNUNET_BIO_ReadHandle *h, 
			    int32_t i);


/**
 * Write an (u)int64_t.
 *
 * @param h hande to open file
 * @param i address of 64-bit integer to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */ 
int GNUNET_BIO_write_int64 (struct GNUNET_BIO_ReadHandle *h, 
			    int64_t i);





typedef struct
{
  int fd;
  unsigned int have;
  unsigned int size;
  char *buffer;
} WriteBuffer;

static void
write_buffered (WriteBuffer * wb, const void *s, unsigned int size)
{
  const char *src = s;
  unsigned int min;
  unsigned int pos;
  int ret;

  if (wb->fd == -1)
    return;
  pos = 0;
  do
    {
      /* first, just use buffer */
      min = wb->size - wb->have;
      if (min > size - pos)
        min = size - pos;
      memcpy (&wb->buffer[wb->have], &src[pos], min);
      pos += min;
      wb->have += min;
      if (pos == size)
        return;                 /* done */
      GNUNET_GE_ASSERT (NULL, wb->have == wb->size);
      ret = WRITE (wb->fd, wb->buffer, wb->size);
      if (ret != wb->size)
        {
          CLOSE (wb->fd);
          wb->fd = -1;
          return;               /* error */
        }
      wb->have = 0;
    }
  while (pos < size);           /* should always be true */
}


static void
WRITEINT (WriteBuffer * wb, int val)
{
  int big;
  big = htonl (val);
  write_buffered (wb, &big, sizeof (int));
}

static void
WRITELONG (WriteBuffer * wb, long long val)
{
  long long big;
  big = GNUNET_htonll (val);
  write_buffered (wb, &big, sizeof (long long));
}

static void
writeURI (WriteBuffer * wb, const struct GNUNET_ECRS_URI *uri)
{
  char *buf;
  unsigned int size;

  buf = GNUNET_ECRS_uri_to_string (uri);
  size = strlen (buf);
  WRITEINT (wb, size);
  write_buffered (wb, buf, size);
  GNUNET_free (buf);
}

static void
WRITESTRING (WriteBuffer * wb, const char *name)
{
  GNUNET_GE_BREAK (NULL, name != NULL);
  WRITEINT (wb, strlen (name));
  write_buffered (wb, name, strlen (name));
}

static void
writeMetaData (struct GNUNET_GE_Context *ectx,
               WriteBuffer * wb, const struct GNUNET_MetaData *meta)
{
  unsigned int size;
  char *buf;

  size = GNUNET_meta_data_get_serialized_size (meta,
                                               GNUNET_SERIALIZE_FULL
                                               |
                                               GNUNET_SERIALIZE_NO_COMPRESS);
  if (size > 1024 * 1024)
    size = 1024 * 1024;
  buf = GNUNET_malloc (size);
  GNUNET_meta_data_serialize (ectx,
                              meta,
                              buf,
                              size,
                              GNUNET_SERIALIZE_PART |
                              GNUNET_SERIALIZE_NO_COMPRESS);
  WRITEINT (wb, size);
  write_buffered (wb, buf, size);
  GNUNET_free (buf);
}


static void
writeFileInfo (struct GNUNET_GE_Context *ectx, WriteBuffer * wb,
               const GNUNET_ECRS_FileInfo * fi)
{
  writeMetaData (ectx, wb, fi->meta);
  writeURI (wb, fi->uri);
}




typedef struct
{
  int fd;
  unsigned int have;
  unsigned int size;
  unsigned int pos;
  char *buffer;
} ReadBuffer;

static int
read_buffered (ReadBuffer * rb, void *d, unsigned int size)
{
  char *dst = d;
  unsigned int min;
  unsigned int pos;
  int ret;

  if (rb->fd == -1)
    return -1;
  pos = 0;
  do
    {
      /* first, use buffer */
      min = rb->have - rb->pos;
      if (min > 0)
        {
          if (min > size - pos)
            min = size - pos;
          memcpy (&dst[pos], &rb->buffer[rb->pos], min);
          rb->pos += min;
          pos += min;
        }
      if (pos == size)
        return pos;             /* done! */
      GNUNET_GE_ASSERT (NULL, rb->have == rb->pos);
      /* fill buffer */
      ret = READ (rb->fd, rb->buffer, rb->size);
      if (ret == -1)
        {
          CLOSE (rb->fd);
          rb->fd = -1;
          return -1;
        }
      if (ret == 0)
        return 0;
      rb->pos = 0;
      rb->have = ret;
    }
  while (pos < size);           /* should always be true */
  return pos;
}


static int
read_int (ReadBuffer * rb, int *val)
{
  int big;

  if (sizeof (int) != read_buffered (rb, &big, sizeof (int)))
    return GNUNET_SYSERR;
  *val = ntohl (big);
  return GNUNET_OK;
}

static unsigned int
read_uint (ReadBuffer * rb, unsigned int *val)
{
  unsigned int big;

  if (sizeof (unsigned int) !=
      read_buffered (rb, &big, sizeof (unsigned int)))
    return GNUNET_SYSERR;
  *val = ntohl (big);
  return GNUNET_OK;
}

#define READINT(a) if (GNUNET_OK != read_int(rb, (int*) &a)) return GNUNET_SYSERR;

static int
read_long (ReadBuffer * rb, long long *val)
{
  long long big;

  if (sizeof (long long) != read_buffered (rb, &big, sizeof (long long)))
    return GNUNET_SYSERR;
  *val = GNUNET_ntohll (big);
  return GNUNET_OK;
}

#define READLONG(a) if (GNUNET_OK != read_long(rb, (long long*) &a)) return GNUNET_SYSERR;

static struct GNUNET_ECRS_URI *
read_uri (struct GNUNET_GE_Context *ectx, ReadBuffer * rb)
{
  char *buf;
  struct GNUNET_ECRS_URI *ret;
  unsigned int size;

  if (GNUNET_OK != read_uint (rb, &size))
    return NULL;
  buf = GNUNET_malloc (size + 1);
  buf[size] = '\0';
  if (size != read_buffered (rb, buf, size))
    {
      GNUNET_free (buf);
      return NULL;
    }
  ret = GNUNET_ECRS_string_to_uri (ectx, buf);
  GNUNET_GE_BREAK (ectx, ret != NULL);
  GNUNET_free (buf);
  return ret;
}

#define READURI(u) if (NULL == (u = read_uri(ectx, rb))) return GNUNET_SYSERR;

static char *
read_string (ReadBuffer * rb, unsigned int maxLen)
{
  char *buf;
  unsigned int big;

  if (GNUNET_OK != read_uint (rb, &big))
    return NULL;
  if (big > maxLen)
    return NULL;
  buf = GNUNET_malloc (big + 1);
  buf[big] = '\0';
  if (big != read_buffered (rb, buf, big))
    {
      GNUNET_free (buf);
      return NULL;
    }
  return buf;
}

#define READSTRING(c, max) if (NULL == (c = read_string(rb, max))) return GNUNET_SYSERR;

/**
 * Read file info from file.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static struct GNUNET_MetaData *
read_meta (struct GNUNET_GE_Context *ectx, ReadBuffer * rb)
{
  unsigned int size;
  char *buf;
  struct GNUNET_MetaData *meta;

  if (read_uint (rb, &size) != GNUNET_OK)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  if (size > 1024 * 1024)
    {
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  buf = GNUNET_malloc (size);
  if (size != read_buffered (rb, buf, size))
    {
      GNUNET_free (buf);
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  meta = GNUNET_meta_data_deserialize (ectx, buf, size);
  if (meta == NULL)
    {
      GNUNET_free (buf);
      GNUNET_GE_BREAK (ectx, 0);
      return NULL;
    }
  GNUNET_free (buf);
  return meta;
}

/* end of bio.c */
