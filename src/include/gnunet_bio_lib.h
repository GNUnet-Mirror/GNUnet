/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_bio_lib.h
 * @brief buffered IO API
 * @author Christian Grothoff
 */

#ifndef GNUNET_BIO_LIB_H
#define GNUNET_BIO_LIB_H

#include "gnunet_container_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Handle for buffered reading.
 */
struct GNUNET_BIO_ReadHandle;


/**
 * Open a file for reading.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_ReadHandle *
GNUNET_BIO_read_open (const char *fn);


/**
 * Close an open file.  Reports if any errors reading
 * from the file were encountered.
 *
 * @param h file handle
 * @param emsg set to the error message
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_read_close (struct GNUNET_BIO_ReadHandle *h, char **emsg);


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
                 void *result, size_t len);


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
                    void *result, size_t len);

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
                        char **result, size_t maxLen);


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
                           struct GNUNET_CONTAINER_MetaData **result);


/**
 * Read a float.
 *
 * @param h hande to open file
 * @param f address of float to read
 */
#define GNUNET_BIO_read_float(h, f) (GNUNET_BIO_read_fn (h, __FILE__, __LINE__, f, sizeof(float)))



/**
 * Read a double.
 *
 * @param h hande to open file
 * @param f address of double to read
 */
#define GNUNET_BIO_read_double(h, f) (GNUNET_BIO_read_fn (h, __FILE__, __LINE__, f, sizeof(double)))


/**
 * Read an (u)int32_t.
 *
 * @param h hande to open file
 * @param file name of the source file
 * @param line line number in the code
 * @param i address of 32-bit integer to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_read_int32__ (struct GNUNET_BIO_ReadHandle *h, const char *file,
                         int line, int32_t * i);


/**
 * Read an (u)int32_t.
 *
 * @param h hande to open file
 * @param i address of 32-bit integer to read
 */
#define GNUNET_BIO_read_int32(h, i) GNUNET_BIO_read_int32__ (h, __FILE__, __LINE__, (int32_t*) i)


/**
 * Read an (u)int64_t.
 *
 * @param h hande to open file
 * @param file name of the source file
 * @param line line number in the code
 * @param i address of 64-bit integer to read
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_read_int64__ (struct GNUNET_BIO_ReadHandle *h, const char *file,
                         int line, int64_t * i);


/**
 * Read an (u)int64_t.
 *
 * @param h hande to open file
 * @param i address of 64-bit integer to read
 */
#define GNUNET_BIO_read_int64(h, i) GNUNET_BIO_read_int64__ (h, __FILE__, __LINE__, (int64_t*) i)


/**
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle;

/**
 * Open a file for writing.
 *
 * @param fn file name to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *
GNUNET_BIO_write_open (const char *fn);


/**
 * Close an open file for writing.
 *
 * @param h file handle
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_write_close (struct GNUNET_BIO_WriteHandle *h);


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
                  size_t n);


/**
 * Write a string to a file.
 *
 * @param h handle to open file
 * @param s string to write (can be NULL)
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_string (struct GNUNET_BIO_WriteHandle *h, const char *s);




/**
 * Write metadata container to a file.
 *
 * @param h handle to open file
 * @param m metadata to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_meta_data (struct GNUNET_BIO_WriteHandle *h,
                            const struct GNUNET_CONTAINER_MetaData *m);



/**
 * Write a float.
 *
 * @param h hande to open file
 * @param f float to write (must be a variable)
 */
#define GNUNET_BIO_write_float(h, f) GNUNET_BIO_write (h, &f, sizeof(float))



/**
 * Write a double.
 *
 * @param h hande to open file
 * @param f double to write (must be a variable)
 */
#define GNUNET_BIO_write_double(h, f) GNUNET_BIO_write (h, &f, sizeof(double))


/**
 * Write an (u)int32_t.
 *
 * @param h hande to open file
 * @param i 32-bit integer to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_int32 (struct GNUNET_BIO_WriteHandle *h, int32_t i);


/**
 * Write an (u)int64_t.
 *
 * @param h hande to open file
 * @param i 64-bit integer to write
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_BIO_write_int64 (struct GNUNET_BIO_WriteHandle *h, int64_t i);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_BIO_LIB_H */
#endif
/* end of gnunet_bio_lib.h */
