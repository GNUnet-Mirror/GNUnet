/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Buffered IO library
 *
 * @defgroup bio  BIO library
 * Buffered binary disk IO (with endianess conversion)
 * @{
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

/****************************** READING API *******************************/

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
GNUNET_BIO_read_open_file (const char *fn);


/**
 * Create a handle from an existing allocated buffer.
 *
 * @param buffer the buffer to use as source
 * @param size the total size in bytes of the buffer
 * @return IO handle on sucess, NULL on error
 */
struct GNUNET_BIO_ReadHandle *
GNUNET_BIO_read_open_buffer (void *buffer, size_t size);


/**
 * Close an open handle.  Reports if any errors reading
 * from the file were encountered.
 *
 * @param h file handle
 * @param emsg set to the error message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_BIO_read_close (struct GNUNET_BIO_ReadHandle *h, char **emsg);


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
                 size_t len);


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
                        size_t max_length);


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
                           struct GNUNET_CONTAINER_MetaData **result);


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
                      float *f);


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
                       double *f);



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
                       int32_t *i);



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
                       int64_t *i);



/****************************** WRITING API *******************************/

/**
 * Handle for buffered writing.
 */
struct GNUNET_BIO_WriteHandle;

/**
 * Open a file for writing.
 *
 * @param fn name of the file to be opened
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *
GNUNET_BIO_write_open_file (const char *fn);


/**
 * Create a handle backed by an in-memory buffer.
 *
 * @return IO handle on success, NULL on error
 */
struct GNUNET_BIO_WriteHandle *
GNUNET_BIO_write_open_buffer (void);


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
GNUNET_BIO_flush (struct GNUNET_BIO_WriteHandle *h);


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
                                size_t *size);


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
GNUNET_BIO_write_close (struct GNUNET_BIO_WriteHandle *h, char **emsg);


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
                  size_t n);


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
                         const char *s);


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
                            const struct GNUNET_CONTAINER_MetaData *m);


/**
 * Write a float.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param f float to write (must be a variable)
 */
int
GNUNET_BIO_write_float(struct GNUNET_BIO_WriteHandle *h,
                       const char *what,
                       float f);

/**
 * Write a double.
 *
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param f double to write (must be a variable)
 */
int
GNUNET_BIO_write_double(struct GNUNET_BIO_WriteHandle *h,
                        const char *what,
                        double f);


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
                        int32_t i);


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
                        int64_t i);


/****************************** READ SPEC API ***************************/


/**
 * Function used to deserialize data read from @a h and store it into @a
 * target.
 *
 * @param cls closure (can be NULL)
 * @param h the IO handle to read from
 * @param what what is being read (for error message creation)
 * @param target where to store the data
 * @param target_size how many bytes can be written in @a target
 *        can be 0 if the size is unknown or is not fixed
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
typedef int
(*GNUNET_BIO_ReadHandler)(void *cls,
                          struct GNUNET_BIO_ReadHandle *h,
                          const char *what,
                          void *target,
                          size_t target_size);


/**
 * Structure specifying a reading operation on an IO handle.
 */
struct GNUNET_BIO_ReadSpec
{
  /**
   * Function performing data deserialization.
   */
  GNUNET_BIO_ReadHandler rh;

  /**
   * Closure for @e rh. Can be NULL.
   */
  void *cls;

  /**
   * What is being read (for error message creation)
   */
  const char *what;

  /**
   * Destination buffer. Can also be a pointer to a pointer, especially for
   * dynamically allocated structures.
   */
  void *target;

  /**
   * Size of @e target. Can be 0 if unknown or not fixed.
   */
  size_t size;
};


/**
 * End of specifications marker.
 */
#define GNUNET_BIO_read_spec_end()              \
  { NULL, NULL, NULL, NULL, 0 }


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
                             size_t size);


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
                             size_t max_length);


/**
 * Create the specification to read a metadata container.
 *
 * @param what describes what is being read (for error message creation)
 * @param result the buffer to store a pointer to the (allocated) metadata
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_meta_data (const char *what,
                                struct GNUNET_CONTAINER_MetaData **result);


/**
 * Create the specification to read an (u)int32_t.
 *
 * @param what describes what is being read (for error message creation)
 * @param i where to store the data
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_int32 (const char *what,
                            int32_t *i);


/**
 * Create the specification to read an (u)int64_t.
 *
 * @param what describes what is being read (for error message creation)
 * @param i where to store the data
 * @return the read spec
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_int64 (const char *what,
                            int64_t *i);


/**
 * Create the specification to read a float.
 *
 * @param what describes what is being read (for error message creation)
 * @param f address of float to read
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_float(const char *what, float *f);


/**
 * Create the specification to read a double.
 *
 * @param what describes what is being read (for error message creation)
 * @param f address of double to read
 */
struct GNUNET_BIO_ReadSpec
GNUNET_BIO_read_spec_double(const char *what, double *f);


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
                             struct GNUNET_BIO_ReadSpec *rs);


/******************************* WRITE SPEC API *****************************/


/**
 * Function used to serialize data from a buffer and write it to @a h.
 *
 * @param cls closure (can be NULL)
 * @param h the IO handle to write to
 * @param what what is being written (for error message creation)
 * @param source the data to write
 * @param source_size how many bytes should be written
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
typedef int
(*GNUNET_BIO_WriteHandler) (void *cls,
                            struct GNUNET_BIO_WriteHandle *h,
                            const char *what,
                            void *source,
                            size_t source_size);


/**
 * Structure specifying a writing operation on an IO handle.
 */
struct GNUNET_BIO_WriteSpec
{
  /**
   * Function performing data serialization.
   */
  GNUNET_BIO_WriteHandler wh;

  /**
   * Closure for @e rh. Can be NULL.
   */
  void *cls;

  /**
   * What is being read (for error message creation)
   */
  const char *what;

  /**
   * Source buffer. The data in this buffer will be written to the handle.
   */
  void *source;

  /**
   * Size of @e source. If it's smaller than the real size of @e source, only
   * this many bytes will be written.
   */
  size_t source_size;
};


/**
 * End of specifications marker.
 */
#define GNUNET_BIO_write_spec_end()             \
  { NULL, NULL, NULL, NULL, 0 }


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
                              size_t size);


/**
 * Create the specification to write a 0-terminated string.
 *
 * @param what describes what is being read (for error message creation)
 * @param s string to write (can be NULL)
 * @return the read spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_string (const char *what,
                              const char *s);


/**
 * Create the specification to write a metadata container.
 *
 * @param what what is being written (for error message creation)
 * @param m metadata to write
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_meta_data (const char *what,
                                 const struct GNUNET_CONTAINER_MetaData *m);


/**
 * Create the specification to write an (u)int32_t.
 *
 * @param what describes what is being written (for error message creation)
 * @param i pointer to a 32-bit integer
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_int32 (const char *what,
                             int32_t *i);


/**
 * Create the specification to write an (u)int64_t.
 *
 * @param what describes what is being written (for error message creation)
 * @param i pointer to a 64-bit integer
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_int64 (const char *what,
                             int64_t *i);


/**
 * Create the specification to write a float.
 *
 * @param what describes what is being written (for error message creation)
 * @param f pointer to a float
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_float(const char *what, float *f);


/**
 * Create the specification to write an double.
 *
 * @param what describes what is being written (for error message creation)
 * @param f pointer to a double
 * @return the write spec
 */
struct GNUNET_BIO_WriteSpec
GNUNET_BIO_write_spec_double(const char *what, double *f);


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
                              struct GNUNET_BIO_WriteSpec *ws);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_BIO_LIB_H */
#endif

/** @} */  /* end of group bio */

/* end of gnunet_bio_lib.h */
