/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file json/mhd_json.c
 * @brief functions to parse JSON snippets we receive via MHD
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_json_lib.h"

/**
 * Initial size for POST request buffers.  Should be big enough to
 * usually not require a reallocation, but not so big that it hurts in
 * terms of memory use.
 */
#define REQUEST_BUFFER_INITIAL (2*1024)


/**
 * Buffer for POST requests.
 */
struct Buffer
{
  /**
   * Allocated memory
   */
  char *data;

  /**
   * Number of valid bytes in buffer.
   */
  size_t fill;

  /**
   * Number of allocated bytes in buffer.
   */
  size_t alloc;
};


/**
 * Initialize a buffer.
 *
 * @param buf the buffer to initialize
 * @param data the initial data
 * @param data_size size of the initial data
 * @param alloc_size size of the buffer
 * @param max_size maximum size that the buffer can grow to
 * @return a GNUnet result code
 */
static int
buffer_init (struct Buffer *buf,
             const void *data,
             size_t data_size,
             size_t alloc_size,
             size_t max_size)
{
  if ( (data_size > max_size) ||
       (alloc_size > max_size) )
    return GNUNET_SYSERR;
  if (data_size > alloc_size)
    alloc_size = data_size;
  buf->data = GNUNET_malloc (alloc_size);
  memcpy (buf->data, data, data_size);
  return GNUNET_OK;
}


/**
 * Free the data in a buffer.  Does *not* free
 * the buffer object itself.
 *
 * @param buf buffer to de-initialize
 */
static void
buffer_deinit (struct Buffer *buf)
{
  GNUNET_free (buf->data);
  buf->data = NULL;
}


/**
 * Append data to a buffer, growing the buffer if necessary.
 *
 * @param buf the buffer to append to
 * @param data the data to append
 * @param data_size the size of @a data
 * @param max_size maximum size that the buffer can grow to
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if the buffer can't accomodate for the new data
 */
static int
buffer_append (struct Buffer *buf,
               const void *data,
               size_t data_size,
               size_t max_size)
{
  if (buf->fill + data_size > max_size)
    return GNUNET_NO;
  if (data_size + buf->fill > buf->alloc)
  {
    char *new_buf;
    size_t new_size = buf->alloc;
    while (new_size < buf->fill + data_size)
      new_size += 2;
    if (new_size > max_size)
      return GNUNET_NO;
    new_buf = GNUNET_malloc (new_size);
    memcpy (new_buf, buf->data, buf->fill);
    GNUNET_free (buf->data);
    buf->data = new_buf;
    buf->alloc = new_size;
  }
  memcpy (buf->data + buf->fill, data, data_size);
  buf->fill += data_size;
  return GNUNET_OK;
}


/**
 * Process a POST request containing a JSON object.  This function
 * realizes an MHD POST processor that will (incrementally) process
 * JSON data uploaded to the HTTP server.  It will store the required
 * state in the @a con_cls, which must be cleaned up using
 * #GNUNET_JSON_post_parser_callback().
 *
 * @param buffer_max maximum allowed size for the buffer
 * @param con_cls the closure (will point to a `struct Buffer *`)
 * @param upload_data the POST data
 * @param upload_data_size number of bytes in @a upload_data
 * @param json the JSON object for a completed request
 * @return result code indicating the status of the operation
 */
enum GNUNET_JSON_PostResult
GNUNET_JSON_post_parser (size_t buffer_max,
                         void **con_cls,
                         const char *upload_data,
                         size_t *upload_data_size,
                         json_t **json)
{
  struct Buffer *r = *con_cls;

  *json = NULL;
  if (NULL == *con_cls)
  {
    /* We are seeing a fresh POST request. */
    r = GNUNET_new (struct Buffer);
    if (GNUNET_OK !=
        buffer_init (r,
                     upload_data,
                     *upload_data_size,
                     REQUEST_BUFFER_INITIAL,
                     buffer_max))
    {
      *con_cls = NULL;
      buffer_deinit (r);
      GNUNET_free (r);
      return GNUNET_JSON_PR_OUT_OF_MEMORY;
    }
    /* everything OK, wait for more POST data */
    *upload_data_size = 0;
    *con_cls = r;
    return GNUNET_JSON_PR_CONTINUE;
  }
  if (0 != *upload_data_size)
  {
    /* We are seeing an old request with more data available. */

    if (GNUNET_OK !=
        buffer_append (r,
                       upload_data,
                       *upload_data_size,
                       buffer_max))
    {
      /* Request too long */
      *con_cls = NULL;
      buffer_deinit (r);
      GNUNET_free (r);
      return GNUNET_JSON_PR_REQUEST_TOO_LARGE;
    }
    /* everything OK, wait for more POST data */
    *upload_data_size = 0;
    return GNUNET_JSON_PR_CONTINUE;
  }

  /* We have seen the whole request. */

  *json = json_loadb (r->data,
                      r->fill,
                      0,
                      NULL);
  if (NULL == *json)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to parse JSON request body\n");
    return GNUNET_JSON_PR_JSON_INVALID;
  }
  buffer_deinit (r);
  GNUNET_free (r);
  *con_cls = NULL;

  return GNUNET_JSON_PR_SUCCESS;
}


/**
 * Function called whenever we are done with a request
 * to clean up our state.
 *
 * @param con_cls value as it was left by
 *        #GNUNET_JSON_post_parser(), to be cleaned up
 */
void
GNUNET_JSON_post_parser_cleanup (void *con_cls)
{
  struct Buffer *r = con_cls;

  if (NULL != r)
  {
    buffer_deinit (r);
    GNUNET_free (r);
  }
}

/* end of mhd_json.c */
