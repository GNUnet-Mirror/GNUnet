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
 * @file util/server_tc.c
 * @brief convenience functions for transmission of
 *        complex responses as a server
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)


/**
 * How much buffer space do we want to have at least
 * before transmitting another increment?
 */
#define MIN_BLOCK_SIZE 128



struct GNUNET_SERVER_TransmitContext
{
  /**
   * Which client are we transmitting to?
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Transmission buffer. (current offset for writing).
   */
  char *buf;

  /**
   * Number of bytes in buf.
   */
  size_t total;

  /**
   * Offset for writing in buf.
   */
  size_t off;

  /**
   * Timeout for this request.
   */
  struct GNUNET_TIME_Absolute timeout;
};


/**
 * Helper function for incremental transmission of the response.
 */
static size_t
transmit_response (void *cls, size_t size, void *buf)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  size_t msize;

  if (buf == NULL)
  {
    GNUNET_SERVER_transmit_context_destroy (tc, GNUNET_SYSERR);
    return 0;
  }
  if (tc->total - tc->off > size)
    msize = size;
  else
    msize = tc->total - tc->off;
  memcpy (buf, &tc->buf[tc->off], msize);
  tc->off += msize;
  if (tc->total == tc->off)
  {

    GNUNET_SERVER_receive_done (tc->client, GNUNET_OK);
    GNUNET_SERVER_client_drop (tc->client);
    GNUNET_free_non_null (tc->buf);
    GNUNET_free (tc);
  }
  else
  {
    if (NULL ==
        GNUNET_SERVER_notify_transmit_ready (tc->client,
                                             GNUNET_MIN (MIN_BLOCK_SIZE,
                                                         tc->total - tc->off),
                                             GNUNET_TIME_absolute_get_remaining
                                             (tc->timeout), &transmit_response,
                                             tc))
    {
      GNUNET_break (0);
      GNUNET_SERVER_transmit_context_destroy (tc, GNUNET_SYSERR);
    }
  }
  return msize;
}


/**
 * Create a new transmission context for the
 * given client.
 *
 * @param client client to create the context for.
 * @return NULL on error
 */
struct GNUNET_SERVER_TransmitContext *
GNUNET_SERVER_transmit_context_create (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_SERVER_TransmitContext *tc;

  GNUNET_assert (client != NULL);
  tc = GNUNET_malloc (sizeof (struct GNUNET_SERVER_TransmitContext));
  GNUNET_SERVER_client_keep (client);
  tc->client = client;
  return tc;
}


/**
 * Append a message to the transmission context.
 * All messages in the context will be sent by
 * the transmit_context_run method.
 *
 * @param tc context to use
 * @param data what to append to the result message
 * @param length length of data
 * @param type type of the message
 */
void
GNUNET_SERVER_transmit_context_append_data (struct GNUNET_SERVER_TransmitContext
                                            *tc, const void *data,
                                            size_t length, uint16_t type)
{
  struct GNUNET_MessageHeader *msg;
  size_t size;

  GNUNET_assert (length < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  size = length + sizeof (struct GNUNET_MessageHeader);
  GNUNET_assert (size > length);
  tc->buf = GNUNET_realloc (tc->buf, tc->total + size);
  msg = (struct GNUNET_MessageHeader *) &tc->buf[tc->total];
  tc->total += size;
  msg->size = htons (size);
  msg->type = htons (type);
  memcpy (&msg[1], data, length);
}


/**
 * Append a message to the transmission context.
 * All messages in the context will be sent by
 * the transmit_context_run method.
 *
 * @param tc context to use
 * @param msg message to append
 */
void
GNUNET_SERVER_transmit_context_append_message (struct
                                               GNUNET_SERVER_TransmitContext
                                               *tc,
                                               const struct GNUNET_MessageHeader
                                               *msg)
{
  struct GNUNET_MessageHeader *m;
  uint16_t size;

  size = ntohs (msg->size);
  tc->buf = GNUNET_realloc (tc->buf, tc->total + size);
  m = (struct GNUNET_MessageHeader *) &tc->buf[tc->total];
  tc->total += size;
  memcpy (m, msg, size);
}


/**
 * Execute a transmission context.  If there is
 * an error in the transmission, the receive_done
 * method will be called with an error code (GNUNET_SYSERR),
 * otherwise with GNUNET_OK.
 *
 * @param tc transmission context to use
 * @param timeout when to time out and abort the transmission
 */
void
GNUNET_SERVER_transmit_context_run (struct GNUNET_SERVER_TransmitContext *tc,
                                    struct GNUNET_TIME_Relative timeout)
{
  tc->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (NULL ==
      GNUNET_SERVER_notify_transmit_ready (tc->client,
                                           GNUNET_MIN (MIN_BLOCK_SIZE,
                                                       tc->total), timeout,
                                           &transmit_response, tc))
  {
    GNUNET_break (0);
    GNUNET_SERVER_transmit_context_destroy (tc, GNUNET_SYSERR);
  }
}


/**
 * Destroy a transmission context. This function must not be called
 * after 'GNUNET_SERVER_transmit_context_run'.
 *
 * @param tc transmission context to destroy
 * @param success code to give to 'GNUNET_SERVER_receive_done' for
 *        the client:  GNUNET_OK to keep the connection open and
 *                          continue to receive
 *                GNUNET_NO to close the connection (normal behavior)
 *                GNUNET_SYSERR to close the connection (signal
 *                          serious error)
 */
void
GNUNET_SERVER_transmit_context_destroy (struct GNUNET_SERVER_TransmitContext
                                        *tc, int success)
{
  GNUNET_SERVER_receive_done (tc->client, success);
  GNUNET_SERVER_client_drop (tc->client);
  GNUNET_free_non_null (tc->buf);
  GNUNET_free (tc);
}


/* end of server_tc.c */
