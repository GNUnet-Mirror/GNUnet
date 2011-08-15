/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file dht/dht_api_get_put.c
 * @brief library to perform DHT gets and puts
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "dht.h"


/**
 * Perform a PUT operation storing data in the DHT.
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param desired_replication_level estimate of how many
 *                nearest peers this request should reach
 * @param options routing options for this message
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param timeout how long to wait for transmission of this request
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 * @return GNUNET_YES if put message is queued for transmission
 */
void
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const GNUNET_HashCode * key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                size_t size,
                const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  struct GNUNET_DHT_PutMessage *put_msg;

  if (size >= sizeof (buf) - sizeof (struct GNUNET_DHT_PutMessage))
  {
    GNUNET_break (0);
    return;
  }
  put_msg = (struct GNUNET_DHT_PutMessage *) buf;
  put_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_PUT);
  put_msg->header.size = htons (sizeof (struct GNUNET_DHT_PutMessage) + size);
  put_msg->type = htonl ((uint32_t) type);
  put_msg->expiration = GNUNET_TIME_absolute_hton (exp);
  memcpy (&put_msg[1], data, size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting route for %u byte `%s' message of type %u \n",
              (unsigned int) (sizeof (struct GNUNET_DHT_PutMessage) + size),
              "PUT", type);
  GNUNET_break (NULL ==
                GNUNET_DHT_route_start (handle,
                                        key,
                                        desired_replication_level, options,
                                        &put_msg->header,
                                        timeout, NULL, NULL, cont, cont_cls));
}



/**
 * Handle to control a get operation.
 */
struct GNUNET_DHT_GetHandle
{
  /**
   * Handle to the actual route operation for the get
   */
  struct GNUNET_DHT_RouteHandle *route_handle;

  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_GetIterator iter;

  /**
   * Closure for the iterator callback
   */
  void *iter_cls;

};



/**
 * Iterator called on each result obtained from a generic route
 * operation
 *
 * @param cls the 'struct GNUNET_DHT_GetHandle'
 * @param key key that was used
 * @param outgoing_path path of the message from this peer
 *                      to the target
 * @param reply response
 */
static void
get_reply_iterator (void *cls,
                    const GNUNET_HashCode * key,
                    const struct GNUNET_PeerIdentity *const *outgoing_path,
                    const struct GNUNET_MessageHeader *reply)
{
  struct GNUNET_DHT_GetHandle *get_handle = cls;
  const struct GNUNET_DHT_GetResultMessage *result;
  const struct GNUNET_PeerIdentity **put_path;
  size_t payload;
  char *path_offset;
  const struct GNUNET_PeerIdentity *pos;
  unsigned int i;
  uint16_t put_path_length;
  uint16_t data_size;

  if (ntohs (reply->type) != GNUNET_MESSAGE_TYPE_DHT_GET_RESULT)
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_assert (ntohs (reply->size) >=
                 sizeof (struct GNUNET_DHT_GetResultMessage));
  result = (const struct GNUNET_DHT_GetResultMessage *) reply;

  put_path = NULL;
  put_path_length = ntohs (result->put_path_length);
  if (put_path_length > 0)
  {
    data_size =
        ntohs (result->header.size) -
        (put_path_length * sizeof (struct GNUNET_PeerIdentity)) -
        sizeof (struct GNUNET_DHT_GetResultMessage);
    path_offset = (char *) &result[1];
    //GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "In get_reply_iterator, result->header.size is %d, put_path_length %d, offset is %d, data_size is %d\n", ntohs(result->header.size), put_path_length, ntohs(result->header.size) - (put_path_length * sizeof(struct GNUNET_PeerIdentity)), data_size);
    path_offset += data_size;
    pos = (const struct GNUNET_PeerIdentity *) path_offset;
    //GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Found put peer %s\n", GNUNET_i2s((const struct GNUNET_PeerIdentity *)path_offset));
    put_path =
        GNUNET_malloc ((put_path_length +
                        1) * sizeof (struct GNUNET_PeerIdentity *));
    for (i = 0; i < put_path_length; i++)
    {
      put_path[i] = pos;
      pos++;
    }
    put_path[put_path_length] = NULL;
  }

  payload = ntohs (reply->size) - sizeof (struct GNUNET_DHT_GetResultMessage);
  get_handle->iter (get_handle->iter_cls,
                    GNUNET_TIME_absolute_ntoh (result->expiration),
                    key,
                    outgoing_path,
                    put_path, ntohs (result->type), payload, &result[1]);
  GNUNET_free_non_null (put_path);
}



/**
 * Perform an asynchronous GET operation on the DHT identified. See
 * also "GNUNET_BLOCK_evaluate".
 *
 * @param handle handle to the DHT service
 * @param timeout how long to wait for transmission of this request to the service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * @param bf bloom filter associated with query (can be NULL)
 * @param bf_mutator mutation value for bf
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 *
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      struct GNUNET_TIME_Relative timeout,
                      enum GNUNET_BLOCK_Type type,
                      const GNUNET_HashCode * key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options,
                      const struct GNUNET_CONTAINER_BloomFilter *bf,
                      int32_t bf_mutator,
                      const void *xquery,
                      size_t xquery_size,
                      GNUNET_DHT_GetIterator iter, void *iter_cls)
{
  struct GNUNET_DHT_GetHandle *get_handle;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_DHT_GetMessage *get_msg;
  size_t bf_size;

  bf_size = GNUNET_CONTAINER_bloomfilter_get_size (bf);
  if ((sizeof (buf) <=
       sizeof (struct GNUNET_DHT_GetMessage) + xquery_size + bf_size) ||
      (sizeof (buf) <= bf_size))
  {
    GNUNET_break (0);
    return NULL;
  }
  get_handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_GetHandle));
  get_handle->iter = iter;
  get_handle->iter_cls = iter_cls;
  get_msg = (struct GNUNET_DHT_GetMessage *) buf;
  get_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_GET);
  get_msg->header.size = htons (sizeof (struct GNUNET_DHT_GetMessage) +
                                xquery_size + bf_size);
  get_msg->type = htonl ((uint32_t) type);
  get_msg->bf_mutator = bf_mutator;
  get_msg->xquery_size = htons ((uint16_t) xquery_size);
  get_msg->bf_size = htons (bf_size);
  if (xquery != NULL)
    memcpy (&buf[sizeof (struct GNUNET_DHT_GetMessage)], xquery, xquery_size);
  else
    GNUNET_assert (xquery_size == 0);
  (void) GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
                                                    &buf[sizeof
                                                         (struct
                                                          GNUNET_DHT_GetMessage)
                                                         + xquery_size],
                                                    bf_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting route for %u byte `%s' message\n",
              (unsigned int) (sizeof (struct GNUNET_DHT_GetMessage) +
                              xquery_size + bf_size), "GET");
  get_handle->route_handle =
      GNUNET_DHT_route_start (handle, key, desired_replication_level, options,
                              &get_msg->header, timeout, &get_reply_iterator,
                              get_handle, NULL, NULL);
  GNUNET_break (NULL != get_handle->route_handle);
  return get_handle;
}


/**
 * Stop async DHT-get.
 *
 * @param get_handle handle to the GET operation to stop
 *
 * On return get_handle will no longer be valid, caller
 * must not use again!!!
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle)
{
  GNUNET_DHT_route_stop (get_handle->route_handle);
  GNUNET_free (get_handle);
}


/* end of dht_api_get_put.c */
