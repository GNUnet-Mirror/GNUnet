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
 * @file gns/gns_api.c
 * @brief library to access the GNS service
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"

#define DEBUG_GNS_API GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

/**
 * Handle to a Lookup request
 */
struct GNUNET_GNS_LookupHandle
{

  /**
   * Iterator to call on data receipt
   */
  GNUNET_GNS_LookupIterator iter;

  /**
   * Closure for the iterator callback
   */
  void *iter_cls;

  /**
   * Main handle to this GNS api
   */
  struct GNUNET_GNS_Handle *gns_handle;

  /**
   * Key that this get request is for
   */
  GNUNET_HashCode key;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint64_t unique_id;

};


/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * How quickly should we retry?  Used for exponential back-off on
   * connect-errors.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * Generator for unique ids.
   */
  uint64_t uid_gen;

  /**
   * Did we start our receive loop yet?
   */
  int in_receive;
};


/**
 * Try to (re)connect to the GNS service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_GNS_Handle *handle)
{
  if (handle->client != NULL)
    return GNUNET_OK;
  handle->in_receive = GNUNET_NO;
  handle->client = GNUNET_CLIENT_connect ("gns", handle->cfg);
  if (handle->client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to connect to the GNS service!\n"));
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

/**
 * Try reconnecting to the GNS service.
 *
 * @param cls GNUNET_GNS_Handle
 * @param tc scheduler context
 */
static void
try_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_GNS_Handle *handle = cls;

#if DEBUG_DHT
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Reconnecting with GNS %p\n", handle);
#endif
  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (handle->retry_time.rel_value < GNUNET_CONSTANTS_SERVICE_RETRY.rel_value)
    handle->retry_time = GNUNET_CONSTANTS_SERVICE_RETRY;
  else
    handle->retry_time = GNUNET_TIME_relative_multiply (handle->retry_time, 2);
  if (handle->retry_time.rel_value > GNUNET_CONSTANTS_SERVICE_TIMEOUT.rel_value)
    handle->retry_time = GNUNET_CONSTANTS_SERVICE_TIMEOUT;
  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES != try_connect (handle))
  {
#if DEBUG_DHT
    LOG (GNUNET_ERROR_TYPE_DEBUG, "GNS reconnect failed(!)\n");
#endif
    return;
  }
  GNUNET_CONTAINER_multihashmap_iterate (handle->active_requests,
                                         &add_request_to_pending, handle);
  process_pending_messages (handle);
}


/**
 * Try reconnecting to the GNS service.
 *
 * @param handle handle to gns to (possibly) disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_GNS_Handle *handle)
{
  if (handle->client == NULL)
    return;
  GNUNET_assert (handle->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  if (NULL != handle->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
  handle->th = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from GNS service, will try to reconnect in %llu ms\n",
              (unsigned long long) handle->retry_time.rel_value);
  GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
  handle->client = NULL;
  handle->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (handle->retry_time, &try_reconnect, handle);
}


/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_GNS_Handle *
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_GNS_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_GNS_Handle));
  handle->cfg = cfg;
  handle->uid_gen =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  handle->active_requests = GNUNET_CONTAINER_multihashmap_create (ht_len);
  if (GNUNET_NO == try_connect (handle))
  {
    GNUNET_GNS_disconnect (handle);
    return NULL;
  }
  return handle;
}


/**
 * Shutdown connection with the GNS service.
 *
 * @param handle handle of the GNS connection to stop
 */
void
GNUNET_GNS_disconnect (struct GNUNET_GNS_Handle *handle)
{
	/* disco from GNS */
}


/**
 * Add a new record to the GNS.
 *
 * @param handle handle to GNS service
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
 */
void
GNUNET_GNS_add_record (struct GNUNET_GNS_Handle *handle, const GNUNET_HashCode * key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type, size_t size, const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout, GNUNET_SCHEDULER_Task cont,
                void *cont_cls)
{
	/* add record to local db, dht; sign etc */
}


/**
 * Perform an asynchronous Lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param timeout how long to wait for transmission of this request to the service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @return handle to stop the async get
 */
struct GNUNET_GNS_LookupHandle *
GNUNET_GNS_lookup_start (struct GNUNET_GNS_Handle *handle,
                      struct GNUNET_TIME_Relative timeout,
                      enum GNUNET_BLOCK_Type type, const GNUNET_HashCode * key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options, const void *xquery,
                      size_t xquery_size, GNUNET_GNS_LookupIterator iter,
                      void *iter_cls)
{
  /* look for local entries, start dht lookup, return lookup_handle */
}


/**
 * Stop async GNS lookup.
 *
 * @param lookup_handle handle to the GNS lookup operation to stop
 */
void
GNUNET_GNS_lookup_stop (struct GNUNET_GNS_LookupHandle *lookup_handle)
{
  struct GNUNET_DHT_Handle *handle;
	/* TODO Stop dht lookups */
}


/* end of gns_api.c */
