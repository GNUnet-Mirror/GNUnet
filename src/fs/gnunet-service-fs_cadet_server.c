/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013, 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file fs/gnunet-service-fs_cadet_server.c
 * @brief non-anonymous file-transfer
 * @author Christian Grothoff
 *
 * TODO:
 * - PORT is set to old application type, unsure if we should keep
 *   it that way (fine for now)
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_indexing.h"
#include "gnunet-service-fs_cadet.h"

/**
 * After how long do we termiante idle connections?
 */
#define IDLE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)


/**
 * A message in the queue to be written to the cadet.
 */
struct WriteQueueItem
{
  /**
   * Kept in a DLL.
   */
  struct WriteQueueItem *next;

  /**
   * Kept in a DLL.
   */
  struct WriteQueueItem *prev;

  /**
   * Number of bytes of payload, allocated at the end of this struct.
   */
  size_t msize;
};


/**
 * Information we keep around for each active cadeting client.
 */
struct CadetClient
{
  /**
   * DLL
   */
  struct CadetClient *next;

  /**
   * DLL
   */
  struct CadetClient *prev;

  /**
   * Channel for communication.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Head of write queue.
   */
  struct WriteQueueItem *wqi_head;

  /**
   * Tail of write queue.
   */
  struct WriteQueueItem *wqi_tail;

  /**
   * Current active request to the datastore, if we have one pending.
   */
  struct GNUNET_DATASTORE_QueueEntry *qe;

  /**
   * Task that is scheduled to asynchronously terminate the connection.
   */
  struct GNUNET_SCHEDULER_Task * terminate_task;

  /**
   * Task that is scheduled to terminate idle connections.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Size of the last write that was initiated.
   */
  size_t reply_size;

};


/**
 * Listen port for incoming requests.
 */
static struct GNUNET_CADET_Port *cadet_port;

/**
 * Head of DLL of cadet clients.
 */
static struct CadetClient *sc_head;

/**
 * Tail of DLL of cadet clients.
 */
static struct CadetClient *sc_tail;

/**
 * Number of active cadet clients in the 'sc_*'-DLL.
 */
static unsigned int sc_count;

/**
 * Maximum allowed number of cadet clients.
 */
static unsigned long long sc_count_max;



/**
 * Task run to asynchronously terminate the cadet due to timeout.
 *
 * @param cls the 'struct CadetClient'
 */
static void
timeout_cadet_task (void *cls)
{
  struct CadetClient *sc = cls;
  struct GNUNET_CADET_Channel *tun;

  sc->timeout_task = NULL;
  tun = sc->channel;
  sc->channel = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout for inactive cadet client %p\n",
	      sc);
  GNUNET_CADET_channel_destroy (tun);
}


/**
 * Reset the timeout for the cadet client (due to activity).
 *
 * @param sc client handle to reset timeout for
 */
static void
refresh_timeout_task (struct CadetClient *sc)
{
  if (NULL != sc->timeout_task)
    GNUNET_SCHEDULER_cancel (sc->timeout_task);
  sc->timeout_task = GNUNET_SCHEDULER_add_delayed (IDLE_TIMEOUT,
						   &timeout_cadet_task,
						   sc);
}


/**
 * Check if we are done with the write queue, and if so tell CADET
 * that we are ready to read more.
 *
 * @param cls where to process the write queue
 */
static void
continue_writing (void *cls)
{
  struct CadetClient *sc = cls;
  struct GNUNET_MQ_Handle *mq;

  mq = GNUNET_CADET_get_mq (sc->channel);
  if (0 != GNUNET_MQ_get_length (mq))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write pending, waiting for it to complete\n");
    return;
  }
  refresh_timeout_task (sc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Finished processing cadet request from client %p, ready to receive the next one\n",
	      sc);
  GNUNET_CADET_receive_done (sc->channel);
}


/**
 * Process a datum that was stored in the datastore.
 *
 * @param cls closure with the `struct CadetClient` which sent the query
 * @param key key for the content
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
handle_datastore_reply (void *cls,
			const struct GNUNET_HashCode *key,
			size_t size,
			const void *data,
			enum GNUNET_BLOCK_Type type,
			uint32_t priority,
			uint32_t anonymity,
			struct GNUNET_TIME_Absolute expiration,
                        uint64_t uid)
{
  struct CadetClient *sc = cls;
  size_t msize = size + sizeof (struct CadetReplyMessage);
  struct GNUNET_MQ_Envelope *env;
  struct CadetReplyMessage *srm;

  sc->qe = NULL;
  if (NULL == data)
  {
    /* no result, this should not really happen, as for
       non-anonymous routing only peers that HAVE the
       answers should be queried; OTOH, this is not a
       hard error as we might have had the answer in the
       past and the user might have unindexed it. Hence
       we log at level "INFO" for now. */
    if (NULL == key)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Have no answer and the query was NULL\n");
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Have no answer for query `%s'\n",
		  GNUNET_h2s (key));
    }
    GNUNET_STATISTICS_update (GSF_stats,
                              gettext_noop ("# queries received via CADET not answered"),
                              1,
                              GNUNET_NO);
    continue_writing (sc);
    return;
  }
  if (GNUNET_BLOCK_TYPE_FS_ONDEMAND == type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Performing on-demand encoding for query %s\n",
		GNUNET_h2s (key));
    if (GNUNET_OK !=
	GNUNET_FS_handle_on_demand_block (key,
					  size,
                                          data,
                                          type,
					  priority,
                                          anonymity,
					  expiration,
                                          uid,
					  &handle_datastore_reply,
					  sc))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "On-demand encoding request failed\n");
      continue_writing (sc);
    }
    return;
  }
  if (msize > GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    continue_writing (sc);
    return;
  }
  GNUNET_break (GNUNET_BLOCK_TYPE_ANY != type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting transmission of %u byte reply of type %d for query `%s' via cadet to %p\n",
	      (unsigned int) size,
              (unsigned int) type,
	      GNUNET_h2s (key),
	      sc);
  env = GNUNET_MQ_msg_extra (srm,
                             size,
                             GNUNET_MESSAGE_TYPE_FS_CADET_REPLY);
  srm->type = htonl (type);
  srm->expiration = GNUNET_TIME_absolute_hton (expiration);
  GNUNET_memcpy (&srm[1],
                 data,
                 size);
  GNUNET_MQ_notify_sent (env,
                         &continue_writing,
                         sc);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# Blocks transferred via cadet"),
                            1,
			    GNUNET_NO);
  GNUNET_MQ_send (GNUNET_CADET_get_mq (sc->channel),
                  env);
}


/**
 * Functions with this signature are called whenever a
 * complete query message is received.
 *
 * @param cls closure with the `struct CadetClient`
 * @param sqm the actual message
 */
static void
handle_request (void *cls,
                const struct CadetQueryMessage *sqm)
{
  struct CadetClient *sc = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received query for `%s' via cadet from client %p\n",
	      GNUNET_h2s (&sqm->query),
	      sc);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# queries received via cadet"),
                            1,
			    GNUNET_NO);
  refresh_timeout_task (sc);
  sc->qe = GNUNET_DATASTORE_get_key (GSF_dsh,
                                     0 /* next_uid */,
                                     false /* random */,
                                     &sqm->query,
                                     ntohl (sqm->type),
                                     0 /* priority */,
                                     GSF_datastore_queue_size,
                                     &handle_datastore_reply,
                                     sc);
  if (NULL == sc->qe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Queueing request with datastore failed (queue full?)\n");
    continue_writing (sc);
  }
}


/**
 * Functions of this type are called upon new cadet connection from other peers.
 *
 * @param cls the closure from GNUNET_CADET_connect
 * @param channel the channel representing the cadet
 * @param initiator the identity of the peer who wants to establish a cadet
 *            with us; NULL on binding error
 * @return initial channel context (our `struct CadetClient`)
 */
static void *
connect_cb (void *cls,
            struct GNUNET_CADET_Channel *channel,
            const struct GNUNET_PeerIdentity *initiator)
{
  struct CadetClient *sc;

  GNUNET_assert (NULL != channel);
  if (sc_count >= sc_count_max)
  {
    GNUNET_STATISTICS_update (GSF_stats,
			      gettext_noop ("# cadet client connections rejected"),
                              1,
			      GNUNET_NO);
    GNUNET_CADET_channel_destroy (channel);
    return NULL;
  }
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# cadet connections active"),
                            1,
			    GNUNET_NO);
  sc = GNUNET_new (struct CadetClient);
  sc->channel = channel;
  GNUNET_CONTAINER_DLL_insert (sc_head,
			       sc_tail,
			       sc);
  sc_count++;
  refresh_timeout_task (sc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Accepting inbound cadet connection from `%s' as client %p\n",
	      GNUNET_i2s (initiator),
	      sc);
  return sc;
}


/**
 * Function called by cadet when a client disconnects.
 * Cleans up our `struct CadetClient` of that channel.
 *
 * @param cls  our `struct CadetClient`
 * @param channel channel of the disconnecting client
 * @param channel_ctx
 */
static void
disconnect_cb (void *cls,
               const struct GNUNET_CADET_Channel *channel)
{
  struct CadetClient *sc = cls;
  struct WriteQueueItem *wqi;

  if (NULL == sc)
    return;
  sc->channel = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Terminating cadet connection with client %p\n",
	      sc);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# cadet connections active"), -1,
			    GNUNET_NO);
  if (NULL != sc->terminate_task)
    GNUNET_SCHEDULER_cancel (sc->terminate_task);
  if (NULL != sc->timeout_task)
    GNUNET_SCHEDULER_cancel (sc->timeout_task);
  if (NULL != sc->qe)
    GNUNET_DATASTORE_cancel (sc->qe);
  while (NULL != (wqi = sc->wqi_head))
  {
    GNUNET_CONTAINER_DLL_remove (sc->wqi_head,
				 sc->wqi_tail,
				 wqi);
    GNUNET_free (wqi);
  }
  GNUNET_CONTAINER_DLL_remove (sc_head,
			       sc_tail,
			       sc);
  sc_count--;
  GNUNET_free (sc);
}


/**
 * Function called whenever an MQ-channel's transmission window size changes.
 *
 * The first callback in an outgoing channel will be with a non-zero value
 * and will mean the channel is connected to the destination.
 *
 * For an incoming channel it will be called immediately after the
 * #GNUNET_CADET_ConnectEventHandler, also with a non-zero value.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end (henceforth invalid).
 * @param window_size New window size. If the is more messages than buffer size
 *                    this value will be negative..
 */
static void
window_change_cb (void *cls,
                  const struct GNUNET_CADET_Channel *channel,
                  int window_size)
{
  /* FIXME: could do flow control here... */
}


/**
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_start_server ()
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (request,
                             GNUNET_MESSAGE_TYPE_FS_CADET_QUERY,
                             struct CadetQueryMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_HashCode port;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_number (GSF_cfg,
					     "fs",
					     "MAX_CADET_CLIENTS",
					     &sc_count_max))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Initializing cadet FS server with a limit of %llu connections\n",
	      sc_count_max);
  cadet_map = GNUNET_CONTAINER_multipeermap_create (16, GNUNET_YES);
  cadet_handle = GNUNET_CADET_connect (GSF_cfg);
  GNUNET_assert (NULL != cadet_handle);
  GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER,
                      strlen (GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER),
                      &port);
  cadet_port = GNUNET_CADET_open_port (cadet_handle,
                                       &port,
                                       &connect_cb,
                                       NULL,
                                       &window_change_cb,
                                       &disconnect_cb,
                                       handlers);
}


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_stop_server ()
{
  GNUNET_CONTAINER_multipeermap_iterate (cadet_map,
					 &GSF_cadet_release_clients,
					 NULL);
  GNUNET_CONTAINER_multipeermap_destroy (cadet_map);
  cadet_map = NULL;
  if (NULL != cadet_port)
  {
    GNUNET_CADET_close_port (cadet_port);
    cadet_port = NULL;
  }
  if (NULL != cadet_handle)
  {
    GNUNET_CADET_disconnect (cadet_handle);
    cadet_handle = NULL;
  }
  GNUNET_assert (NULL == sc_head);
  GNUNET_assert (0 == sc_count);
}

/* end of gnunet-service-fs_cadet.c */
