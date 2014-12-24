/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
   * Handle for active write operation, or NULL.
   */
  struct GNUNET_CADET_TransmitHandle *wh;

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
 * Listen channel for incoming requests.
 */
static struct GNUNET_CADET_Handle *listen_channel;

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
 * @param tc scheduler context
 */
static void
timeout_cadet_task (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
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
 * We're done handling a request from a client, read the next one.
 *
 * @param sc client to continue reading requests from
 */
static void
continue_reading (struct CadetClient *sc)
{
  refresh_timeout_task (sc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Finished processing cadet request from client %p, ready to receive the next one\n",
	      sc);
  GNUNET_CADET_receive_done (sc->channel);
}


/**
 * Transmit the next entry from the write queue.
 *
 * @param sc where to process the write queue
 */
static void
continue_writing (struct CadetClient *sc);


/**
 * Send a reply now, cadet is ready.
 *
 * @param cls closure with the `struct CadetClient` which sent the query
 * @param size number of bytes available in @a buf
 * @param buf where to write the message
 * @return number of bytes written to @a buf
 */
static size_t
write_continuation (void *cls,
		    size_t size,
		    void *buf)
{
  struct CadetClient *sc = cls;
  struct GNUNET_CADET_Channel *tun;
  struct WriteQueueItem *wqi;
  size_t ret;

  sc->wh = NULL;
  if (NULL == (wqi = sc->wqi_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write queue empty, reading more requests\n");
    return 0;
  }
  if ( (0 == size) ||
       (size < wqi->msize) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Transmission of reply failed, terminating cadet\n");
    tun = sc->channel;
    sc->channel = NULL;
    GNUNET_CADET_channel_destroy (tun);
    return 0;
  }
  GNUNET_CONTAINER_DLL_remove (sc->wqi_head,
			       sc->wqi_tail,
			       wqi);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitted %u byte reply via cadet to %p\n",
	      (unsigned int) size,
	      sc);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# Blocks transferred via cadet"), 1,
			    GNUNET_NO);
  memcpy (buf, &wqi[1], ret = wqi->msize);
  GNUNET_free (wqi);
  continue_writing (sc);
  return ret;
}


/**
 * Transmit the next entry from the write queue.
 *
 * @param sc where to process the write queue
 */
static void
continue_writing (struct CadetClient *sc)
{
  struct WriteQueueItem *wqi;
  struct GNUNET_CADET_Channel *tun;

  if (NULL != sc->wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write pending, waiting for it to complete\n");
    return; /* write already pending */
  }
  if (NULL == (wqi = sc->wqi_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write queue empty, reading more requests\n");
    continue_reading (sc);
    return;
  }
  sc->wh = GNUNET_CADET_notify_transmit_ready (sc->channel, GNUNET_NO,
					      GNUNET_TIME_UNIT_FOREVER_REL,
					      wqi->msize,
					      &write_continuation,
					      sc);
  if (NULL == sc->wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write failed; terminating cadet\n");
    tun = sc->channel;
    sc->channel = NULL;
    GNUNET_CADET_channel_destroy (tun);
    return;
  }
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
  struct WriteQueueItem *wqi;
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
                              gettext_noop ("# queries received via CADET not answered"), 1,
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
					  size, data, type,
					  priority, anonymity,
					  expiration, uid,
					  &handle_datastore_reply,
					  sc))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "On-demand encoding request failed\n");
      continue_writing (sc);
    }
    return;
  }
  if (msize > GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  wqi = GNUNET_malloc (sizeof (struct WriteQueueItem) + msize);
  wqi->msize = msize;
  srm = (struct CadetReplyMessage *) &wqi[1];
  srm->header.size = htons ((uint16_t) msize);
  srm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_CADET_REPLY);
  srm->type = htonl (type);
  srm->expiration = GNUNET_TIME_absolute_hton (expiration);
  memcpy (&srm[1], data, size);
  sc->reply_size = msize;
  GNUNET_CONTAINER_DLL_insert (sc->wqi_head,
			       sc->wqi_tail,
			       wqi);
  continue_writing (sc);
}


/**
 * Functions with this signature are called whenever a
 * complete query message is received.
 *
 * Do not call #GNUNET_SERVER_mst_destroy() in callback
 *
 * @param cls closure with the `struct CadetClient`
 * @param channel channel handle
 * @param channel_ctx channel context
 * @param message the actual message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
request_cb (void *cls,
	    struct GNUNET_CADET_Channel *channel,
	    void **channel_ctx,
	    const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *sc = *channel_ctx;
  const struct CadetQueryMessage *sqm;

  sqm = (const struct CadetQueryMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received query for `%s' via cadet from client %p\n",
	      GNUNET_h2s (&sqm->query),
	      sc);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# queries received via cadet"), 1,
			    GNUNET_NO);
  refresh_timeout_task (sc);
  sc->qe = GNUNET_DATASTORE_get_key (GSF_dsh,
				     0,
				     &sqm->query,
				     ntohl (sqm->type),
				     0 /* priority */,
				     GSF_datastore_queue_size,
				     GNUNET_TIME_UNIT_FOREVER_REL,
				     &handle_datastore_reply, sc);
  if (NULL == sc->qe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Queueing request with datastore failed (queue full?)\n");
    continue_writing (sc);
  }
  return GNUNET_OK;
}


/**
 * Functions of this type are called upon new cadet connection from other peers.
 *
 * @param cls the closure from GNUNET_CADET_connect
 * @param channel the channel representing the cadet
 * @param initiator the identity of the peer who wants to establish a cadet
 *            with us; NULL on binding error
 * @param port cadet port used for the incoming connection
 * @param options channel option flags
 * @return initial channel context (our 'struct CadetClient')
 */
static void *
accept_cb (void *cls,
	   struct GNUNET_CADET_Channel *channel,
	   const struct GNUNET_PeerIdentity *initiator,
	   uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  struct CadetClient *sc;

  GNUNET_assert (NULL != channel);
  if (sc_count >= sc_count_max)
  {
    GNUNET_STATISTICS_update (GSF_stats,
			      gettext_noop ("# cadet client connections rejected"), 1,
			      GNUNET_NO);
    GNUNET_CADET_channel_destroy (channel);
    return NULL;
  }
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# cadet connections active"), 1,
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
 * Cleans up our 'struct CadetClient' of that channel.
 *
 * @param cls NULL
 * @param channel channel of the disconnecting client
 * @param channel_ctx our 'struct CadetClient'
 */
static void
cleaner_cb (void *cls,
	    const struct GNUNET_CADET_Channel *channel,
	    void *channel_ctx)
{
  struct CadetClient *sc = channel_ctx;
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
  if (NULL != sc->wh)
    GNUNET_CADET_notify_transmit_ready_cancel (sc->wh);
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
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_start_server ()
{
  static const struct GNUNET_CADET_MessageHandler handlers[] = {
    { &request_cb, GNUNET_MESSAGE_TYPE_FS_CADET_QUERY, sizeof (struct CadetQueryMessage)},
    { NULL, 0, 0 }
  };
  static const uint32_t ports[] = {
    GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
    0
  };

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_number (GSF_cfg,
					     "fs",
					     "MAX_CADET_CLIENTS",
					     &sc_count_max))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Initializing cadet FS server with a limit of %llu connections\n",
	      sc_count_max);
  listen_channel = GNUNET_CADET_connect (GSF_cfg,
				       NULL,
				       &accept_cb,
				       &cleaner_cb,
				       handlers,
				       ports);
}


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_stop_server ()
{
  if (NULL != listen_channel)
  {
    GNUNET_CADET_disconnect (listen_channel);
    listen_channel = NULL;
  }
  GNUNET_assert (NULL == sc_head);
  GNUNET_assert (0 == sc_count);
}

/* end of gnunet-service-fs_cadet.c */
