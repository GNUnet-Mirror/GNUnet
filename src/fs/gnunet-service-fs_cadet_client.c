/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_cadet_client.c
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
 * After how long do we reset connections without replies?
 */
#define CLIENT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * Handle for a cadet to another peer.
 */
struct CadetHandle;


/**
 * Handle for a request that is going out via cadet API.
 */
struct GSF_CadetRequest
{

  /**
   * DLL.
   */
  struct GSF_CadetRequest *next;

  /**
   * DLL.
   */
  struct GSF_CadetRequest *prev;

  /**
   * Which cadet is this request associated with?
   */
  struct CadetHandle *mh;

  /**
   * Function to call with the result.
   */
  GSF_CadetReplyProcessor proc;

  /**
   * Closure for 'proc'
   */
  void *proc_cls;

  /**
   * Query to transmit to the other peer.
   */
  struct GNUNET_HashCode query;

  /**
   * Desired type for the reply.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Did we transmit this request already? #GNUNET_YES if we are
   * in the 'waiting_map', #GNUNET_NO if we are in the 'pending' DLL.
   */
  int was_transmitted;
};


/**
 * Handle for a cadet to another peer.
 */
struct CadetHandle
{
  /**
   * Head of DLL of pending requests on this cadet.
   */
  struct GSF_CadetRequest *pending_head;

  /**
   * Tail of DLL of pending requests on this cadet.
   */
  struct GSF_CadetRequest *pending_tail;

  /**
   * Map from query to `struct GSF_CadetRequest`s waiting for
   * a reply.
   */
  struct GNUNET_CONTAINER_MultiHashMap *waiting_map;

  /**
   * Channel to the other peer.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Handle for active write operation, or NULL.
   */
  struct GNUNET_CADET_TransmitHandle *wh;

  /**
   * Which peer does this cadet go to?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Task to kill inactive cadets (we keep them around for
   * a few seconds to give the application a chance to give
   * us another query).
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Task to reset cadets that had errors (asynchronously,
   * as we may not be able to do it immediately during a
   * callback from the cadet API).
   */
  struct GNUNET_SCHEDULER_Task * reset_task;

};


/**
 * Cadet channel for creating outbound channels.
 */
static struct GNUNET_CADET_Handle *cadet_handle;

/**
 * Map from peer identities to 'struct CadetHandles' with cadet
 * channels to those peers.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *cadet_map;


/* ********************* client-side code ************************* */


/**
 * Transmit pending requests via the cadet.
 *
 * @param mh cadet to process
 */
static void
transmit_pending (struct CadetHandle *mh);


/**
 * Iterator called on each entry in a waiting map to
 * move it back to the pending list.
 *
 * @param cls the `struct CadetHandle`
 * @param key the key of the entry in the map (the query)
 * @param value the `struct GSF_CadetRequest` to move to pending
 * @return #GNUNET_YES (continue to iterate)
 */
static int
move_to_pending (void *cls,
		 const struct GNUNET_HashCode *key,
		 void *value)
{
  struct CadetHandle *mh = cls;
  struct GSF_CadetRequest *sr = value;

  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (mh->waiting_map,
						       key,
						       value));
  GNUNET_CONTAINER_DLL_insert (mh->pending_head,
			       mh->pending_tail,
			       sr);
  sr->was_transmitted = GNUNET_NO;
  return GNUNET_YES;
}


/**
 * We had a serious error, tear down and re-create cadet from scratch.
 *
 * @param mh cadet to reset
 */
static void
reset_cadet (struct CadetHandle *mh)
{
  struct GNUNET_CADET_Channel *channel = mh->channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Resetting cadet channel to %s\n",
	      GNUNET_i2s (&mh->target));
  mh->channel = NULL;

  if (NULL != channel)
  {
    /* Avoid loop */
    if (NULL != mh->wh)
    {
      GNUNET_CADET_notify_transmit_ready_cancel (mh->wh);
      mh->wh = NULL;
    }
    GNUNET_CADET_channel_destroy (channel);
  }
  GNUNET_CONTAINER_multihashmap_iterate (mh->waiting_map,
					 &move_to_pending,
					 mh);
  mh->channel = GNUNET_CADET_channel_create (cadet_handle,
					  mh,
					  &mh->target,
					  GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
					  GNUNET_CADET_OPTION_RELIABLE);
  transmit_pending (mh);
}


/**
 * Task called when it is time to destroy an inactive cadet channel.
 *
 * @param cls the `struct CadetHandle` to tear down
 * @param tc scheduler context, unused
 */
static void
cadet_timeout (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetHandle *mh = cls;
  struct GNUNET_CADET_Channel *tun;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on cadet channel to %s\n",
	      GNUNET_i2s (&mh->target));
  mh->timeout_task = NULL;
  tun = mh->channel;
  mh->channel = NULL;
  if(NULL != tun)
	GNUNET_CADET_channel_destroy (tun);
}


/**
 * Task called when it is time to reset an cadet.
 *
 * @param cls the `struct CadetHandle` to tear down
 * @param tc scheduler context, unused
 */
static void
reset_cadet_task (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetHandle *mh = cls;

  mh->reset_task = NULL;
  reset_cadet (mh);
}


/**
 * We had a serious error, tear down and re-create cadet from scratch,
 * but do so asynchronously.
 *
 * @param mh cadet to reset
 */
static void
reset_cadet_async (struct CadetHandle *mh)
{
  if (NULL != mh->reset_task)
    GNUNET_SCHEDULER_cancel (mh->reset_task);
  mh->reset_task = GNUNET_SCHEDULER_add_now (&reset_cadet_task,
					     mh);
}


/**
 * Functions of this signature are called whenever we are ready to transmit
 * query via a cadet.
 *
 * @param cls the struct CadetHandle for which we did the write call
 * @param size the number of bytes that can be written to @a buf
 * @param buf where to write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_sqm (void *cls,
	      size_t size,
	      void *buf)
{
  struct CadetHandle *mh = cls;
  struct CadetQueryMessage sqm;
  struct GSF_CadetRequest *sr;

  mh->wh = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Cadet channel to %s failed during transmission attempt, rebuilding\n",
		GNUNET_i2s (&mh->target));
    reset_cadet_async (mh);
    return 0;
  }
  sr = mh->pending_head;
  if (NULL == sr)
    return 0;
  GNUNET_assert (size >= sizeof (struct CadetQueryMessage));
  GNUNET_CONTAINER_DLL_remove (mh->pending_head,
			       mh->pending_tail,
			       sr);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (mh->waiting_map,
						    &sr->query,
						    sr,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  sr->was_transmitted = GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending query for %s via cadet to %s\n",
	      GNUNET_h2s (&sr->query),
	      GNUNET_i2s (&mh->target));
  sqm.header.size = htons (sizeof (sqm));
  sqm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_CADET_QUERY);
  sqm.type = htonl (sr->type);
  sqm.query = sr->query;
  memcpy (buf, &sqm, sizeof (sqm));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Successfully transmitted %u bytes via cadet to %s\n",
	      (unsigned int) size,
	      GNUNET_i2s (&mh->target));
  transmit_pending (mh);
  return sizeof (sqm);
}


/**
 * Transmit pending requests via the cadet.
 *
 * @param mh cadet to process
 */
static void
transmit_pending (struct CadetHandle *mh)
{
  if (NULL == mh->channel)
    return;
  if (NULL != mh->wh)
    return;
  mh->wh = GNUNET_CADET_notify_transmit_ready (mh->channel, GNUNET_YES /* allow cork */,
					      GNUNET_TIME_UNIT_FOREVER_REL,
					      sizeof (struct CadetQueryMessage),
					      &transmit_sqm, mh);
}


/**
 * Closure for handle_reply().
 */
struct HandleReplyClosure
{

  /**
   * Reply payload.
   */
  const void *data;

  /**
   * Expiration time for the block.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Did we have a matching query?
   */
  int found;
};


/**
 * Iterator called on each entry in a waiting map to
 * process a result.
 *
 * @param cls the `struct HandleReplyClosure`
 * @param key the key of the entry in the map (the query)
 * @param value the `struct GSF_CadetRequest` to handle result for
 * @return #GNUNET_YES (continue to iterate)
 */
static int
handle_reply (void *cls,
	      const struct GNUNET_HashCode *key,
	      void *value)
{
  struct HandleReplyClosure *hrc = cls;
  struct GSF_CadetRequest *sr = value;

  sr->proc (sr->proc_cls,
	    hrc->type,
	    hrc->expiration,
	    hrc->data_size,
	    hrc->data);
  sr->proc = NULL;
  GSF_cadet_query_cancel (sr);
  hrc->found = GNUNET_YES;
  return GNUNET_YES;
}


/**
 * Functions with this signature are called whenever a complete reply
 * is received.
 *
 * @param cls closure with the `struct CadetHandle`
 * @param channel channel handle
 * @param channel_ctx channel context
 * @param message the actual message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
reply_cb (void *cls,
	  struct GNUNET_CADET_Channel *channel,
	  void **channel_ctx,
          const struct GNUNET_MessageHeader *message)
{
  struct CadetHandle *mh = *channel_ctx;
  const struct CadetReplyMessage *srm;
  struct HandleReplyClosure hrc;
  uint16_t msize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_HashCode query;

  msize = ntohs (message->size);
  if (sizeof (struct CadetReplyMessage) > msize)
  {
    GNUNET_break_op (0);
    reset_cadet_async (mh);
    return GNUNET_SYSERR;
  }
  srm = (const struct CadetReplyMessage *) message;
  msize -= sizeof (struct CadetReplyMessage);
  type = (enum GNUNET_BLOCK_Type) ntohl (srm->type);
  if (GNUNET_YES !=
      GNUNET_BLOCK_get_key (GSF_block_ctx,
			    type,
			    &srm[1], msize, &query))
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received bogus reply of type %u with %u bytes via cadet from peer %s\n",
                type,
                msize,
                GNUNET_i2s (&mh->target));
    reset_cadet_async (mh);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received reply `%s' via cadet from peer %s\n",
	      GNUNET_h2s (&query),
	      GNUNET_i2s (&mh->target));
  GNUNET_CADET_receive_done (channel);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# replies received via cadet"), 1,
			    GNUNET_NO);
  hrc.data = &srm[1];
  hrc.data_size = msize;
  hrc.expiration = GNUNET_TIME_absolute_ntoh (srm->expiration);
  hrc.type = type;
  hrc.found = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_get_multiple (mh->waiting_map,
					      &query,
					      &handle_reply,
					      &hrc);
  if (GNUNET_NO == hrc.found)
  {
    GNUNET_STATISTICS_update (GSF_stats,
			      gettext_noop ("# replies received via cadet dropped"), 1,
			      GNUNET_NO);
    return GNUNET_OK;
  }
  return GNUNET_OK;
}


/**
 * Get (or create) a cadet to talk to the given peer.
 *
 * @param target peer we want to communicate with
 */
static struct CadetHandle *
get_cadet (const struct GNUNET_PeerIdentity *target)
{
  struct CadetHandle *mh;

  mh = GNUNET_CONTAINER_multipeermap_get (cadet_map,
					  target);
  if (NULL != mh)
  {
    if (NULL != mh->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (mh->timeout_task);
      mh->timeout_task = NULL;
    }
    return mh;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating cadet channel to %s\n",
	      GNUNET_i2s (target));
  mh = GNUNET_new (struct CadetHandle);
  mh->reset_task = GNUNET_SCHEDULER_add_delayed (CLIENT_RETRY_TIMEOUT,
						 &reset_cadet_task,
						 mh);
  mh->waiting_map = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_YES);
  mh->target = *target;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multipeermap_put (cadet_map,
						    &mh->target,
						    mh,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  mh->channel = GNUNET_CADET_channel_create (cadet_handle,
                                            mh,
                                            &mh->target,
                                            GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
                                            GNUNET_CADET_OPTION_RELIABLE);
  GNUNET_assert (mh ==
                 GNUNET_CONTAINER_multipeermap_get (cadet_map,
                                                    target));
  return mh;
}


/**
 * Look for a block by directly contacting a particular peer.
 *
 * @param target peer that should have the block
 * @param query hash to query for the block
 * @param type desired type for the block
 * @param proc function to call with result
 * @param proc_cls closure for @a proc
 * @return handle to cancel the operation
 */
struct GSF_CadetRequest *
GSF_cadet_query (const struct GNUNET_PeerIdentity *target,
		const struct GNUNET_HashCode *query,
		enum GNUNET_BLOCK_Type type,
		GSF_CadetReplyProcessor proc, void *proc_cls)
{
  struct CadetHandle *mh;
  struct GSF_CadetRequest *sr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Preparing to send query for %s via cadet to %s\n",
	      GNUNET_h2s (query),
	      GNUNET_i2s (target));
  mh = get_cadet (target);
  sr = GNUNET_new (struct GSF_CadetRequest);
  sr->mh = mh;
  sr->proc = proc;
  sr->proc_cls = proc_cls;
  sr->type = type;
  sr->query = *query;
  GNUNET_CONTAINER_DLL_insert (mh->pending_head,
			       mh->pending_tail,
			       sr);
  transmit_pending (mh);
  return sr;
}


/**
 * Cancel an active request; must not be called after 'proc'
 * was calld.
 *
 * @param sr request to cancel
 */
void
GSF_cadet_query_cancel (struct GSF_CadetRequest *sr)
{
  struct CadetHandle *mh = sr->mh;
  GSF_CadetReplyProcessor p;

  p = sr->proc;
  sr->proc = NULL;
  if (NULL != p)
  {
    /* signal failure / cancellation to callback */
    p (sr->proc_cls, GNUNET_BLOCK_TYPE_ANY,
       GNUNET_TIME_UNIT_ZERO_ABS,
       0, NULL);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Cancelled query for %s via cadet to %s\n",
	      GNUNET_h2s (&sr->query),
	      GNUNET_i2s (&sr->mh->target));
  if (GNUNET_YES == sr->was_transmitted)
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_remove (mh->waiting_map,
							 &sr->query,
							 sr));
  else
    GNUNET_CONTAINER_DLL_remove (mh->pending_head,
				 mh->pending_tail,
				 sr);
  GNUNET_free (sr);
  if ( (0 == GNUNET_CONTAINER_multihashmap_size (mh->waiting_map)) &&
       (NULL == mh->pending_head) )
    mh->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
						     &cadet_timeout,
						     mh);
}


/**
 * Iterator called on each entry in a waiting map to
 * call the 'proc' continuation and release associated
 * resources.
 *
 * @param cls the `struct CadetHandle`
 * @param key the key of the entry in the map (the query)
 * @param value the `struct GSF_CadetRequest` to clean up
 * @return #GNUNET_YES (continue to iterate)
 */
static int
free_waiting_entry (void *cls,
		    const struct GNUNET_HashCode *key,
		    void *value)
{
  struct GSF_CadetRequest *sr = value;

  GSF_cadet_query_cancel (sr);
  return GNUNET_YES;
}


/**
 * Function called by cadet when a client disconnects.
 * Cleans up our `struct CadetClient` of that channel.
 *
 * @param cls NULL
 * @param channel channel of the disconnecting client
 * @param channel_ctx our `struct CadetClient`
 */
static void
cleaner_cb (void *cls,
	    const struct GNUNET_CADET_Channel *channel,
	    void *channel_ctx)
{
  struct CadetHandle *mh = channel_ctx;
  struct GSF_CadetRequest *sr;

  if (NULL == mh->channel)
    return; /* being destroyed elsewhere */
  GNUNET_assert (channel == mh->channel);
  mh->channel = NULL;
  while (NULL != (sr = mh->pending_head))
    GSF_cadet_query_cancel (sr);
  /* first remove `mh` from the `cadet_map`, so that if the
     callback from `free_waiting_entry()` happens to re-issue
     the request, we don't immediately have it back in the
     `waiting_map`. */
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multipeermap_remove (cadet_map,
						       &mh->target,
						       mh));
  GNUNET_CONTAINER_multihashmap_iterate (mh->waiting_map,
					 &free_waiting_entry,
					 mh);
  if (NULL != mh->wh)
    GNUNET_CADET_notify_transmit_ready_cancel (mh->wh);
  if (NULL != mh->timeout_task)
    GNUNET_SCHEDULER_cancel (mh->timeout_task);
  if (NULL != mh->reset_task)
    GNUNET_SCHEDULER_cancel (mh->reset_task);
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (mh->waiting_map));
  GNUNET_CONTAINER_multihashmap_destroy (mh->waiting_map);
  GNUNET_free (mh);
}


/**
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_start_client ()
{
  static const struct GNUNET_CADET_MessageHandler handlers[] = {
    { &reply_cb, GNUNET_MESSAGE_TYPE_FS_CADET_REPLY, 0 },
    { NULL, 0, 0 }
  };

  cadet_map = GNUNET_CONTAINER_multipeermap_create (16, GNUNET_YES);
  cadet_handle = GNUNET_CADET_connect (GSF_cfg,
				     NULL,
				     NULL,
				     &cleaner_cb,
				     handlers,
				     NULL);
}


/**
 * Function called on each active cadets to shut them down.
 *
 * @param cls NULL
 * @param key target peer, unused
 * @param value the `struct CadetHandle` to destroy
 * @return #GNUNET_YES (continue to iterate)
 */
static int
release_cadets (void *cls,
	       const struct GNUNET_PeerIdentity *key,
	       void *value)
{
  struct CadetHandle *mh = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on cadet channel to %s\n",
	      GNUNET_i2s (&mh->target));
  if (NULL != mh->channel)
    GNUNET_CADET_channel_destroy (mh->channel);
  return GNUNET_YES;
}


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_stop_client ()
{
  GNUNET_CONTAINER_multipeermap_iterate (cadet_map,
					 &release_cadets,
					 NULL);
  GNUNET_CONTAINER_multipeermap_destroy (cadet_map);
  cadet_map = NULL;
  if (NULL != cadet_handle)
  {
    GNUNET_CADET_disconnect (cadet_handle);
    cadet_handle = NULL;
  }
}


/* end of gnunet-service-fs_cadet_client.c */
