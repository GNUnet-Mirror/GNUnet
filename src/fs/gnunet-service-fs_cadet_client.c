/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 GNUnet e.V.

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
   * Closure for @e proc
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
   * Which peer does this cadet go to?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Task to kill inactive cadets (we keep them around for
   * a few seconds to give the application a chance to give
   * us another query).
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Task to reset cadets that had errors (asynchronously,
   * as we may not be able to do it immediately during a
   * callback from the cadet API).
   */
  struct GNUNET_SCHEDULER_Task *reset_task;

};


/**
 * Cadet channel for creating outbound channels.
 */
struct GNUNET_CADET_Handle *cadet_handle;

/**
 * Map from peer identities to 'struct CadetHandles' with cadet
 * channels to those peers.
 */
struct GNUNET_CONTAINER_MultiPeerMap *cadet_map;


/* ********************* client-side code ************************* */


/**
 * Transmit pending requests via the cadet.
 *
 * @param cls `struct CadetHandle` to process
 */
static void
transmit_pending (void *cls);


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
 * Functions with this signature are called whenever a complete reply
 * is received.
 *
 * @param cls closure with the `struct CadetHandle`
 * @param srm the actual message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
check_reply (void *cls,
             const struct CadetReplyMessage *srm)
{
  /* We check later... */
  return GNUNET_OK;
}


/**
 * Task called when it is time to reset an cadet.
 *
 * @param cls the `struct CadetHandle` to tear down
 */
static void
reset_cadet_task (void *cls);


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
   * Number of bytes in @e data.
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
process_reply (void *cls,
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
 * Functions with this signature are called whenever a complete reply
 * is received.
 *
 * @param cls closure with the `struct CadetHandle`
 * @param srm the actual message
 */
static void
handle_reply (void *cls,
              const struct CadetReplyMessage *srm)
{
  struct CadetHandle *mh = cls;
  struct HandleReplyClosure hrc;
  uint16_t msize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_HashCode query;

  msize = ntohs (srm->header.size) - sizeof (struct CadetReplyMessage);
  type = (enum GNUNET_BLOCK_Type) ntohl (srm->type);
  if (GNUNET_YES !=
      GNUNET_BLOCK_get_key (GSF_block_ctx,
			    type,
			    &srm[1],
                            msize,
                            &query))
  {
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received bogus reply of type %u with %u bytes via cadet from peer %s\n",
                type,
                msize,
                GNUNET_i2s (&mh->target));
    reset_cadet_async (mh);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received reply `%s' via cadet from peer %s\n",
	      GNUNET_h2s (&query),
	      GNUNET_i2s (&mh->target));
  GNUNET_CADET_receive_done (mh->channel);
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
					      &process_reply,
					      &hrc);
  if (GNUNET_NO == hrc.found)
  {
    GNUNET_STATISTICS_update (GSF_stats,
			      gettext_noop ("# replies received via cadet dropped"), 1,
			      GNUNET_NO);
  }
}


/**
 * Function called by cadet when a client disconnects.
 * Cleans up our `struct CadetClient` of that channel.
 *
 * @param cls our `struct CadetClient`
 * @param channel channel of the disconnecting client
 */
static void
disconnect_cb (void *cls,
               const struct GNUNET_CADET_Channel *channel)
{
  struct CadetHandle *mh = cls;
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
  /* FIXME: for flow control, implement? */
#if 0
  /* Something like this instead of the GNUNET_MQ_notify_sent() in
     transmit_pending() might be good (once the window change CB works...) */
  if (0 < window_size) /* test needed? */
    transmit_pending (mh);
#endif
}


/**
 * We had a serious error, tear down and re-create cadet from scratch.
 *
 * @param mh cadet to reset
 */
static void
reset_cadet (struct CadetHandle *mh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Resetting cadet channel to %s\n",
	      GNUNET_i2s (&mh->target));
  if (NULL != mh->channel)
  {
    GNUNET_CADET_channel_destroy (mh->channel);
    mh->channel = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (mh->waiting_map,
					 &move_to_pending,
					 mh);
  {
    struct GNUNET_MQ_MessageHandler handlers[] = {
      GNUNET_MQ_hd_var_size (reply,
                             GNUNET_MESSAGE_TYPE_FS_CADET_REPLY,
                             struct CadetReplyMessage,
                             mh),
      GNUNET_MQ_handler_end ()
    };
    struct GNUNET_HashCode port;

    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER,
                        strlen (GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER),
                        &port);
    mh->channel = GNUNET_CADET_channel_create (cadet_handle,
                                               mh,
                                               &mh->target,
                                               &port,
                                               &window_change_cb,
                                               &disconnect_cb,
                                               handlers);
  }
  transmit_pending (mh);
}


/**
 * Task called when it is time to destroy an inactive cadet channel.
 *
 * @param cls the `struct CadetHandle` to tear down
 */
static void
cadet_timeout (void *cls)
{
  struct CadetHandle *mh = cls;
  struct GNUNET_CADET_Channel *tun;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on cadet channel to %s\n",
	      GNUNET_i2s (&mh->target));
  mh->timeout_task = NULL;
  tun = mh->channel;
  mh->channel = NULL;
  if (NULL != tun)
    GNUNET_CADET_channel_destroy (tun);
}


/**
 * Task called when it is time to reset an cadet.
 *
 * @param cls the `struct CadetHandle` to tear down
 */
static void
reset_cadet_task (void *cls)
{
  struct CadetHandle *mh = cls;

  mh->reset_task = NULL;
  reset_cadet (mh);
}


/**
 * Transmit pending requests via the cadet.
 *
 * @param cls `struct CadetHandle` to process
 */
static void
transmit_pending (void *cls)
{
  struct CadetHandle *mh = cls;
  struct GNUNET_MQ_Handle *mq = GNUNET_CADET_get_mq (mh->channel);
  struct GSF_CadetRequest *sr;
  struct GNUNET_MQ_Envelope *env;
  struct CadetQueryMessage *sqm;

  if ( (0 != GNUNET_MQ_get_length (mq)) ||
       (NULL == (sr = mh->pending_head)) )
    return;
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
  env = GNUNET_MQ_msg (sqm,
                       GNUNET_MESSAGE_TYPE_FS_CADET_QUERY);
  GNUNET_MQ_env_set_options(env,
			      GNUNET_MQ_PREF_RELIABLE);
  sqm->type = htonl (sr->type);
  sqm->query = sr->query;
  GNUNET_MQ_notify_sent (env,
                         &transmit_pending,
                         mh);
  GNUNET_MQ_send (mq,
                  env);
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
  {
    struct GNUNET_MQ_MessageHandler handlers[] = {
      GNUNET_MQ_hd_var_size (reply,
                             GNUNET_MESSAGE_TYPE_FS_CADET_REPLY,
                             struct CadetReplyMessage,
                             mh),
      GNUNET_MQ_handler_end ()
    };
    struct GNUNET_HashCode port;

    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER,
                        strlen (GNUNET_APPLICATION_PORT_FS_BLOCK_TRANSFER),
                        &port);
    mh->channel = GNUNET_CADET_channel_create (cadet_handle,
                                               mh,
                                               &mh->target,
                                               &port,
                                               &window_change_cb,
                                               &disconnect_cb,
                                               handlers);
  }
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
                 GSF_CadetReplyProcessor proc,
                 void *proc_cls)
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
 * Function called on each active cadets to shut them down.
 *
 * @param cls NULL
 * @param key target peer, unused
 * @param value the `struct CadetHandle` to destroy
 * @return #GNUNET_YES (continue to iterate)
 */
int
GSF_cadet_release_clients (void *cls,
                           const struct GNUNET_PeerIdentity *key,
                           void *value)
{
  struct CadetHandle *mh = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on cadet channel to %s\n",
	      GNUNET_i2s (&mh->target));
  if (NULL != mh->channel)
  {
    struct GNUNET_CADET_Channel *channel = mh->channel;

    mh->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
  if (NULL != mh->reset_task)
  {
    GNUNET_SCHEDULER_cancel (mh->reset_task);
    mh->reset_task = NULL;
  }
  return GNUNET_YES;
}



/* end of gnunet-service-fs_cadet_client.c */
