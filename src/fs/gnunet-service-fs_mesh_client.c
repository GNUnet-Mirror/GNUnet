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
 * @file fs/gnunet-service-fs_mesh_client.c
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
#include "gnunet_mesh_service.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_indexing.h"
#include "gnunet-service-fs_mesh.h"


/**
 * After how long do we reset connections without replies?
 */
#define CLIENT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * Handle for a mesh to another peer.
 */
struct MeshHandle;


/**
 * Handle for a request that is going out via mesh API.
 */
struct GSF_MeshRequest
{

  /**
   * DLL.
   */
  struct GSF_MeshRequest *next;

  /**
   * DLL.
   */
  struct GSF_MeshRequest *prev;

  /**
   * Which mesh is this request associated with?
   */
  struct MeshHandle *mh;

  /**
   * Function to call with the result.
   */
  GSF_MeshReplyProcessor proc;

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
   * Did we transmit this request already? YES if we are
   * in the 'waiting_map', NO if we are in the 'pending' DLL.
   */
  int was_transmitted;
};


/**
 * Handle for a mesh to another peer.
 */
struct MeshHandle
{
  /**
   * Head of DLL of pending requests on this mesh.
   */
  struct GSF_MeshRequest *pending_head;

  /**
   * Tail of DLL of pending requests on this mesh.
   */
  struct GSF_MeshRequest *pending_tail;

  /**
   * Map from query to 'struct GSF_MeshRequest's waiting for
   * a reply.
   */
  struct GNUNET_CONTAINER_MultiHashMap *waiting_map;

  /**
   * Channel to the other peer.
   */
  struct GNUNET_MESH_Channel *channel;

  /**
   * Handle for active write operation, or NULL.
   */
  struct GNUNET_MESH_TransmitHandle *wh;

  /**
   * Which peer does this mesh go to?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Task to kill inactive meshs (we keep them around for
   * a few seconds to give the application a chance to give
   * us another query).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Task to reset meshs that had errors (asynchronously,
   * as we may not be able to do it immediately during a
   * callback from the mesh API).
   */
  GNUNET_SCHEDULER_TaskIdentifier reset_task;

};


/**
 * Mesh channel for creating outbound channels.
 */
static struct GNUNET_MESH_Handle *mesh_handle;

/**
 * Map from peer identities to 'struct MeshHandles' with mesh
 * channels to those peers.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *mesh_map;


/* ********************* client-side code ************************* */


/**
 * Transmit pending requests via the mesh.
 *
 * @param mh mesh to process
 */
static void
transmit_pending (struct MeshHandle *mh);


/**
 * Iterator called on each entry in a waiting map to
 * move it back to the pending list.
 *
 * @param cls the 'struct MeshHandle'
 * @param key the key of the entry in the map (the query)
 * @param value the 'struct GSF_MeshRequest' to move to pending
 * @return GNUNET_YES (continue to iterate)
 */
static int
move_to_pending (void *cls,
		 const struct GNUNET_HashCode *key,
		 void *value)
{
  struct MeshHandle *mh = cls;
  struct GSF_MeshRequest *sr = value;

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
 * We had a serious error, tear down and re-create mesh from scratch.
 *
 * @param mh mesh to reset
 */
static void
reset_mesh (struct MeshHandle *mh)
{
  struct GNUNET_MESH_Channel *channel = mh->channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Resetting mesh channel to %s\n",
	      GNUNET_i2s (&mh->target));
  mh->channel = NULL;
  if (NULL != channel)
    GNUNET_MESH_channel_destroy (channel);
  GNUNET_CONTAINER_multihashmap_iterate (mh->waiting_map,
					 &move_to_pending,
					 mh);
  mh->channel = GNUNET_MESH_channel_create (mesh_handle,
					  mh,
					  &mh->target,
					  GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
					  GNUNET_NO,
					  GNUNET_YES);
  transmit_pending (mh);
}


/**
 * Task called when it is time to destroy an inactive mesh channel.
 *
 * @param cls the 'struct MeshHandle' to tear down
 * @param tc scheduler context, unused
 */
static void
mesh_timeout (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshHandle *mh = cls;
  struct GNUNET_MESH_Channel *tun;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on mesh channel to %s\n",
	      GNUNET_i2s (&mh->target));
  mh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  tun = mh->channel;
  mh->channel = NULL;
  GNUNET_MESH_channel_destroy (tun);
}


/**
 * Task called when it is time to reset an mesh.
 *
 * @param cls the 'struct MeshHandle' to tear down
 * @param tc scheduler context, unused
 */
static void
reset_mesh_task (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshHandle *mh = cls;

  mh->reset_task = GNUNET_SCHEDULER_NO_TASK;
  reset_mesh (mh);
}


/**
 * We had a serious error, tear down and re-create mesh from scratch,
 * but do so asynchronously.
 *
 * @param mh mesh to reset
 */
static void
reset_mesh_async (struct MeshHandle *mh)
{
  if (GNUNET_SCHEDULER_NO_TASK != mh->reset_task)
    GNUNET_SCHEDULER_cancel (mh->reset_task);
  mh->reset_task = GNUNET_SCHEDULER_add_now (&reset_mesh_task,
					     mh);
}


/**
 * Functions of this signature are called whenever we are ready to transmit
 * query via a mesh.
 *
 * @param cls the struct MeshHandle for which we did the write call
 * @param size the number of bytes that can be written to @a buf
 * @param buf where to write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_sqm (void *cls,
	      size_t size,
	      void *buf)
{
  struct MeshHandle *mh = cls;
  struct MeshQueryMessage sqm;
  struct GSF_MeshRequest *sr;

  mh->wh = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Mesh channel to %s failed during transmission attempt, rebuilding\n",
		GNUNET_i2s (&mh->target));
    reset_mesh_async (mh);
    return 0;
  }
  sr = mh->pending_head;
  if (NULL == sr)
    return 0;
  GNUNET_assert (size >= sizeof (struct MeshQueryMessage));
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
	      "Sending query for %s via mesh to %s\n",
	      GNUNET_h2s (&sr->query),
	      GNUNET_i2s (&mh->target));
  sqm.header.size = htons (sizeof (sqm));
  sqm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_MESH_QUERY);
  sqm.type = htonl (sr->type);
  sqm.query = sr->query;
  memcpy (buf, &sqm, sizeof (sqm));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Successfully transmitted %u bytes via mesh to %s\n",
	      (unsigned int) size,
	      GNUNET_i2s (&mh->target));
  transmit_pending (mh);
  return sizeof (sqm);
}


/**
 * Transmit pending requests via the mesh.
 *
 * @param mh mesh to process
 */
static void
transmit_pending (struct MeshHandle *mh)
{
  if (NULL == mh->channel)
    return;
  if (NULL != mh->wh)
    return;
  mh->wh = GNUNET_MESH_notify_transmit_ready (mh->channel, GNUNET_YES /* allow cork */,
					      GNUNET_TIME_UNIT_FOREVER_REL,
					      sizeof (struct MeshQueryMessage),
					      &transmit_sqm, mh);
}


/**
 * Closure for 'handle_reply'.
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
 * @param cls the 'struct HandleReplyClosure'
 * @param key the key of the entry in the map (the query)
 * @param value the 'struct GSF_MeshRequest' to handle result for
 * @return GNUNET_YES (continue to iterate)
 */
static int
handle_reply (void *cls,
	      const struct GNUNET_HashCode *key,
	      void *value)
{
  struct HandleReplyClosure *hrc = cls;
  struct GSF_MeshRequest *sr = value;

  sr->proc (sr->proc_cls,
	    hrc->type,
	    hrc->expiration,
	    hrc->data_size,
	    hrc->data);
  GSF_mesh_query_cancel (sr);
  hrc->found = GNUNET_YES;
  return GNUNET_YES;
}


/**
 * Functions with this signature are called whenever a complete reply
 * is received.
 *
 * @param cls closure with the 'struct MeshHandle'
 * @param channel channel handle
 * @param channel_ctx channel context
 * @param message the actual message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
reply_cb (void *cls,
	  struct GNUNET_MESH_Channel *channel,
	  void **channel_ctx,
          const struct GNUNET_MessageHeader *message)
{
  struct MeshHandle *mh = *channel_ctx;
  const struct MeshReplyMessage *srm;
  struct HandleReplyClosure hrc;
  uint16_t msize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_HashCode query;

  msize = ntohs (message->size);
  if (sizeof (struct MeshReplyMessage) > msize)
  {
    GNUNET_break_op (0);
    reset_mesh_async (mh);
    return GNUNET_SYSERR;
  }
  srm = (const struct MeshReplyMessage *) message;
  msize -= sizeof (struct MeshReplyMessage);
  type = (enum GNUNET_BLOCK_Type) ntohl (srm->type);
  if (GNUNET_YES !=
      GNUNET_BLOCK_get_key (GSF_block_ctx,
			    type,
			    &srm[1], msize, &query))
  {
    GNUNET_break_op (0);
    reset_mesh_async (mh);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received reply `%s' via mesh from peer %s\n",
	      GNUNET_h2s (&query),
	      GNUNET_i2s (&mh->target));
  GNUNET_MESH_receive_done (channel);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# replies received via mesh"), 1,
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
			      gettext_noop ("# replies received via mesh dropped"), 1,
			      GNUNET_NO);
    return GNUNET_OK;
  }
  return GNUNET_OK;
}


/**
 * Get (or create) a mesh to talk to the given peer.
 *
 * @param target peer we want to communicate with
 */
static struct MeshHandle *
get_mesh (const struct GNUNET_PeerIdentity *target)
{
  struct MeshHandle *mh;

  mh = GNUNET_CONTAINER_multipeermap_get (mesh_map,
					  target);
  if (NULL != mh)
  {
    if (GNUNET_SCHEDULER_NO_TASK != mh->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (mh->timeout_task);
      mh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    return mh;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating mesh channel to %s\n",
	      GNUNET_i2s (target));
  mh = GNUNET_new (struct MeshHandle);
  mh->reset_task = GNUNET_SCHEDULER_add_delayed (CLIENT_RETRY_TIMEOUT,
						 &reset_mesh_task,
						 mh);
  mh->waiting_map = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_YES);
  mh->target = *target;
  mh->channel = GNUNET_MESH_channel_create (mesh_handle,
					  mh,
					  &mh->target,
					  GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
					  GNUNET_NO,
					  GNUNET_YES);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multipeermap_put (mesh_map,
						    &mh->target,
						    mh,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
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
struct GSF_MeshRequest *
GSF_mesh_query (const struct GNUNET_PeerIdentity *target,
		const struct GNUNET_HashCode *query,
		enum GNUNET_BLOCK_Type type,
		GSF_MeshReplyProcessor proc, void *proc_cls)
{
  struct MeshHandle *mh;
  struct GSF_MeshRequest *sr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Preparing to send query for %s via mesh to %s\n",
	      GNUNET_h2s (query),
	      GNUNET_i2s (target));
  mh = get_mesh (target);
  sr = GNUNET_new (struct GSF_MeshRequest);
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
GSF_mesh_query_cancel (struct GSF_MeshRequest *sr)
{
  struct MeshHandle *mh = sr->mh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Cancelled query for %s via mesh to %s\n",
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
						     &mesh_timeout,
						     mh);
}


/**
 * Iterator called on each entry in a waiting map to
 * call the 'proc' continuation and release associated
 * resources.
 *
 * @param cls the 'struct MeshHandle'
 * @param key the key of the entry in the map (the query)
 * @param value the 'struct GSF_MeshRequest' to clean up
 * @return GNUNET_YES (continue to iterate)
 */
static int
free_waiting_entry (void *cls,
		    const struct GNUNET_HashCode *key,
		    void *value)
{
  struct GSF_MeshRequest *sr = value;

  sr->proc (sr->proc_cls, GNUNET_BLOCK_TYPE_ANY,
	    GNUNET_TIME_UNIT_FOREVER_ABS,
	    0, NULL);
  GSF_mesh_query_cancel (sr);
  return GNUNET_YES;
}


/**
 * Function called by mesh when a client disconnects.
 * Cleans up our 'struct MeshClient' of that channel.
 *
 * @param cls NULL
 * @param channel channel of the disconnecting client
 * @param channel_ctx our `struct MeshClient`
 */
static void
cleaner_cb (void *cls,
	    const struct GNUNET_MESH_Channel *channel,
	    void *channel_ctx)
{
  struct MeshHandle *mh = channel_ctx;
  struct GSF_MeshRequest *sr;

  if (NULL == mh->channel)
    return; /* being destroyed elsewhere */
  GNUNET_assert (channel == mh->channel);
  mh->channel = NULL;
  while (NULL != (sr = mh->pending_head))
  {
    sr->proc (sr->proc_cls, GNUNET_BLOCK_TYPE_ANY,
	      GNUNET_TIME_UNIT_FOREVER_ABS,
	      0, NULL);
    GSF_mesh_query_cancel (sr);
  }
  GNUNET_CONTAINER_multihashmap_iterate (mh->waiting_map,
					 &free_waiting_entry,
					 mh);
  if (NULL != mh->wh)
    GNUNET_MESH_notify_transmit_ready_cancel (mh->wh);
  if (GNUNET_SCHEDULER_NO_TASK != mh->timeout_task)
    GNUNET_SCHEDULER_cancel (mh->timeout_task);
  if (GNUNET_SCHEDULER_NO_TASK != mh->reset_task)
    GNUNET_SCHEDULER_cancel (mh->reset_task);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multipeermap_remove (mesh_map,
						       &mh->target,
						       mh));
  GNUNET_CONTAINER_multihashmap_destroy (mh->waiting_map);
  GNUNET_free (mh);
}


/**
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_mesh_start_client ()
{
  static const struct GNUNET_MESH_MessageHandler handlers[] = {
    { &reply_cb, GNUNET_MESSAGE_TYPE_FS_MESH_REPLY, 0 },
    { NULL, 0, 0 }
  };

  mesh_map = GNUNET_CONTAINER_multipeermap_create (16, GNUNET_YES);
  mesh_handle = GNUNET_MESH_connect (GSF_cfg,
				     NULL,
				     NULL,
				     &cleaner_cb,
				     handlers,
				     NULL);
}


/**
 * Function called on each active meshs to shut them down.
 *
 * @param cls NULL
 * @param key target peer, unused
 * @param value the `struct MeshHandle` to destroy
 * @return #GNUNET_YES (continue to iterate)
 */
static int
release_meshs (void *cls,
	       const struct GNUNET_PeerIdentity *key,
	       void *value)
{
  struct MeshHandle *mh = value;
  struct GNUNET_MESH_Channel *tun;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on mesh channel to %s\n",
	      GNUNET_i2s (&mh->target));
  tun = mh->channel;
  mh->channel = NULL;
  if (NULL != tun)
    GNUNET_MESH_channel_destroy (tun);
  return GNUNET_YES;
}


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_mesh_stop_client ()
{
  GNUNET_CONTAINER_multipeermap_iterate (mesh_map,
					 &release_meshs,
					 NULL);
  GNUNET_CONTAINER_multipeermap_destroy (mesh_map);
  mesh_map = NULL;
  if (NULL != mesh_handle)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }
}


/* end of gnunet-service-fs_mesh_client.c */
