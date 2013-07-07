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
 * @file fs/gnunet-service-fs_mesh.c
 * @brief non-anonymous file-transfer
 * @author Christian Grothoff
 *
 * TODO:
 * - update comments on functions (still matches 'mesh')
 * - MESH2 API doesn't allow flow control for server yet (needed!)
 * - likely need to register clean up handler with mesh to handle
 *   client disconnect (likely leaky right now)
 * - server is optional, currently client code will NPE if we have
 *   no server, again MESH2 API requirement forcing this for now
 * - message handlers are symmetric for client/server, should be
 *   separated (currently clients can get requests and servers can
 *   handle answers, not good)
 * - code is entirely untested
 * - might have overlooked a few possible simplifications
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
 * After how long do we termiante idle connections?
 */
#define IDLE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * After how long do we reset connections without replies?
 */
#define CLIENT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


/**
 * A message in the queue to be written to the mesh.
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
 * Information we keep around for each active meshing client.
 */
struct StreamClient
{
  /**
   * DLL
   */ 
  struct StreamClient *next;

  /**
   * DLL
   */ 
  struct StreamClient *prev;

  /**
   * Socket for communication.
   */ 
  struct GNUNET_MESH_Tunnel *socket;

  /**
   * Handle for active write operation, or NULL.
   */ 
  struct GNUNET_MESH_TransmitHandle *wh;

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
  GNUNET_SCHEDULER_TaskIdentifier terminate_task;

  /**
   * Task that is scheduled to terminate idle connections.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Size of the last write that was initiated.
   */ 
  size_t reply_size;

};


/**
 * Query from one peer, asking the other for CHK-data.
 */
struct StreamQueryMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_FS_STREAM_QUERY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Block type must be DBLOCK or IBLOCK.
   */
  uint32_t type;

  /**
   * Query hash from CHK (hash of encrypted block).
   */
  struct GNUNET_HashCode query;

};


/**
 * Reply to a StreamQueryMessage.
 */
struct StreamReplyMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_FS_STREAM_REPLY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Block type must be DBLOCK or IBLOCK.
   */
  uint32_t type;

  /**
   * Expiration time for the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* followed by the encrypted block */

};


/** 
 * Handle for a mesh to another peer.
 */
struct StreamHandle;


/**
 * Handle for a request that is going out via mesh API.
 */
struct GSF_StreamRequest
{

  /**
   * DLL.
   */
  struct GSF_StreamRequest *next;

  /**
   * DLL.
   */
  struct GSF_StreamRequest *prev;

  /**
   * Which mesh is this request associated with?
   */
  struct StreamHandle *sh;

  /**
   * Function to call with the result.
   */
  GSF_StreamReplyProcessor proc;

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
   * in the 'waiting' DLL, NO if we are in the 'pending' DLL.
   */
  int was_transmitted;
};


/** 
 * Handle for a mesh to another peer.
 */
struct StreamHandle
{
  /**
   * Head of DLL of pending requests on this mesh.
   */
  struct GSF_StreamRequest *pending_head;

  /**
   * Tail of DLL of pending requests on this mesh.
   */
  struct GSF_StreamRequest *pending_tail;

  /**
   * Map from query to 'struct GSF_StreamRequest's waiting for
   * a reply.
   */
  struct GNUNET_CONTAINER_MultiHashMap *waiting_map;

  /**
   * Connection to the other peer.
   */
  struct GNUNET_MESH_Tunnel *mesh;

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

  /**
   * Is this mesh ready for transmission?
   */
  int is_ready;

};


/**
 * Listen socket for incoming requests.
 */
static struct GNUNET_MESH_Handle *listen_socket;

/**
 * Head of DLL of mesh clients.
 */ 
static struct StreamClient *sc_head;

/**
 * Tail of DLL of mesh clients.
 */ 
static struct StreamClient *sc_tail;

/**
 * Number of active mesh clients in the 'sc_*'-DLL.
 */
static unsigned int sc_count;

/**
 * Maximum allowed number of mesh clients.
 */
static unsigned long long sc_count_max;

/**
 * Map from peer identities to 'struct StreamHandles' with meshs to
 * those peers.
 */
static struct GNUNET_CONTAINER_MultiHashMap *mesh_map;


/* ********************* client-side code ************************* */

/**
 * Iterator called on each entry in a waiting map to 
 * call the 'proc' continuation and release associated
 * resources.
 *
 * @param cls the 'struct StreamHandle'
 * @param key the key of the entry in the map (the query)
 * @param value the 'struct GSF_StreamRequest' to clean up
 * @return GNUNET_YES (continue to iterate)
 */
static int
free_waiting_entry (void *cls,
		    const struct GNUNET_HashCode *key,
		    void *value)
{
  struct GSF_StreamRequest *sr = value;

  sr->proc (sr->proc_cls, GNUNET_BLOCK_TYPE_ANY,
	    GNUNET_TIME_UNIT_FOREVER_ABS,
	    0, NULL);
  GSF_mesh_query_cancel (sr);
  return GNUNET_YES;
}


/**
 * Destroy a mesh handle.
 *
 * @param sh mesh to process
 */
static void
destroy_mesh_handle (struct StreamHandle *sh)
{
  struct GSF_StreamRequest *sr;

  while (NULL != (sr = sh->pending_head))
  {
    sr->proc (sr->proc_cls, GNUNET_BLOCK_TYPE_ANY,
	      GNUNET_TIME_UNIT_FOREVER_ABS,
	      0, NULL);
    GSF_mesh_query_cancel (sr);
  }
  GNUNET_CONTAINER_multihashmap_iterate (sh->waiting_map,
					 &free_waiting_entry,
					 sh);
  if (NULL != sh->wh)
    GNUNET_MESH_notify_transmit_ready_cancel (sh->wh);
  if (GNUNET_SCHEDULER_NO_TASK != sh->timeout_task)
    GNUNET_SCHEDULER_cancel (sh->timeout_task);
  if (GNUNET_SCHEDULER_NO_TASK != sh->reset_task)
    GNUNET_SCHEDULER_cancel (sh->reset_task);
  GNUNET_MESH_tunnel_destroy (sh->mesh);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (mesh_map,
						       &sh->target.hashPubKey,
						       sh));
  GNUNET_CONTAINER_multihashmap_destroy (sh->waiting_map);
  GNUNET_free (sh);
}


/**
 * Transmit pending requests via the mesh.
 *
 * @param sh mesh to process
 */
static void
transmit_pending (struct StreamHandle *sh);


/**
 * Iterator called on each entry in a waiting map to 
 * move it back to the pending list.
 *
 * @param cls the 'struct StreamHandle'
 * @param key the key of the entry in the map (the query)
 * @param value the 'struct GSF_StreamRequest' to move to pending
 * @return GNUNET_YES (continue to iterate)
 */
static int
move_to_pending (void *cls,
		 const struct GNUNET_HashCode *key,
		 void *value)
{
  struct StreamHandle *sh = cls;
  struct GSF_StreamRequest *sr = value;
  
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (sh->waiting_map,
						       key,
						       value));
  GNUNET_CONTAINER_DLL_insert (sh->pending_head,
			       sh->pending_tail,
			       sr);
  sr->was_transmitted = GNUNET_NO;
  return GNUNET_YES;
}


/**
 * We had a serious error, tear down and re-create mesh from scratch.
 *
 * @param sh mesh to reset
 */
static void
reset_mesh (struct StreamHandle *sh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Resetting mesh to %s\n",
	      GNUNET_i2s (&sh->target));
  GNUNET_MESH_tunnel_destroy (sh->mesh);
  sh->is_ready = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_iterate (sh->waiting_map,
					 &move_to_pending,
					 sh);
  sh->mesh = GNUNET_MESH_tunnel_create (listen_socket,
					  sh,				    
					  &sh->target,
					  GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER);
}


/**
 * Task called when it is time to destroy an inactive mesh.
 *
 * @param cls the 'struct StreamHandle' to tear down
 * @param tc scheduler context, unused
 */
static void
mesh_timeout (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StreamHandle *sh = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Timeout on mesh to %s\n",
	      GNUNET_i2s (&sh->target));
  sh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  destroy_mesh_handle (sh);
}


/**
 * Task called when it is time to reset an mesh.
 *
 * @param cls the 'struct StreamHandle' to tear down
 * @param tc scheduler context, unused
 */
static void
reset_mesh_task (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StreamHandle *sh = cls;

  sh->reset_task = GNUNET_SCHEDULER_NO_TASK;
  reset_mesh (sh);
}


/**
 * We had a serious error, tear down and re-create mesh from scratch,
 * but do so asynchronously.
 *
 * @param sh mesh to reset
 */
static void
reset_mesh_async (struct StreamHandle *sh)
{
  if (GNUNET_SCHEDULER_NO_TASK != sh->reset_task)
    GNUNET_SCHEDULER_cancel (sh->reset_task);
  sh->reset_task = GNUNET_SCHEDULER_add_now (&reset_mesh_task,
					     sh);
}


/**
 * Functions of this signature are called whenever we are ready to transmit
 * query via a mesh.
 *
 * @param cls the struct StreamHandle for which we did the write call
 * @param size the number of bytes that can be written to 'buf'
 * @param buf where to write the message
 * @return number of bytes written to 'buf'
 */
static size_t
transmit_sqm (void *cls,
	      size_t size,
	      void *buf)
{
  struct StreamHandle *sh = cls;
  struct StreamQueryMessage sqm;
  struct GSF_StreamRequest *sr;

  sh->wh = NULL;
  if (NULL == buf)
  {
    reset_mesh (sh);
    return 0;
  }
  sr = sh->pending_head;
  if (NULL == sr)
    return 0;
  GNUNET_assert (size >= sizeof (struct StreamQueryMessage));
  GNUNET_CONTAINER_DLL_remove (sh->pending_head,
			       sh->pending_tail,
			       sr);
  GNUNET_CONTAINER_multihashmap_put (sh->waiting_map,
				     &sr->query,
				     sr,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending query via mesh to %s\n",
	      GNUNET_i2s (&sh->target));
  sr->was_transmitted = GNUNET_YES;
  sqm.header.size = htons (sizeof (sqm));
  sqm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_STREAM_QUERY);
  sqm.type = htonl (sr->type);
  sqm.query = sr->query;
  memcpy (buf, &sqm, sizeof (sqm));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Successfully transmitted %u bytes via mesh to %s\n",
	      (unsigned int) size,
	      GNUNET_i2s (&sh->target));
  transmit_pending (sh);
  return sizeof (sqm);
}
	  

/**
 * Transmit pending requests via the mesh.
 *
 * @param sh mesh to process
 */
static void
transmit_pending (struct StreamHandle *sh)
{
  if (NULL != sh->wh)
    return;
  sh->wh = GNUNET_MESH_notify_transmit_ready (sh->mesh, GNUNET_YES /* allow cork */,
					      GNUNET_TIME_UNIT_FOREVER_REL,
					      sizeof (struct StreamQueryMessage),
					      &transmit_sqm, sh);
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
 * @param value the 'struct GSF_StreamRequest' to handle result for
 * @return GNUNET_YES (continue to iterate)
 */
static int
handle_reply (void *cls,
	      const struct GNUNET_HashCode *key,
	      void *value)
{
  struct HandleReplyClosure *hrc = cls;
  struct GSF_StreamRequest *sr = value;
  
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
 * Functions with this signature are called whenever a
 * complete reply is received.
 *
 * @param cls closure with the 'struct StreamHandle'
 * @param tunnel tunnel handle
 * @param tunnel_ctx tunnel context
 * @param message the actual message
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
reply_cb (void *cls,
	  struct GNUNET_MESH_Tunnel *tunnel,
	  void **tunnel_ctx,
          const struct GNUNET_MessageHeader *message)
{
  struct StreamHandle *sh = *tunnel_ctx;
  const struct StreamReplyMessage *srm;
  struct HandleReplyClosure hrc;
  uint16_t msize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_HashCode query;

  msize = ntohs (message->size);
  if (sizeof (struct StreamReplyMessage) > msize)
  {
    GNUNET_break_op (0);
    reset_mesh_async (sh);
    return GNUNET_SYSERR;
  }
  srm = (const struct StreamReplyMessage *) message;
  msize -= sizeof (struct StreamReplyMessage);
  type = (enum GNUNET_BLOCK_Type) ntohl (srm->type);
  if (GNUNET_YES !=
      GNUNET_BLOCK_get_key (GSF_block_ctx,
			    type,
			    &srm[1], msize, &query))
  {
    GNUNET_break_op (0); 
    reset_mesh_async (sh);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received reply `%s' via mesh\n",
	      GNUNET_h2s (&query));
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# replies received via mesh"), 1,
			    GNUNET_NO);
  hrc.data = &srm[1];
  hrc.data_size = msize;
  hrc.expiration = GNUNET_TIME_absolute_ntoh (srm->expiration);
  hrc.type = type;
  hrc.found = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_get_multiple (sh->waiting_map,
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
static struct StreamHandle *
get_mesh (const struct GNUNET_PeerIdentity *target)
{
  struct StreamHandle *sh;

  sh = GNUNET_CONTAINER_multihashmap_get (mesh_map,
					  &target->hashPubKey);
  if (NULL != sh)
  {
    if (GNUNET_SCHEDULER_NO_TASK != sh->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (sh->timeout_task);
      sh->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    return sh;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating mesh to %s\n",
	      GNUNET_i2s (target));
  sh = GNUNET_malloc (sizeof (struct StreamHandle));
  sh->reset_task = GNUNET_SCHEDULER_add_delayed (CLIENT_RETRY_TIMEOUT,
						 &reset_mesh_task,
						 sh);
  sh->waiting_map = GNUNET_CONTAINER_multihashmap_create (512, GNUNET_YES);
  sh->target = *target;
  sh->mesh = GNUNET_MESH_tunnel_create (listen_socket,
					  sh,
					  &sh->target,
					  GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (mesh_map,
						    &sh->target.hashPubKey,
						    sh,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return sh;
}


/**
 * Look for a block by directly contacting a particular peer.
 *
 * @param target peer that should have the block
 * @param query hash to query for the block
 * @param type desired type for the block
 * @param proc function to call with result
 * @param proc_cls closure for 'proc'
 * @return handle to cancel the operation
 */
struct GSF_StreamRequest *
GSF_mesh_query (const struct GNUNET_PeerIdentity *target,
		  const struct GNUNET_HashCode *query,
		  enum GNUNET_BLOCK_Type type,
		  GSF_StreamReplyProcessor proc, void *proc_cls)
{
  struct StreamHandle *sh;
  struct GSF_StreamRequest *sr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Preparing to send query for %s via mesh to %s\n",
	      GNUNET_h2s (query),
	      GNUNET_i2s (target));
  sh = get_mesh (target);
  sr = GNUNET_malloc (sizeof (struct GSF_StreamRequest));
  sr->sh = sh;
  sr->proc = proc;
  sr->proc_cls = proc_cls;
  sr->type = type;
  sr->query = *query;
  GNUNET_CONTAINER_DLL_insert (sh->pending_head,
			       sh->pending_tail,
			       sr);
  if (GNUNET_YES == sh->is_ready)
    transmit_pending (sh);
  return sr;
}


/**
 * Cancel an active request; must not be called after 'proc'
 * was calld.
 *
 * @param sr request to cancel
 */
void
GSF_mesh_query_cancel (struct GSF_StreamRequest *sr)
{
  struct StreamHandle *sh = sr->sh;

  if (GNUNET_YES == sr->was_transmitted)
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_remove (sh->waiting_map,
							 &sr->query,
							 sr));
  else
    GNUNET_CONTAINER_DLL_remove (sh->pending_head,
				 sh->pending_tail,
				 sr);
  GNUNET_free (sr);
  if ( (0 == GNUNET_CONTAINER_multihashmap_size (sh->waiting_map)) &&
       (NULL == sh->pending_head) )
    sh->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
						     &mesh_timeout,
						     sh);
}


/* ********************* server-side code ************************* */


/**
 * We're done with a particular client, clean up.
 *
 * @param sc client to clean up
 */
static void
terminate_mesh (struct StreamClient *sc)
{
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# mesh connections active"), -1,
			    GNUNET_NO);
  if (GNUNET_SCHEDULER_NO_TASK != sc->terminate_task)
    GNUNET_SCHEDULER_cancel (sc->terminate_task); 
  if (GNUNET_SCHEDULER_NO_TASK != sc->timeout_task)
    GNUNET_SCHEDULER_cancel (sc->timeout_task); 
  if (NULL != sc->wh)
    GNUNET_MESH_notify_transmit_ready_cancel (sc->wh);
  if (NULL != sc->qe)
    GNUNET_DATASTORE_cancel (sc->qe);
  GNUNET_MESH_tunnel_destroy (sc->socket);
  struct WriteQueueItem *wqi;
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
 * Task run to asynchronously terminate the mesh due to timeout.
 *
 * @param cls the 'struct StreamClient'
 * @param tc scheduler context
 */ 
static void
timeout_mesh_task (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StreamClient *sc = cls;

  sc->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  terminate_mesh (sc);
}


/**
 * Reset the timeout for the mesh client (due to activity).
 *
 * @param sc client handle to reset timeout for
 */
static void
refresh_timeout_task (struct StreamClient *sc)
{
  if (GNUNET_SCHEDULER_NO_TASK != sc->timeout_task)
    GNUNET_SCHEDULER_cancel (sc->timeout_task); 
  sc->timeout_task = GNUNET_SCHEDULER_add_delayed (IDLE_TIMEOUT,
						   &timeout_mesh_task,
						   sc);
}


/**
 * We're done handling a request from a client, read the next one.
 *
 * @param sc client to continue reading requests from
 */
static void
continue_reading (struct StreamClient *sc)
{
  refresh_timeout_task (sc);
}


/**
 * Transmit the next entry from the write queue.
 *
 * @param sc where to process the write queue
 */
static void
continue_writing (struct StreamClient *sc);


/**
 * Send a reply now, mesh is ready.
 *
 * @param cls closure with the struct StreamClient which sent the query
 * @param size number of bytes available in 'buf'
 * @param buf where to write the message
 * @return number of bytes written to 'buf'
 */
static size_t
write_continuation (void *cls,
		    size_t size,
		    void *buf)
{
  struct StreamClient *sc = cls;
  struct WriteQueueItem *wqi;
  size_t ret;

  sc->wh = NULL;
  if (NULL == (wqi = sc->wqi_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write queue empty, reading more requests\n");
    return 0;
  }
  if (0 == size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Transmission of reply failed, terminating mesh\n");
    terminate_mesh (sc);    
    return 0;
  }
  GNUNET_CONTAINER_DLL_remove (sc->wqi_head,
			       sc->wqi_tail,
			       wqi);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitted %u byte reply via mesh\n",
	      (unsigned int) size);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# Blocks transferred via mesh"), 1,
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
continue_writing (struct StreamClient *sc)
{
  struct WriteQueueItem *wqi;

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
  sc->wh = GNUNET_MESH_notify_transmit_ready (sc->socket, GNUNET_NO,
					      GNUNET_TIME_UNIT_FOREVER_REL,
					      wqi->msize,				      
					      &write_continuation,
					      sc);
  if (NULL == sc->wh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Write failed; terminating mesh\n");
    terminate_mesh (sc);
    return;
  }
}


/**
 * Process a datum that was stored in the datastore.
 *
 * @param cls closure with the struct StreamClient which sent the query
 * @param key key for the content
 * @param size number of bytes in data
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
			const struct GNUNET_HashCode * key,
			size_t size, const void *data,
			enum GNUNET_BLOCK_Type type,
			uint32_t priority,
			uint32_t anonymity,
			struct GNUNET_TIME_Absolute
			expiration, uint64_t uid)
{
  struct StreamClient *sc = cls;
  size_t msize = size + sizeof (struct StreamReplyMessage);
  struct WriteQueueItem *wqi;
  struct StreamReplyMessage *srm;

  sc->qe = NULL;
  if (GNUNET_BLOCK_TYPE_FS_ONDEMAND == type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Performing on-demand encoding\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting transmission of %u byte reply for query `%s' via mesh\n",
	      (unsigned int) size,
	      GNUNET_h2s (key));
  wqi = GNUNET_malloc (sizeof (struct WriteQueueItem) + msize);
  wqi->msize = msize;
  srm = (struct StreamReplyMessage *) &wqi[1];
  srm->header.size = htons ((uint16_t) msize);
  srm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_STREAM_REPLY);
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
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure with the 'struct StreamClient'
 * @param tunnel tunnel handle
 * @param tunnel_ctx tunnel context
 * @param message the actual message
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
request_cb (void *cls,
	    struct GNUNET_MESH_Tunnel *tunnel,
	    void **tunnel_ctx,
	    const struct GNUNET_MessageHeader *message)
{
  struct StreamClient *sc = *tunnel_ctx;
  const struct StreamQueryMessage *sqm;

  sqm = (const struct StreamQueryMessage *) message;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received query for `%s' via mesh\n",
	      GNUNET_h2s (&sqm->query));
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# queries received via mesh"), 1,
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
 * Functions of this type are called upon new mesh connection from other peers.
 *
 * @param cls the closure from GNUNET_MESH_connect
 * @param socket the socket representing the mesh
 * @param initiator the identity of the peer who wants to establish a mesh
 *            with us; NULL on binding error
 * @param port mesh port used for the incoming connection
 * @return initial tunnel context (our 'struct StreamClient')
 */
static void *
accept_cb (void *cls,
	   struct GNUNET_MESH_Tunnel *socket,
	   const struct GNUNET_PeerIdentity *initiator,
	   uint32_t port)
{
  struct StreamClient *sc;

  GNUNET_assert (NULL != socket);
  if (sc_count >= sc_count_max)
  {
    GNUNET_STATISTICS_update (GSF_stats,
			      gettext_noop ("# mesh client connections rejected"), 1,
			      GNUNET_NO);
    GNUNET_MESH_tunnel_destroy (socket);
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Accepting inbound mesh connection from `%s'\n",
	      GNUNET_i2s (initiator));
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# mesh connections active"), 1,
			    GNUNET_NO);
  sc = GNUNET_malloc (sizeof (struct StreamClient));
  sc->socket = socket;
  GNUNET_CONTAINER_DLL_insert (sc_head,
			       sc_tail,
			       sc);
  sc_count++;
  refresh_timeout_task (sc);
  return sc;
}


/**
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_mesh_start ()
{
  static const struct GNUNET_MESH_MessageHandler handlers[] = {
    { &request_cb, GNUNET_MESSAGE_TYPE_FS_STREAM_QUERY, sizeof (struct StreamQueryMessage)},
    { &reply_cb, GNUNET_MESSAGE_TYPE_FS_STREAM_REPLY, 0 },
    { NULL, 0, 0 }
  };
  static const uint32_t ports[] = {
    GNUNET_APPLICATION_TYPE_FS_BLOCK_TRANSFER,
    0
  };

  mesh_map = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_YES);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (GSF_cfg,
					     "fs",
					     "MAX_STREAM_CLIENTS",
					     &sc_count_max))
  {
    listen_socket = GNUNET_MESH_connect (GSF_cfg,
					 NULL,
					 &accept_cb,
					 NULL /* FIXME: have a cleanup callback? */,
					 handlers,
					 ports);
  } 
}


/**
 * Function called on each active meshs to shut them down.
 *
 * @param cls NULL
 * @param key target peer, unused
 * @param value the 'struct StreamHandle' to destroy
 * @return GNUNET_YES (continue to iterate)
 */
static int
release_meshs (void *cls,
		 const struct GNUNET_HashCode *key,
		 void *value)
{
  struct StreamHandle *sh = value;

  destroy_mesh_handle (sh);
  return GNUNET_YES;
}


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_mesh_stop ()
{
  struct StreamClient *sc;

  while (NULL != (sc = sc_head))
    terminate_mesh (sc);
  if (NULL != listen_socket)
  {
    GNUNET_MESH_disconnect (listen_socket);
    listen_socket = NULL;
  }
  GNUNET_CONTAINER_multihashmap_iterate (mesh_map,
					 &release_meshs,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (mesh_map);
  mesh_map = NULL;
}

/* end of gnunet-service-fs_mesh.c */
