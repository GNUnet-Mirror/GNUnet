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
 * @file fs/gnunet-service-fs.c
 * @brief program that provides the file-sharing service
 * @author Christian Grothoff
 *
 * TODO:
 * - INDEX_START handling
 * - INDEX_LIST handling 
 * - UNINDEX handling 
 * - bloomfilter support (GET, CS-request with BF, etc.)
 * - all P2P messages
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_core_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_util_lib.h"
#include "fs.h"

/**
 * Our connection to the datastore.
 */
static struct GNUNET_DATASTORE_Handle *dsh;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle INDEX_START-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_index_start (void *cls,
		    struct GNUNET_SERVER_Client *client,
		    const struct GNUNET_MessageHeader *message)
{
  const struct IndexStartMessage *ism;
  const char *fn;
  uint16_t msize;

  msize = ntohs(message->size);
  if ( (msize <= sizeof (struct IndexStartMessage)) ||
       ( ((const char *)message)[msize-1] != '\0') )
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client,
				  GNUNET_SYSERR);
      return;
    }
  ism = (const struct IndexStartMessage*) message;
  fn = (const char*) &ism[1];
  // FIXME: store fn, hash, check, respond to client, etc.
}


/**
 * Handle INDEX_LIST_GET-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_index_list_get (void *cls,
		       struct GNUNET_SERVER_Client *client,
		       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_TransmitContext *tc;
  struct IndexInfoMessage *iim;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  size_t slen;
  char *fn;
  struct GNUNET_MessageHeader *msg;

  tc = GNUNET_SERVER_transmit_context_create (client);
  iim = (struct IndexInfoMessage*) buf;
  msg = &iim->header;
  while (0)
    {
      iim->reserved = 0;
      // FIXME: read actual list of indexed files...
      // iim->file_id = id;
      fn = "FIXME";
      slen = strlen (fn) + 1;
      if (slen + sizeof (struct IndexInfoMessage) > 
	  GNUNET_SERVER_MAX_MESSAGE_SIZE)
	{
	  GNUNET_break (0);
	  break;
	}
      memcpy (&iim[1], fn, slen);
      GNUNET_SERVER_transmit_context_append
	(tc,
	 &msg[1],
	 sizeof (struct IndexInfoMessage) 
	 - sizeof (struct GNUNET_MessageHeader) + slen,
	 GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY);
    }
  GNUNET_SERVER_transmit_context_append (tc,
					 NULL, 0,
					 GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END);
  GNUNET_SERVER_transmit_context_run (tc,
				      GNUNET_TIME_UNIT_MINUTES);
}


/**
 * Handle UNINDEX-message.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_unindex (void *cls,
		struct GNUNET_SERVER_Client *client,
		const struct GNUNET_MessageHeader *message)
{
  const struct UnindexMessage *um;
  struct GNUNET_SERVER_TransmitContext *tc;
  
  um = (const struct UnindexMessage*) message;
  // fixme: process!
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_SERVER_transmit_context_append (tc,
					 NULL, 0,
					 GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK);
  GNUNET_SERVER_transmit_context_run (tc,
				      GNUNET_TIME_UNIT_MINUTES);
}


/**
 * Signature of a function that is called whenever a datastore
 * request can be processed (or an entry put on the queue times out).
 *
 * @param cls closure
 * @param ok GNUNET_OK if DS is ready, GNUNET_SYSERR on timeout
 */
typedef void (*RequestFunction)(void *cls,
				int ok);


/**
 * Doubly-linked list of our requests for the datastore.
 */
struct DatastoreRequestQueue
{

  /**
   * This is a doubly-linked list.
   */
  struct DatastoreRequestQueue *next;

  /**
   * This is a doubly-linked list.
   */
  struct DatastoreRequestQueue *prev;

  /**
   * Function to call (will issue the request).
   */
  RequestFunction req;

  /**
   * Closure for req.
   */
  void *req_cls;

  /**
   * When should this request time-out because we don't care anymore?
   */
  struct GNUNET_TIME_Absolute timeout;
    
  /**
   * ID of task used for signaling timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

};


/**
 * Head of request queue for the datastore, sorted by timeout.
 */
static struct DatastoreRequestQueue *drq_head;

/**
 * Tail of request queue for the datastore.
 */
static struct DatastoreRequestQueue *drq_tail;


/**
 * Run the next DS request in our
 * queue, we're done with the current one.
 */
static void
next_ds_request ()
{
  struct DatastoreRequestQueue *e;
  
  while (NULL != (e = drq_head))
    {
      if (0 != GNUNET_TIME_absolute_get_remaining (e->timeout).value)
	break;
      if (e->task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (sched, e->task);
      GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, e);
      e->req (e->req_cls, GNUNET_NO);
      GNUNET_free (e);  
    }
  if (e == NULL)
    return;
  if (e->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (sched, e->task);
  e->task = GNUNET_SCHEDULER_NO_TASK;
  e->req (e->req_cls, GNUNET_YES);
  GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, e);
  GNUNET_free (e);  
}


/**
 * A datastore request had to be timed out. 
 *
 * @param cls closure (of type "struct DatastoreRequestQueue*")
 * @param tc task context, unused
 */
static void
timeout_ds_request (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DatastoreRequestQueue *e = cls;

  e->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, e);
  e->req (e->req_cls, GNUNET_NO);
  GNUNET_free (e);  
}


/**
 * Queue a request for the datastore.
 *
 * @param deadline by when the request should run
 * @param fun function to call once the request can be run
 * @param fun_cls closure for fun
 */
static struct DatastoreRequestQueue *
queue_ds_request (struct GNUNET_TIME_Relative deadline,
		  RequestFunction fun,
		  void *fun_cls)
{
  struct DatastoreRequestQueue *e;
  struct DatastoreRequestQueue *bef;

  if (drq_head == NULL)
    {
      /* no other requests pending, run immediately */
      fun (fun_cls, GNUNET_OK);
      return NULL;
    }
  e = GNUNET_malloc (sizeof (struct DatastoreRequestQueue));
  e->timeout = GNUNET_TIME_relative_to_absolute (deadline);
  e->req = fun;
  e->req_cls = fun_cls;
  if (deadline.value == GNUNET_TIME_UNIT_FOREVER_REL.value)
    {
      /* local request, highest prio, put at head of queue
	 regardless of deadline */
      bef = NULL;
    }
  else
    {
      bef = drq_tail;
      while ( (NULL != bef) &&
	      (e->timeout.value < bef->timeout.value) )
	bef = bef->prev;
    }
  GNUNET_CONTAINER_DLL_insert_after (drq_head, drq_tail, bef, e);
  if (deadline.value == GNUNET_TIME_UNIT_FOREVER_REL.value)
    return e;
  e->task = GNUNET_SCHEDULER_add_delayed (sched,
					  GNUNET_NO,
					  GNUNET_SCHEDULER_PRIORITY_BACKGROUND,
					  GNUNET_SCHEDULER_NO_TASK,
					  deadline,
					  &timeout_ds_request,
					  e);
  return e;				       
}


/**
 * Closure for processing START_SEARCH messages from a client.
 */
struct LocalGetContext
{

  /**
   * This is a doubly-linked list.
   */
  struct LocalGetContext *next;

  /**
   * This is a doubly-linked list.
   */
  struct LocalGetContext *prev;

  /**
   * Client that initiated the search.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Array of results that we've already received 
   * (can be NULL).
   */
  GNUNET_HashCode *results; 

  /**
   * Bloomfilter over all results (for fast query construction);
   * NULL if we don't have any results.
   */
  struct GNUNET_CONTAINER_BloomFilter *results_bf; 

  /**
   * DS request associated with this operation.
   */
  struct DatastoreRequestQueue *req;

  /**
   * Current result message to transmit to client (or NULL).
   */
  struct ContentMessage *result;
  
  /**
   * Type of the content that we're looking for.
   * 0 for any.
   */
  uint32_t type;

  /**
   * Desired anonymity level.
   */
  uint32_t anonymity_level;

  /**
   * Number of results actually stored in the results array.
   */
  unsigned int results_used;
  
  /**
   * Size of the results array in memory.
   */
  unsigned int results_size;

  /**
   * If the request is for a DBLOCK or IBLOCK, this is the identity of
   * the peer that is known to have a response.  Set to all-zeros if
   * such a target is not known (note that even if OUR anonymity
   * level is >0 we may happen to know the responder's identity;
   * nevertheless, we should probably not use it for a DHT-lookup
   * or similar blunt actions in order to avoid exposing ourselves).
   * <p>
   * If the request is for an SBLOCK, this is the identity of the
   * pseudonym to which the SBLOCK belongs. 
   * <p>
   * If the request is for a KBLOCK, "target" must be all zeros.
   */
  GNUNET_HashCode target;

  /**
   * Hash of the keyword (aka query) for KBLOCKs; Hash of
   * the CHK-encoded block for DBLOCKS and IBLOCKS (aka query)
   * and hash of the identifier XORed with the target for
   * SBLOCKS (aka query).
   */
  GNUNET_HashCode query;

};


/**
 * Head of doubly-linked LGC list.
 */
static struct LocalGetContext *lgc_head;

/**
 * Tail of doubly-linked LGC list.
 */
static struct LocalGetContext *lgc_tail;


/**
 * Free the state associated with a local get context.
 *
 * @param lgc the lgc to free
 */
static void
local_get_context_free (struct LocalGetContext *lgc) 
{
  GNUNET_CONTAINER_DLL_remove (lgc_head, lgc_tail, lgc);
  GNUNET_SERVER_client_drop (lgc->client); 
  GNUNET_free_non_null (lgc->results);
  if (lgc->results_bf != NULL)
    GNUNET_CONTAINER_bloomfilter_free (lgc->results_bf);
  if (lgc->req != NULL)
    {
      if (lgc->req->task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (sched, lgc->req->task);
      GNUNET_CONTAINER_DLL_remove (lgc_head, lgc_tail, lgc);
      GNUNET_free (lgc->req);
    }
  GNUNET_free (lgc);
}


/**
 * We're able to transmit the next (local) result to the client.
 * Do it and ask the datastore for more.  Or, on error, tell
 * the datastore to stop giving us more.
 *
 * @param cls our closure (struct LocalGetContext)
 * @param max maximum number of bytes we can transmit
 * @param buf where to copy our message
 * @return number of bytes copied to buf
 */
static size_t
transmit_local_result (void *cls,
		       size_t max,
		       void *buf)
{
  struct LocalGetContext *lgc = cls;  
  uint16_t msize;

  if (NULL == buf)
    {
      /* error, abort! */
      GNUNET_free (lgc->result);
      lgc->result = NULL;
      GNUNET_DATASTORE_get_next (dsh, GNUNET_NO);
      return 0;
    }
  msize = ntohs (lgc->result->header.size);
  GNUNET_assert (max >= msize);
  memcpy (buf, lgc->result, msize);
  GNUNET_free (lgc->result);
  lgc->result = NULL;
  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
  return msize;
}


/**
 * We're processing (local) results for a search request
 * from a (local) client.  Pass applicable results to the
 * client and if we are done either clean up (operation
 * complete) or switch to P2P search (more results possible).
 *
 * @param cls our closure (struct LocalGetContext)
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
process_local_get_result (void *cls,
			  const GNUNET_HashCode * key,
			  uint32_t size,
			  const void *data,
			  uint32_t type,
			  uint32_t priority,
			  uint32_t anonymity,
			  struct GNUNET_TIME_Absolute
			  expiration, 
			  uint64_t uid)
{
  struct LocalGetContext *lgc = cls;
  size_t msize;
  
  if (key == NULL)
    {
      /* no further results from datastore; continue
	 processing further requests from the client and
	 allow the next task to use the datastore; also,
	 switch to P2P requests or clean up our state. */
      next_ds_request ();
      GNUNET_SERVER_receive_done (lgc->client,
				  GNUNET_OK);
      if ( (lgc->results_used == 0) ||
	   (lgc->type == GNUNET_DATASTORE_BLOCKTYPE_KBLOCK) ||
	   (lgc->type == GNUNET_DATASTORE_BLOCKTYPE_SBLOCK) ||
	   (lgc->type == GNUNET_DATASTORE_BLOCKTYPE_SKBLOCK) )
	{
	  // FIXME: initiate P2P search
	  return;
	}
      /* got all possible results, clean up! */
      local_get_context_free (lgc);
      return;
    }
  if (lgc->results_used == lgc->results_size)
    {
      GNUNET_array_grow (lgc->results,
			 lgc->results_size,
			 lgc->results_size * 2 + 2);
      if ( (lgc->type != GNUNET_DATASTORE_BLOCKTYPE_DBLOCK) ||
	   (lgc->type != GNUNET_DATASTORE_BLOCKTYPE_IBLOCK) )
	{
	  // FIXME: possibly grow/create BF!
	}
    }
  GNUNET_CRYPTO_hash (data, 
		      size, 
		      &lgc->results[lgc->results_used++]);    
  if ( (lgc->type != GNUNET_DATASTORE_BLOCKTYPE_DBLOCK) ||
       (lgc->type != GNUNET_DATASTORE_BLOCKTYPE_IBLOCK) )
    {
      // FIXME: add result to BF!
    }
  msize = size + sizeof (struct ContentMessage);
  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  lgc->result = GNUNET_malloc (msize);
  lgc->result->header.size = htons (msize);
  lgc->result->header.type = htons (GNUNET_MESSAGE_TYPE_FS_CONTENT);
  lgc->result->type = htonl (type);
  lgc->result->expiration = GNUNET_TIME_absolute_hton (expiration);
  memcpy (&lgc->result[1],
	  data,
	  size);
  GNUNET_SERVER_notify_transmit_ready (lgc->client,
				       msize,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       &transmit_local_result,
				       lgc);
}


/**
 * We're processing a search request from a local
 * client.  Now it is our turn to query the datastore.
 * 
 * @param cls our closure (struct LocalGetContext)
 * @param tc unused
 */
static void
transmit_local_get (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LocalGetContext *lgc = cls;

  GNUNET_DATASTORE_get (dsh,
			&lgc->query,
			lgc->type,
			&process_local_get_result,
			lgc,
			GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * We're processing a search request from a local
 * client.  Now it is our turn to query the datastore.
 * 
 * @param cls our closure (struct LocalGetContext)
 * @param ok did we succeed to queue for datastore access, should always be GNUNET_OK
 */
static void 
transmit_local_get_ready (void *cls,
			  int ok)
{
  struct LocalGetContext *lgc = cls;

  GNUNET_assert (GNUNET_OK == ok);
  GNUNET_SCHEDULER_add_continuation (sched,
				     GNUNET_NO,
				     &transmit_local_get,
				     lgc,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Handle START_SEARCH-message (search request from client).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start_search (void *cls,
		     struct GNUNET_SERVER_Client *client,
		     const struct GNUNET_MessageHeader *message)
{
  const struct SearchMessage *sm;
  struct LocalGetContext *lgc;

  sm = (const struct SearchMessage*) message;
  GNUNET_SERVER_client_keep (client);
  lgc = GNUNET_malloc (sizeof (struct LocalGetContext));
  lgc->client = client;
  lgc->type = ntohl (sm->type);
  lgc->anonymity_level = ntohl (sm->anonymity_level);
  lgc->target = sm->target;
  lgc->query = sm->query;
  GNUNET_CONTAINER_DLL_insert (lgc_head, lgc_tail, lgc);
  lgc->req = queue_ds_request (GNUNET_TIME_UNIT_FOREVER_REL,
			       &transmit_local_get_ready,
			       lgc);
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_index_start, NULL, 
   GNUNET_MESSAGE_TYPE_FS_INDEX_START, 0},
  {&handle_index_list_get, NULL, 
   GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET, sizeof(struct GNUNET_MessageHeader) },
  {&handle_unindex, NULL, GNUNET_MESSAGE_TYPE_FS_UNINDEX, 
   sizeof (struct UnindexMessage) },
  {&handle_start_search, NULL, GNUNET_MESSAGE_TYPE_FS_START_SEARCH, 
   sizeof (struct SearchMessage) },
  {NULL, NULL, 0, 0}
};


/**
 * A client disconnected.  Remove all of its pending queries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client
			  * client)
{
  struct LocalGetContext *lgc;

  lgc = lgc_head;
  while ( (NULL != lgc) &&
	  (lgc->client != client) )
    lgc = lgc->next;
  if (lgc == NULL)
    return; /* not one of our clients */
  local_get_context_free (lgc);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DATASTORE_disconnect (dsh,
			       GNUNET_NO);
  dsh = NULL;
}


/**
 * Process fs requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  sched = s;
  cfg = c;
  dsh = GNUNET_DATASTORE_connect (cfg,
				  sched);
  if (NULL == dsh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to datastore service.\n"));
      return;
    }
  GNUNET_SERVER_disconnect_notify (server, 
				   &handle_client_disconnect,
				   NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  // FIXME: also register with core to handle P2P messages!
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_YES,
				GNUNET_SCHEDULER_PRIORITY_IDLE,
				GNUNET_SCHEDULER_NO_TASK,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
}


/**
 * The main function for the fs service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "fs", &run, NULL, NULL, NULL)) ? 0 : 1;
}

/* end of gnunet-service-fs.c */
