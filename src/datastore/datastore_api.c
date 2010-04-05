/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file datastore/datastore_api.c
 * @brief Management for the datastore for files stored on a GNUnet node
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_datastore_service.h"
#include "datastore.h"

/**
 * Handle to the datastore service.  Followed
 * by 65536 bytes used for storing messages.
 */
struct GNUNET_DATASTORE_Handle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Current connection to the datastore service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Current response processor (NULL if we are not waiting for a
   * response).  The specific type depends on the kind of message we
   * just transmitted.
   */
  void *response_proc;
  
  /**
   * Closure for response_proc.
   */
  void *response_proc_cls;

  /**
   * Timeout for the current operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Number of bytes in the message following
   * this struct, 0 if we have no request pending.
   */
  size_t message_size;

};



/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *GNUNET_DATASTORE_connect (const struct
                                                          GNUNET_CONFIGURATION_Handle
                                                          *cfg,
                                                          struct
                                                          GNUNET_SCHEDULER_Handle
                                                          *sched)
{
  struct GNUNET_CLIENT_Connection *c;
  struct GNUNET_DATASTORE_Handle *h;
  
  c = GNUNET_CLIENT_connect (sched, "datastore", cfg);
  if (c == NULL)
    return NULL; /* oops */
  GNUNET_ARM_start_services (cfg, sched, "datastore", NULL);
  h = GNUNET_malloc (sizeof(struct GNUNET_DATASTORE_Handle) + 
		     GNUNET_SERVER_MAX_MESSAGE_SIZE);
  h->client = c;
  h->cfg = cfg;
  h->sched = sched;
  return h;
}


/**
 * Transmit DROP message to datastore service.
 */
static size_t
transmit_drop (void *cls,
	       size_t size, void *buf)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_MessageHeader *hdr;
  
  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to transmit request to drop database.\n"));
      GNUNET_DATASTORE_disconnect (h, GNUNET_NO);
      return 0;
    }
  GNUNET_assert (size >= sizeof(struct GNUNET_MessageHeader));
  hdr = buf;
  hdr->size = htons(sizeof(struct GNUNET_MessageHeader));
  hdr->type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_DROP);
  GNUNET_DATASTORE_disconnect (h, GNUNET_NO);
  return sizeof(struct GNUNET_MessageHeader);
}


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to GNUNET_YES to delete all data in datastore (!)
 */
void GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h,
				  int drop)
{
  if (h->client != NULL)
    GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  h->client = NULL;
  if (GNUNET_YES == drop) 
    {
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      if (h->client != NULL)
	{
	  if (NULL != 
	      GNUNET_CLIENT_notify_transmit_ready (h->client,
						   sizeof(struct GNUNET_MessageHeader),
						   GNUNET_TIME_UNIT_MINUTES,
						   GNUNET_YES,
						   &transmit_drop,
						   h))
	    return;
	  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
	}
      GNUNET_break (0);
    }
  GNUNET_free (h);
}


/**
 * Type of a function to call when we receive a message
 * from the service.  This specific function is used
 * to handle messages of type "struct StatusMessage".
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
with_status_response_handler (void *cls,
			      const struct
			      GNUNET_MessageHeader * msg)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  GNUNET_DATASTORE_ContinuationWithStatus cont = h->response_proc;
  const struct StatusMessage *sm;
  const char *emsg;
  int status;

  h->message_size = 0;
  if (msg == NULL)
    {
      h->response_proc = NULL;
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      cont (h->response_proc_cls, 
	    GNUNET_SYSERR,
	    _("Timeout trying to read response from datastore service"));
      return;
    }
  if ( (ntohs(msg->size) < sizeof(struct StatusMessage)) ||
       (ntohs(msg->type) != GNUNET_MESSAGE_TYPE_DATASTORE_STATUS) ) 
    {
      GNUNET_break (0);
      h->response_proc = NULL;
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      cont (h->response_proc_cls, 
	    GNUNET_SYSERR,
	    _("Error reading response from datastore service"));
      return;
    }
  sm = (const struct StatusMessage*) msg;
  status = ntohl(sm->status);
  emsg = NULL;
  if (ntohs(msg->size) > sizeof(struct StatusMessage))
    {
      emsg = (const char*) &sm[1];
      if (emsg[ntohs(msg->size) - sizeof(struct StatusMessage) - 1] != '\0')
	{
	  GNUNET_break (0);
	  emsg = _("Invalid error message received from datastore service");
	}
    }  
  if ( (status == GNUNET_SYSERR) &&
       (emsg == NULL) )
    {
      GNUNET_break (0);
      emsg = _("Invalid error message received from datastore service");
    }
  h->response_proc = NULL;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received status %d/%s\n",
	      status,
	      emsg);
#endif
  cont (h->response_proc_cls, 
	status,
	emsg);
}


/**
 * Helper function that will initiate the
 * transmission of a message to the datastore
 * service.  The message must already be prepared
 * and stored in the buffer at the end of the
 * handle.  The message must be of a type that
 * expects a "StatusMessage" in response.
 *
 * @param h handle to the service with prepared message
 * @param cont function to call with result
 * @param cont_cls closure
 * @param timeout timeout for the operation
 */
static void
transmit_for_status (struct GNUNET_DATASTORE_Handle *h,
		     GNUNET_DATASTORE_ContinuationWithStatus cont,
		     void *cont_cls,
		     struct GNUNET_TIME_Relative timeout)
{
  const struct GNUNET_MessageHeader *hdr;
  uint16_t msize;

  GNUNET_assert (cont != NULL);
  hdr = (const struct GNUNET_MessageHeader*) &h[1];
  msize = ntohs(hdr->size);
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting %u byte message of type %u to datastore service\n",
	      msize,
	      ntohs(hdr->type));
#endif
  GNUNET_assert (h->response_proc == NULL);
  h->response_proc = cont;
  h->response_proc_cls = cont_cls;
  h->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  h->message_size = msize;
  if (GNUNET_OK !=
      GNUNET_CLIENT_transmit_and_get_response (h->client,
					       hdr,					       
					       timeout,
					       GNUNET_YES,
					       &with_status_response_handler,					       
					       h))
    {
      GNUNET_break (0);
      h->response_proc = NULL;
      h->message_size = 0;
      cont (cont_cls,
	    GNUNET_SYSERR,
	    _("Not ready to transmit request to datastore service"));
    }
}


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @param h handle to the datastore
 * @param rid reservation ID to use (from "reserve"); use 0 if no
 *            prior reservation was made
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param timeout timeout for the operation
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
		      int rid,
                      const GNUNET_HashCode * key,
                      uint32_t size,
                      const void *data,
                      uint32_t type,
                      uint32_t priority,
                      uint32_t anonymity,
                      struct GNUNET_TIME_Absolute expiration,
                      struct GNUNET_TIME_Relative timeout,
		      GNUNET_DATASTORE_ContinuationWithStatus cont,
		      void *cont_cls)
{
  struct DataMessage *dm;
  size_t msize;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to put %u bytes of data under key `%s'\n",
	      size,
	      GNUNET_h2s (key));
#endif
  msize = sizeof(struct DataMessage) + size;
  GNUNET_assert (msize <= GNUNET_SERVER_MAX_MESSAGE_SIZE);
  dm = (struct DataMessage*) &h[1];
  dm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_PUT);
  dm->header.size = htons(msize);
  dm->rid = htonl(rid);
  dm->size = htonl(size);
  dm->type = htonl(type);
  dm->priority = htonl(priority);
  dm->anonymity = htonl(anonymity);
  dm->uid = GNUNET_htonll(0);
  dm->expiration = GNUNET_TIME_absolute_hton(expiration);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  transmit_for_status (h, cont, cont_cls, timeout);
}


/**
 * Reserve space in the datastore.  This function should be used
 * to avoid "out of space" failures during a longer sequence of "put"
 * operations (for example, when a file is being inserted).
 *
 * @param h handle to the datastore
 * @param amount how much space (in bytes) should be reserved (for content only)
 * @param entries how many entries will be created (to calculate per-entry overhead)
 * @param cont continuation to call when done; "success" will be set to
 *             a positive reservation value if space could be reserved.
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_reserve (struct GNUNET_DATASTORE_Handle *h,
			  uint64_t amount,
			  uint32_t entries,
			  GNUNET_DATASTORE_ContinuationWithStatus cont,
			  void *cont_cls,
			  struct GNUNET_TIME_Relative timeout)
{
  struct ReserveMessage *rm;

  rm = (struct ReserveMessage*) &h[1];
  rm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE);
  rm->header.size = htons(sizeof (struct ReserveMessage));
  rm->entries = htonl(entries);
  rm->amount = GNUNET_htonll(amount);
  transmit_for_status (h, cont, cont_cls, timeout);
}


/**
 * Signal that all of the data for which a reservation was made has
 * been stored and that whatever excess space might have been reserved
 * can now be released.
 *
 * @param h handle to the datastore
 * @param rid reservation ID (value of "success" in original continuation
 *        from the "reserve" function).
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_release_reserve (struct GNUNET_DATASTORE_Handle *h,
				  int rid,
				  GNUNET_DATASTORE_ContinuationWithStatus cont,
				  void *cont_cls,
				  struct GNUNET_TIME_Relative timeout)
{
  struct ReleaseReserveMessage *rrm;

  rrm = (struct ReleaseReserveMessage*) &h[1];
  rrm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE);
  rrm->header.size = htons(sizeof (struct ReleaseReserveMessage));
  rrm->rid = htonl(rid);
  transmit_for_status (h, cont, cont_cls, timeout);
}


/**
 * Update a value in the datastore.
 *
 * @param h handle to the datastore
 * @param uid identifier for the value
 * @param priority how much to increase the priority of the value
 * @param expiration new expiration value should be MAX of existing and this argument
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_update (struct GNUNET_DATASTORE_Handle *h,
			 unsigned long long uid,
			 uint32_t priority,
			 struct GNUNET_TIME_Absolute expiration,
			 GNUNET_DATASTORE_ContinuationWithStatus cont,
			 void *cont_cls,
			 struct GNUNET_TIME_Relative timeout)
{
  struct UpdateMessage *um;

  um = (struct UpdateMessage*) &h[1];
  um->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE);
  um->header.size = htons(sizeof (struct UpdateMessage));
  um->priority = htonl(priority);
  um->expiration = GNUNET_TIME_absolute_hton(expiration);
  um->uid = GNUNET_htonll(uid);
  transmit_for_status (h, cont, cont_cls, timeout);
}


/**
 * Helper function that will initiate the transmission of a message to
 * the datastore service.  The message must already be prepared and
 * stored in the buffer at the end of the handle.  The message must be
 * of a type that expects a "DataMessage" in response.
 *
 * @param h handle to the service with prepared message
 * @param cont function to call with result
 * @param cont_cls closure
 * @param timeout timeout for the operation
 */
static void
transmit_for_result (struct GNUNET_DATASTORE_Handle *h,
		     GNUNET_DATASTORE_Iterator cont,
		     void *cont_cls,
		     struct GNUNET_TIME_Relative timeout);


/**
 * Type of a function to call when we receive a message
 * from the service.  This specific function is used
 * to handle messages of type "struct DataMessage".
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
with_result_response_handler (void *cls,
			      const struct
			      GNUNET_MessageHeader * msg)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  GNUNET_DATASTORE_Iterator cont = h->response_proc;
  const struct DataMessage *dm;
  size_t msize;
  struct GNUNET_TIME_Relative remaining;

  if (msg == NULL)
    {
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Got disconnected from datastore\n");
#endif
      h->response_proc = NULL;
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      remaining = GNUNET_TIME_absolute_get_remaining (h->timeout);
      if (remaining.value > 0)
	{
	  transmit_for_result (h,
			       cont,
			       h->response_proc_cls,
			       remaining);
	}
      else
	{
	  h->message_size = 0;
	  cont (h->response_proc_cls, 
		NULL, 0, NULL, 0, 0, 0, 
		GNUNET_TIME_UNIT_ZERO_ABS, 0);
	}
      return;
    }
  h->message_size = 0;
  if (ntohs(msg->type) == GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END) 
    {
      GNUNET_break (ntohs(msg->size) == sizeof(struct GNUNET_MessageHeader));
      h->response_proc = NULL;
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received end of result set\n");
#endif
      cont (h->response_proc_cls, 
	    NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  if ( (ntohs(msg->size) < sizeof(struct DataMessage)) ||
       (ntohs(msg->type) != GNUNET_MESSAGE_TYPE_DATASTORE_DATA) ) 
    {
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      h->response_proc = NULL;
      cont (h->response_proc_cls, 
	    NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
  dm = (const struct DataMessage*) msg;
  msize = ntohl(dm->size);
  if (ntohs(msg->size) != msize + sizeof(struct DataMessage))
    {
      GNUNET_break (0);
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      h->response_proc = NULL;
      cont (h->response_proc_cls, 
	    NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
      return;
    }
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received result %llu with type %u and size %u with key %s\n",
	      (unsigned long long) GNUNET_ntohll(dm->uid),
	      ntohl(dm->type),
	      msize,
	      GNUNET_h2s(&dm->key));
#endif
  cont (h->response_proc_cls, 
	&dm->key,
	msize,
	&dm[1],
	ntohl(dm->type),
	ntohl(dm->priority),
	ntohl(dm->anonymity),
	GNUNET_TIME_absolute_ntoh(dm->expiration),	
	GNUNET_ntohll(dm->uid));
}


/**
 * Function called to trigger obtaining the next result
 * from the datastore.
 * 
 * @param h handle to the datastore
 * @param more GNUNET_YES to get moxre results, GNUNET_NO to abort
 *        iteration (with a final call to "iter" with key/data == NULL).
 */
void 
GNUNET_DATASTORE_get_next (struct GNUNET_DATASTORE_Handle *h,
			   int more)
{
  GNUNET_DATASTORE_Iterator cont;

  if (GNUNET_YES == more)
    {
      GNUNET_CLIENT_receive (h->client,
			     &with_result_response_handler,
			     h,
			     GNUNET_TIME_absolute_get_remaining (h->timeout));
      return;
    }
  cont = h->response_proc;
  h->response_proc = NULL;
  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
  cont (h->response_proc_cls, 
	NULL, 0, NULL, 0, 0, 0, 
	GNUNET_TIME_UNIT_ZERO_ABS, 0);
}


/**
 * Helper function that will initiate the transmission of a message to
 * the datastore service.  The message must already be prepared and
 * stored in the buffer at the end of the handle.  The message must be
 * of a type that expects a "DataMessage" in response.
 *
 * @param h handle to the service with prepared message
 * @param cont function to call with result
 * @param cont_cls closure
 * @param timeout timeout for the operation
 */
static void
transmit_for_result (struct GNUNET_DATASTORE_Handle *h,
		     GNUNET_DATASTORE_Iterator cont,
		     void *cont_cls,
		     struct GNUNET_TIME_Relative timeout)
{
  const struct GNUNET_MessageHeader *hdr;
  uint16_t msize;

  GNUNET_assert (cont != NULL);
  hdr = (const struct GNUNET_MessageHeader*) &h[1];
  msize = ntohs(hdr->size);
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting %u byte message of type %u to datastore service\n",
	      msize,
	      ntohs(hdr->type));
#endif
  GNUNET_assert (h->response_proc == NULL);
  h->response_proc = cont;
  h->response_proc_cls = cont_cls;
  h->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  h->message_size = msize;
  if (GNUNET_OK !=
      GNUNET_CLIENT_transmit_and_get_response (h->client,
					       hdr,
					       timeout,
					       GNUNET_YES,
					       &with_result_response_handler,
					       h))
    {
      GNUNET_break (0);
      h->response_proc = NULL;
      h->message_size = 0;
      cont (h->response_proc_cls, 
	    NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);
    }
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param h handle to the datastore
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_get (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
                      uint32_t type,
                      GNUNET_DATASTORE_Iterator iter, void *iter_cls,
		      struct GNUNET_TIME_Relative timeout)
{
  struct GetMessage *gm;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to look for data under key `%s'\n",
	      GNUNET_h2s (key));
#endif
  gm = (struct GetMessage*) &h[1];
  gm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_GET);
  gm->type = htonl(type);
  if (key != NULL)
    {
      gm->header.size = htons(sizeof (struct GetMessage));
      gm->key = *key;
    }
  else
    {
      gm->header.size = htons(sizeof (struct GetMessage) - sizeof(GNUNET_HashCode));
    }
  GNUNET_assert (h->response_proc == NULL);
  transmit_for_result (h, iter, iter_cls, timeout);
}


/**
 * Get a random value from the datastore.
 *
 * @param h handle to the datastore
 * @param iter function to call on a random value; it
 *        will be called exactly once; if no values
 *        are available, the value will be NULL.
 * @param iter_cls closure for iter
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_get_random (struct GNUNET_DATASTORE_Handle *h,
                             GNUNET_DATASTORE_Iterator iter, void *iter_cls,
			     struct GNUNET_TIME_Relative timeout)
{
  struct GNUNET_MessageHeader *m;

  m = (struct GNUNET_MessageHeader*) &h[1];
  m->type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_GET_RANDOM);
  m->size = htons(sizeof (struct GNUNET_MessageHeader));
  GNUNET_assert (h->response_proc == NULL);
  transmit_for_result (h, iter, iter_cls, timeout);
}


/**
 * Explicitly remove some content from the database.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const GNUNET_HashCode * key,
                         uint32_t size, const void *data,
			 GNUNET_DATASTORE_ContinuationWithStatus cont,
			 void *cont_cls,
			 struct GNUNET_TIME_Relative timeout)
{
  struct DataMessage *dm;
  size_t msize;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to remove %u bytes of data under key `%s'\n",
	      size,
	      GNUNET_h2s (key));
#endif
  msize = sizeof(struct DataMessage) + size;
  GNUNET_assert (msize <= GNUNET_SERVER_MAX_MESSAGE_SIZE);
  dm = (struct DataMessage*) &h[1];
  dm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE);
  dm->header.size = htons(msize);
  dm->rid = htonl(0);
  dm->size = htonl(size);
  dm->type = htonl(0);
  dm->priority = htonl(0);
  dm->anonymity = htonl(0);
  dm->uid = GNUNET_htonll(0);
  dm->expiration = GNUNET_TIME_absolute_hton(GNUNET_TIME_UNIT_ZERO_ABS);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  transmit_for_status (h, cont, cont_cls, timeout);
}


/* end of datastore_api.c */
