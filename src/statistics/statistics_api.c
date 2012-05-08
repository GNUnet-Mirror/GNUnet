/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file statistics/statistics_api.c
 * @brief API of the statistics service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_container_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "statistics.h"

/**
 * How long do we wait until a statistics request for setting
 * a value times out?  (The update will be lost if the
 * service does not react within this timeframe).
 */
#define SET_TRANSMIT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

#define LOG(kind,...) GNUNET_log_from (kind, "statistics-api",__VA_ARGS__)

/**
 * Types of actions.
 */
enum ActionType
{
  /**
   * Get a value.
   */
  ACTION_GET,

  /**
   * Set a value.
   */
  ACTION_SET,

  /**
   * Update a value.
   */
  ACTION_UPDATE,

  /**
   * Watch a value.
   */
  ACTION_WATCH
};


/**
 * Entry kept for each value we are watching.
 */
struct GNUNET_STATISTICS_WatchEntry
{

  /**
   * What subsystem is this action about? (never NULL)
   */
  char *subsystem;

  /**
   * What value is this action about? (never NULL)
   */
  char *name;

  /**
   * Function to call
   */
  GNUNET_STATISTICS_Iterator proc;

  /**
   * Closure for proc
   */
  void *proc_cls;

};


/**
 * Linked list of things we still need to do.
 */
struct GNUNET_STATISTICS_GetHandle
{

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_STATISTICS_GetHandle *next;

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_STATISTICS_GetHandle *prev;

  /**
   * Main statistics handle.
   */
  struct GNUNET_STATISTICS_Handle *sh;

  /**
   * What subsystem is this action about? (can be NULL)
   */
  char *subsystem;

  /**
   * What value is this action about? (can be NULL)
   */
  char *name;

  /**
   * Continuation to call once action is complete.
   */
  GNUNET_STATISTICS_Callback cont;

  /**
   * Function to call (for GET actions only).
   */
  GNUNET_STATISTICS_Iterator proc;

  /**
   * Closure for proc and cont.
   */
  void *cls;

  /**
   * Timeout for this action.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Associated value.
   */
  uint64_t value;

  /**
   * Flag for SET/UPDATE actions.
   */
  int make_persistent;

  /**
   * Has the current iteration been aborted; for GET actions.
   */
  int aborted;

  /**
   * Is this a GET, SET, UPDATE or WATCH?
   */
  enum ActionType type;

  /**
   * Size of the message that we will be transmitting.
   */
  uint16_t msize;

};


/**
 * Handle for the service.
 */
struct GNUNET_STATISTICS_Handle
{
  /**
   * Name of our subsystem.
   */
  char *subsystem;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of the linked list of pending actions (first action
   * to be performed).
   */
  struct GNUNET_STATISTICS_GetHandle *action_head;

  /**
   * Tail of the linked list of actions (for fast append).
   */
  struct GNUNET_STATISTICS_GetHandle *action_tail;

  /**
   * Action we are currently busy with (action request has been
   * transmitted, we're now receiving the response from the
   * service).
   */
  struct GNUNET_STATISTICS_GetHandle *current;

  /**
   * Array of watch entries.
   */
  struct GNUNET_STATISTICS_WatchEntry **watches;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier backoff_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Size of the 'watches' array.
   */
  unsigned int watches_size;

  /**
   * Should this handle auto-destruct once all actions have
   * been processed?
   */
  int do_destroy;

  /**
   * Are we currently receiving from the service?
   */
  int receiving;

};


/**
 * Schedule the next action to be performed.
 *
 * @param h statistics handle to reconnect
 */
static void
schedule_action (struct GNUNET_STATISTICS_Handle *h);


/**
 * Transmit request to service that we want to watch
 * the development of a particular value.
 *
 * @param h statistics handle
 * @param watch watch entry of the value to watch
 */
static void
schedule_watch_request (struct GNUNET_STATISTICS_Handle *h,
                        struct GNUNET_STATISTICS_WatchEntry *watch)
{

  struct GNUNET_STATISTICS_GetHandle *ai;
  size_t slen;
  size_t nlen;
  size_t nsize;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != watch);

  slen = strlen (watch->subsystem) + 1;
  nlen = strlen (watch->name) + 1;
  nsize = sizeof (struct GNUNET_MessageHeader) + slen + nlen;
  if (nsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  ai = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_GetHandle));
  ai->sh = h;
  ai->subsystem = GNUNET_strdup (watch->subsystem);
  ai->name = GNUNET_strdup (watch->name);
  ai->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  ai->msize = nsize;
  ai->type = ACTION_WATCH;
  ai->proc = watch->proc;
  ai->cls = watch->proc_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->action_head, h->action_tail,
				    ai);
  schedule_action (h);
}


/**
 * Free memory associated with the given action item.
 *
 * @param gh action item to free
 */
static void
free_action_item (struct GNUNET_STATISTICS_GetHandle *gh)
{
  GNUNET_free_non_null (gh->subsystem);
  GNUNET_free_non_null (gh->name);
  GNUNET_free (gh);
}


/**
 * Disconnect from the statistics service.
 *
 * @param h statistics handle to disconnect from
 */
static void
do_disconnect (struct GNUNET_STATISTICS_Handle *h)
{
  struct GNUNET_STATISTICS_GetHandle *c;
  
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  } 
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->receiving = GNUNET_NO;
  if (NULL != (c = h->current))
  {
    h->current = NULL;
    if (NULL != c->cont)
      c->cont (c->cls, GNUNET_SYSERR);
    free_action_item (c);
  }
}


/**
 * Try to (re)connect to the statistics service.
 *
 * @param h statistics handle to reconnect
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_STATISTICS_Handle *h)
{
  struct GNUNET_STATISTICS_GetHandle *gh;
  struct GNUNET_STATISTICS_GetHandle *gn;
  unsigned int i;

  if (GNUNET_SCHEDULER_NO_TASK != h->backoff_task)
    return GNUNET_NO;
  if (NULL != h->client)
    return GNUNET_YES;
  h->client = GNUNET_CLIENT_connect ("statistics", h->cfg);  
  if (NULL != h->client)
  {
    gn = h->action_head; 
    while (NULL != (gh = gn))
    {
      gn = gh->next;
      if (gh->type == ACTION_WATCH)
      {
	GNUNET_CONTAINER_DLL_remove (h->action_head,
				     h->action_tail,
				     gh);
	free_action_item (gh);	
      }
    }
    for (i = 0; i < h->watches_size; i++)
    {
      if (NULL != h->watches[i])
        schedule_watch_request (h, h->watches[i]);
    }
    return GNUNET_YES;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Failed to connect to statistics service!\n");
  return GNUNET_NO;
}


/**
 * We've waited long enough, reconnect now.
 *
 * @param cls the 'struct GNUNET_STATISTICS_Handle' to reconnect
 * @param tc scheduler context (unused)
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  h->backoff_task = GNUNET_SCHEDULER_NO_TASK;
  schedule_action (h);
}


/**
 * Task used by 'reconnect_later' to shutdown the handle
 *
 * @param cls the statistics handle
 * @param tc scheduler context
 */
static void
do_destroy (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
}


/**
 * Reconnect at a later time, respecting back-off.
 *
 * @param h statistics handle
 */
static void
reconnect_later (struct GNUNET_STATISTICS_Handle *h)
{
  int loss;
  struct GNUNET_STATISTICS_GetHandle *gh;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == h->backoff_task);
  if (GNUNET_YES == h->do_destroy)
  {
    /* So we are shutting down and the service is not reachable.
     * Chances are that it's down for good and we are not going to connect to
     * it anymore.
     * Give up and don't sync the rest of the data.
     */
    loss = GNUNET_NO;
    for (gh = h->action_head; NULL != gh; gh = gh->next)
      if ( (gh->make_persistent) && (ACTION_SET == gh->type) )
	loss = GNUNET_YES;
    if (GNUNET_YES == loss)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Could not save some persistent statistics\n"));
    h->do_destroy = GNUNET_NO;
    GNUNET_SCHEDULER_add_continuation (&do_destroy, h,
				       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    return;
  }
  h->backoff_task =
    GNUNET_SCHEDULER_add_delayed (h->backoff, &reconnect_task, h);
  h->backoff = GNUNET_TIME_relative_multiply (h->backoff, 2);
  h->backoff =
    GNUNET_TIME_relative_min (h->backoff, GNUNET_CONSTANTS_SERVICE_TIMEOUT);
}


/**
 * Process a 'GNUNET_MESSAGE_TYPE_STATISTICS_VALUE' message.
 *
 * @param h statistics handle
 * @param msg message received from the service, never NULL
 * @return GNUNET_OK if the message was well-formed
 */
static int
process_statistics_value_message (struct GNUNET_STATISTICS_Handle *h,
				  const struct GNUNET_MessageHeader *msg)
{
  char *service;
  char *name;
  const struct GNUNET_STATISTICS_ReplyMessage *smsg;
  uint16_t size;

  if (h->current->aborted)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Iteration was aborted, ignoring VALUE\n");
    return GNUNET_OK;           /* don't bother */
  }
  size = ntohs (msg->size);
  if (size < sizeof (struct GNUNET_STATISTICS_ReplyMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  smsg = (const struct GNUNET_STATISTICS_ReplyMessage *) msg;
  size -= sizeof (struct GNUNET_STATISTICS_ReplyMessage);
  if (size !=
      GNUNET_STRINGS_buffer_tokenize ((const char *) &smsg[1], size, 2,
                                      &service, &name))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received valid statistic on `%s:%s': %llu\n",
       service, name, GNUNET_ntohll (smsg->value));
  if (GNUNET_OK !=
      h->current->proc (h->current->cls, service, name,
                        GNUNET_ntohll (smsg->value),
                        0 !=
                        (ntohl (smsg->uid) & GNUNET_STATISTICS_PERSIST_BIT)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Processing of remaining statistics aborted by client.\n");
    h->current->aborted = GNUNET_YES;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "VALUE processed successfully\n");
  return GNUNET_OK;
}


/**
 * We have received a watch value from the service.  Process it.
 *
 * @param h statistics handle
 * @param msg the watch value message
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not,
 *         GNUNET_NO if this watch has been cancelled
 */
static int
process_watch_value (struct GNUNET_STATISTICS_Handle *h,
                     const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_STATISTICS_WatchValueMessage *wvm;
  struct GNUNET_STATISTICS_WatchEntry *w;
  uint32_t wid;

  if (sizeof (struct GNUNET_STATISTICS_WatchValueMessage) != ntohs (msg->size))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  wvm = (const struct GNUNET_STATISTICS_WatchValueMessage *) msg;
  GNUNET_break (0 == ntohl (wvm->reserved));
  wid = ntohl (wvm->wid);
  if (wid >= h->watches_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  w = h->watches[wid];
  if (NULL == w)  
    return GNUNET_NO;  
  (void) w->proc (w->proc_cls, w->subsystem, w->name,
                  GNUNET_ntohll (wvm->value),
                  0 != (ntohl (wvm->flags) & GNUNET_STATISTICS_PERSIST_BIT));
  return GNUNET_OK;
}


static void
destroy_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
}


/**
 * Function called with messages from stats service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
receive_stats (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_STATISTICS_Handle *h = cls;
  struct GNUNET_STATISTICS_GetHandle *c;
  int ret;

  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         "Error receiving statistics from service, is the service running?\n");
    do_disconnect (h);
    reconnect_later (h);
    return;
  }
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TEST:
    if (GNUNET_SYSERR != h->do_destroy)
    {
      /* not in shutdown, why do we get 'TEST'? */
      GNUNET_break (0);
      do_disconnect (h);
      reconnect_later (h);
      return;
    }
    h->do_destroy = GNUNET_NO;
    GNUNET_SCHEDULER_add_continuation (&destroy_task, h,
				       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  case GNUNET_MESSAGE_TYPE_STATISTICS_END:
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Received end of statistics marker\n");
    if (NULL == (c = h->current))
    {
      GNUNET_break (0);
      do_disconnect (h);
      reconnect_later (h);
      return;
    }
    h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
    if (h->watches_size > 0)
    {
      GNUNET_CLIENT_receive (h->client, &receive_stats, h,
                             GNUNET_TIME_UNIT_FOREVER_REL);
    }
    else
    {
      h->receiving = GNUNET_NO;
    }    
    h->current = NULL;
    schedule_action (h);
    if (NULL != c->cont)
      c->cont (c->cls, GNUNET_OK);
    free_action_item (c);
    return;
  case GNUNET_MESSAGE_TYPE_STATISTICS_VALUE:
    if (GNUNET_OK != process_statistics_value_message (h, msg))
    {
      do_disconnect (h);
      reconnect_later (h);
      return;     
    }
    /* finally, look for more! */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Processing VALUE done, now reading more\n");
    GNUNET_CLIENT_receive (h->client, &receive_stats, h,
			   GNUNET_TIME_absolute_get_remaining (h->
							       current->timeout));
    h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
    return;
  case GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE:
    if (GNUNET_OK != 
	(ret = process_watch_value (h, msg)))
    {
      do_disconnect (h);
      if (GNUNET_NO == ret)
	h->backoff = GNUNET_TIME_UNIT_MILLISECONDS; 
      reconnect_later (h);
      return;
    }
    h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
    GNUNET_assert (h->watches_size > 0);
    GNUNET_CLIENT_receive (h->client, &receive_stats, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    return;    
  default:
    GNUNET_break (0);
    do_disconnect (h);
    reconnect_later (h);
    return;
  }
}


/**
 * Transmit a GET request (and if successful, start to receive
 * the response).
 *
 * @param handle statistics handle
 * @param size how many bytes can we write to buf
 * @param buf where to write requests to the service
 * @return number of bytes written to buf
 */
static size_t
transmit_get (struct GNUNET_STATISTICS_Handle *handle, size_t size, void *buf)
{
  struct GNUNET_STATISTICS_GetHandle *c;
  struct GNUNET_MessageHeader *hdr;
  size_t slen1;
  size_t slen2;
  uint16_t msize;

  GNUNET_assert (NULL != (c = handle->current));
  if (NULL == buf)
  {
    /* timeout / error */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission of request for statistics failed!\n");
    do_disconnect (handle);
    reconnect_later (handle);
    return 0;
  }
  slen1 = strlen (c->subsystem) + 1;
  slen2 = strlen (c->name) + 1;
  msize = slen1 + slen2 + sizeof (struct GNUNET_MessageHeader);
  GNUNET_assert (msize <= size);
  hdr = (struct GNUNET_MessageHeader *) buf;
  hdr->size = htons (msize);
  hdr->type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_GET);
  GNUNET_assert (slen1 + slen2 ==
                 GNUNET_STRINGS_buffer_fill ((char *) &hdr[1], slen1 + slen2, 2,
                                             c->subsystem,
                                             c->name));
  if (GNUNET_YES != handle->receiving)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission of GET done, now reading response\n");
    handle->receiving = GNUNET_YES;
    GNUNET_CLIENT_receive (handle->client, &receive_stats, handle,
                           GNUNET_TIME_absolute_get_remaining (c->timeout));
  }
  return msize;
}


/**
 * Transmit a WATCH request (and if successful, start to receive
 * the response).
 *
 * @param handle statistics handle
 * @param size how many bytes can we write to buf
 * @param buf where to write requests to the service
 * @return number of bytes written to buf
 */
static size_t
transmit_watch (struct GNUNET_STATISTICS_Handle *handle, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr;
  size_t slen1;
  size_t slen2;
  uint16_t msize;

  if (NULL == buf)
  {
    /* timeout / error */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission of request for statistics failed!\n");
    do_disconnect (handle);
    reconnect_later (handle);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transmitting watch request for `%s'\n",
       handle->current->name);
  slen1 = strlen (handle->current->subsystem) + 1;
  slen2 = strlen (handle->current->name) + 1;
  msize = slen1 + slen2 + sizeof (struct GNUNET_MessageHeader);
  GNUNET_assert (msize <= size);
  hdr = (struct GNUNET_MessageHeader *) buf;
  hdr->size = htons (msize);
  hdr->type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_WATCH);
  GNUNET_assert (slen1 + slen2 ==
                 GNUNET_STRINGS_buffer_fill ((char *) &hdr[1], slen1 + slen2, 2,
                                             handle->current->subsystem,
                                             handle->current->name));
  if (GNUNET_YES != handle->receiving)
  {
    handle->receiving = GNUNET_YES;
    GNUNET_CLIENT_receive (handle->client, &receive_stats, handle,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  GNUNET_assert (NULL == handle->current->cont);
  free_action_item (handle->current);
  handle->current = NULL;
  return msize;
}


/**
 * Transmit a SET/UPDATE request.
 *
 * @param handle statistics handle
 * @param size how many bytes can we write to buf
 * @param buf where to write requests to the service
 * @return number of bytes written to buf
 */
static size_t
transmit_set (struct GNUNET_STATISTICS_Handle *handle, size_t size, void *buf)
{
  struct GNUNET_STATISTICS_SetMessage *r;
  size_t slen;
  size_t nlen;
  size_t nsize;

  if (NULL == buf)
  {
    do_disconnect (handle);
    reconnect_later (handle);
    return 0;
  }
  slen = strlen (handle->current->subsystem) + 1;
  nlen = strlen (handle->current->name) + 1;
  nsize = sizeof (struct GNUNET_STATISTICS_SetMessage) + slen + nlen;
  if (size < nsize)
  {
    GNUNET_break (0);
    do_disconnect (handle);
    reconnect_later (handle);
    return 0;
  }
  r = buf;
  r->header.size = htons (nsize);
  r->header.type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_SET);
  r->flags = 0;
  r->value = GNUNET_htonll (handle->current->value);
  if (handle->current->make_persistent)
    r->flags |= htonl (GNUNET_STATISTICS_SETFLAG_PERSISTENT);
  if (handle->current->type == ACTION_UPDATE)
    r->flags |= htonl (GNUNET_STATISTICS_SETFLAG_RELATIVE);
  GNUNET_assert (slen + nlen ==
                 GNUNET_STRINGS_buffer_fill ((char *) &r[1], slen + nlen, 2,
                                             handle->current->subsystem,
                                             handle->current->name));
  GNUNET_assert (NULL == handle->current->cont);
  free_action_item (handle->current);
  handle->current = NULL;
  return nsize;
}


/**
 * Function called when we are ready to transmit a request to the service.
 *
 * @param cls the 'struct GNUNET_STATISTICS_Handle'
 * @param size how many bytes can we write to buf
 * @param buf where to write requests to the service
 * @return number of bytes written to buf
 */
static size_t
transmit_action (void *cls, size_t size, void *buf)
{
  struct GNUNET_STATISTICS_Handle *h = cls;
  size_t ret;

  h->th = NULL;
  ret = 0;
  if (NULL != h->current)
    switch (h->current->type)
    {
    case ACTION_GET:
      ret = transmit_get (h, size, buf);
      break;
    case ACTION_SET:
    case ACTION_UPDATE:
      ret = transmit_set (h, size, buf);
      break;
    case ACTION_WATCH:
      ret = transmit_watch (h, size, buf);
      break;
    default:
      GNUNET_assert (0);
      break;
    }
  schedule_action (h);
  return ret;
}


/**
 * Get handle for the statistics service.
 *
 * @param subsystem name of subsystem using the service
 * @param cfg services configuration in use
 * @return handle to use
 */
struct GNUNET_STATISTICS_Handle *
GNUNET_STATISTICS_create (const char *subsystem,
                          const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_STATISTICS_Handle *ret;

  GNUNET_assert (NULL != subsystem);
  GNUNET_assert (NULL != cfg);
  ret = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_Handle));
  ret->cfg = cfg;
  ret->subsystem = GNUNET_strdup (subsystem);
  ret->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  return ret;
}


/**
 * Destroy a handle (free all state associated with
 * it).
 *
 * @param h statistics handle to destroy
 * @param sync_first set to GNUNET_YES if pending SET requests should
 *        be completed
 */
void
GNUNET_STATISTICS_destroy (struct GNUNET_STATISTICS_Handle *h, int sync_first)
{
  struct GNUNET_STATISTICS_GetHandle *pos;
  struct GNUNET_STATISTICS_GetHandle *next;
  struct GNUNET_TIME_Relative timeout;
  int i;

  if (NULL == h)
    return;
  GNUNET_assert (GNUNET_NO == h->do_destroy); // Don't call twice.
  if (GNUNET_SCHEDULER_NO_TASK != h->backoff_task)
  {
    GNUNET_SCHEDULER_cancel (h->backoff_task);
    h->backoff_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (sync_first)
  {
    if (NULL != h->current)
    {
      if (ACTION_GET == h->current->type)
      {
        GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
        h->th = NULL;
        free_action_item (h->current);
        h->current = NULL;
      }
    }
    next = h->action_head; 
    while (NULL != (pos = next))
    {
      next = pos->next;
      if (ACTION_GET == pos->type)
      {
	GNUNET_CONTAINER_DLL_remove (h->action_head,
				     h->action_tail,
				     pos);
        free_action_item (pos);
      }
    }
    if ( (NULL == h->current) &&
	 (NULL != (h->current = h->action_head)) )
      GNUNET_CONTAINER_DLL_remove (h->action_head,
				   h->action_tail,
				   h->current);
    h->do_destroy = GNUNET_YES;
    if ((NULL != h->current) && (NULL == h->th) &&
	(NULL != h->client))
    {
      timeout = GNUNET_TIME_absolute_get_remaining (h->current->timeout);
      h->th =
	GNUNET_CLIENT_notify_transmit_ready (h->client, h->current->msize,
					     timeout, GNUNET_YES,
					     &transmit_action, h);
      GNUNET_assert (NULL != h->th);
    }
    if (NULL != h->th)
      return; /* do not finish destruction just yet */
  }
  while (NULL != (pos = h->action_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->action_head,
				 h->action_tail,
				 pos);
    free_action_item (pos);
  }
  do_disconnect (h);
  for (i = 0; i < h->watches_size; i++)
  {
    if (NULL == h->watches[i])
      continue; 
    GNUNET_free (h->watches[i]->subsystem);
    GNUNET_free (h->watches[i]->name);
    GNUNET_free (h->watches[i]);
  }
  GNUNET_array_grow (h->watches, h->watches_size, 0);
  GNUNET_free (h->subsystem);
  GNUNET_free (h);
}


/**
 * Function called to transmit TEST message to service to
 * confirm that the service has received all of our 'SET'
 * messages (during statistics disconnect/shutdown).
 *
 * @param cls the 'struct GNUNET_STATISTICS_Handle'
 * @param size how many bytes can we write to buf
 * @param buf where to write requests to the service
 * @return number of bytes written to buf
 */
static size_t
transmit_test_on_shutdown (void *cls,
			   size_t size,
			   void *buf)
{
  struct GNUNET_STATISTICS_Handle *h = cls;
  struct GNUNET_MessageHeader hdr;

  h->th = NULL;
  if (NULL == buf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to receive acknowledgement from statistics service, some statistics might have been lost!\n"));
    h->do_destroy = GNUNET_NO;
    GNUNET_SCHEDULER_add_continuation (&destroy_task, h,
				       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    return 0;
  }
  hdr.type = htons (GNUNET_MESSAGE_TYPE_TEST);
  hdr.size = htons (sizeof (struct GNUNET_MessageHeader));
  memcpy (buf, &hdr, sizeof (hdr));
  if (GNUNET_YES != h->receiving)
  {
    h->receiving = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client, &receive_stats, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Schedule the next action to be performed.
 *
 * @param h statistics handle
 */
static void
schedule_action (struct GNUNET_STATISTICS_Handle *h)
{
  struct GNUNET_TIME_Relative timeout;

  if ( (NULL != h->th) ||
       (GNUNET_SCHEDULER_NO_TASK != h->backoff_task) )
    return;                     /* action already pending */
  if (GNUNET_YES != try_connect (h))
  {
    reconnect_later (h);
    return;
  }
  if (NULL != h->current)
    return; /* action already pending */
  /* schedule next action */
  h->current = h->action_head;
  if (NULL == h->current)
  {
    if (GNUNET_YES == h->do_destroy)
    {
      h->do_destroy = GNUNET_SYSERR; /* in 'TEST' mode */
      h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
						   sizeof (struct GNUNET_MessageHeader),
						   SET_TRANSMIT_TIMEOUT,
						   GNUNET_NO,
						   &transmit_test_on_shutdown, h);
    }
    return;
  }
  GNUNET_CONTAINER_DLL_remove (h->action_head, h->action_tail, h->current);
  timeout = GNUNET_TIME_absolute_get_remaining (h->current->timeout);
  if (NULL ==
      (h->th =
       GNUNET_CLIENT_notify_transmit_ready (h->client, h->current->msize,
                                            timeout, GNUNET_YES,
                                            &transmit_action, h)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to transmit request to statistics service.\n");
    do_disconnect (h);
    reconnect_later (h);
  }
}


/**
 * Get statistic from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, NULL for our subsystem
 * @param name name of the statistic value, NULL for all values
 * @param timeout after how long should we give up (and call
 *        cont with an error code)?
 * @param cont continuation to call when done (can be NULL)
 *        This callback CANNOT destroy the statistics handle in the same call.
 * @param proc function to call on each value
 * @param cls closure for cont and proc
 * @return NULL on error
 */
struct GNUNET_STATISTICS_GetHandle *
GNUNET_STATISTICS_get (struct GNUNET_STATISTICS_Handle *handle,
                       const char *subsystem, const char *name,
                       struct GNUNET_TIME_Relative timeout,
                       GNUNET_STATISTICS_Callback cont,
                       GNUNET_STATISTICS_Iterator proc, void *cls)
{
  size_t slen1;
  size_t slen2;
  struct GNUNET_STATISTICS_GetHandle *ai;

  if (NULL == handle)
    return NULL;
  GNUNET_assert (NULL != proc);
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  if (NULL == subsystem)
    subsystem = "";
  if (NULL == name)
    name = "";
  slen1 = strlen (subsystem) + 1;
  slen2 = strlen (name) + 1;
  GNUNET_assert (slen1 + slen2 + sizeof (struct GNUNET_MessageHeader) <
                 GNUNET_SERVER_MAX_MESSAGE_SIZE);
  ai = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_GetHandle));
  ai->sh = handle;
  ai->subsystem = GNUNET_strdup (subsystem);
  ai->name = GNUNET_strdup (name);
  ai->cont = cont;
  ai->proc = proc;
  ai->cls = cls;
  ai->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ai->type = ACTION_GET;
  ai->msize = slen1 + slen2 + sizeof (struct GNUNET_MessageHeader);
  GNUNET_CONTAINER_DLL_insert_tail (handle->action_head, handle->action_tail,
				    ai);
  schedule_action (handle);
  return ai;
}


/**
 * Cancel a 'get' request.  Must be called before the 'cont'
 * function is called.
 *
 * @param gh handle of the request to cancel
 */
void
GNUNET_STATISTICS_get_cancel (struct GNUNET_STATISTICS_GetHandle *gh)
{
  if (NULL == gh)
    return;
  if (gh->sh->current == gh)
  {
    gh->aborted = GNUNET_YES;
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (gh->sh->action_head, gh->sh->action_tail, gh);
    GNUNET_free (gh->name);
    GNUNET_free (gh->subsystem);
    GNUNET_free (gh);
  }
}


/**
 * Watch statistics from the peer (be notified whenever they change).
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for proc
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STATISTICS_watch (struct GNUNET_STATISTICS_Handle *handle,
                         const char *subsystem, const char *name,
                         GNUNET_STATISTICS_Iterator proc, void *proc_cls)
{
  struct GNUNET_STATISTICS_WatchEntry *w;

  if (NULL == handle)
    return GNUNET_SYSERR;
  w = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_WatchEntry));
  w->subsystem = GNUNET_strdup (subsystem);
  w->name = GNUNET_strdup (name);
  w->proc = proc;
  w->proc_cls = proc_cls;
  GNUNET_array_append (handle->watches, handle->watches_size, w);
  schedule_watch_request (handle, w);
  return GNUNET_OK;
}


/**
 * Stop watching statistics from the peer.  
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for proc
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (no such watch)
 */
int
GNUNET_STATISTICS_watch_cancel (struct GNUNET_STATISTICS_Handle *handle,
				const char *subsystem, const char *name,
				GNUNET_STATISTICS_Iterator proc, void *proc_cls)
{
  struct GNUNET_STATISTICS_WatchEntry *w;
  unsigned int i;

  if (NULL == handle)
    return GNUNET_SYSERR;
  for (i=0;i<handle->watches_size;i++)
  {
    w = handle->watches[i];
    if (NULL == w)
      continue;
    if ( (w->proc == proc) &&
	 (w->proc_cls == proc_cls) &&
	 (0 == strcmp (w->name, name)) &&
	 (0 == strcmp (w->subsystem, subsystem)) )
    {
      GNUNET_free (w->name);
      GNUNET_free (w->subsystem);
      GNUNET_free (w);
      handle->watches[i] = NULL;      
      return GNUNET_OK;
    }	 
  }
  return GNUNET_SYSERR;
}



/**
 * Queue a request to change a statistic.
 *
 * @param h statistics handle
 * @param name name of the value
 * @param make_persistent  should the value be kept across restarts?
 * @param value new value or change
 * @param type type of the action (ACTION_SET or ACTION_UPDATE)
 */
static void
add_setter_action (struct GNUNET_STATISTICS_Handle *h, const char *name,
                   int make_persistent, uint64_t value, enum ActionType type)
{
  struct GNUNET_STATISTICS_GetHandle *ai;
  size_t slen;
  size_t nlen;
  size_t nsize;
  int64_t delta;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != name);
  slen = strlen (h->subsystem) + 1;
  nlen = strlen (name) + 1;
  nsize = sizeof (struct GNUNET_STATISTICS_SetMessage) + slen + nlen;
  if (nsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  for (ai = h->action_head; NULL != ai; ai = ai->next)
  {
    if (! ( (0 == strcmp (ai->subsystem, h->subsystem)) &&
	    (0 == strcmp (ai->name, name)) && 
	    ( (ACTION_UPDATE == ai->type) ||
	      (ACTION_SET == ai->type) ) ) )
      continue;
    if (ACTION_SET == ai->type)
    {
      if (ACTION_UPDATE == type)
      {
	delta = (int64_t) value;
	if (delta > 0)
        {
	  /* update old set by new delta */
	  ai->value += delta;
	}
	else
        {
	  /* update old set by new delta, but never go negative */
	  if (ai->value < -delta)
	    ai->value = 0;
	  else
	    ai->value += delta;
	}
      }
      else
      {
	/* new set overrides old set */
	ai->value = value;
      }
    }
    else
    {
      if (ACTION_UPDATE == type)
      {
	/* make delta cummulative */
	delta = (int64_t) value;
	ai->value += delta;
      }
      else
      {
	/* drop old 'update', use new 'set' instead */
	ai->value = value;
	ai->type = type;
      }
    }
    ai->timeout = GNUNET_TIME_relative_to_absolute (SET_TRANSMIT_TIMEOUT);
    ai->make_persistent = make_persistent;
    return;  
  }
  /* no existing entry matches, create a fresh one */
  ai = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_GetHandle));
  ai->sh = h;
  ai->subsystem = GNUNET_strdup (h->subsystem);
  ai->name = GNUNET_strdup (name);
  ai->timeout = GNUNET_TIME_relative_to_absolute (SET_TRANSMIT_TIMEOUT);
  ai->make_persistent = make_persistent;
  ai->msize = nsize;
  ai->value = value;
  ai->type = type;
  GNUNET_CONTAINER_DLL_insert_tail (h->action_head, h->action_tail,
				    ai);
  schedule_action (h);
}


/**
 * Set statistic value for the peer.  Will always use our
 * subsystem (the argument used when "handle" was created).
 *
 * @param handle identification of the statistics service
 * @param name name of the statistic value
 * @param value new value to set
 * @param make_persistent should the value be kept across restarts?
 */
void
GNUNET_STATISTICS_set (struct GNUNET_STATISTICS_Handle *handle,
                       const char *name, uint64_t value, int make_persistent)
{
  if (NULL == handle)
    return;
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  add_setter_action (handle, name, make_persistent, value, ACTION_SET);
}


/**
 * Set statistic value for the peer.  Will always use our
 * subsystem (the argument used when "handle" was created).
 *
 * @param handle identification of the statistics service
 * @param name name of the statistic value
 * @param delta change in value (added to existing value)
 * @param make_persistent should the value be kept across restarts?
 */
void
GNUNET_STATISTICS_update (struct GNUNET_STATISTICS_Handle *handle,
                          const char *name, int64_t delta, int make_persistent)
{
  if (NULL == handle)
    return;
  if (0 == delta)
    return;
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  add_setter_action (handle, name, make_persistent, (uint64_t) delta,
                     ACTION_UPDATE);
}


/* end of statistics_api.c */
