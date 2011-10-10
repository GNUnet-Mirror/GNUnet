/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
  ACTION_GET,
  ACTION_SET,
  ACTION_UPDATE,
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
 */
static void schedule_action (struct GNUNET_STATISTICS_Handle *h);

/**
 * Try to (re)connect to the statistics service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int try_connect (struct GNUNET_STATISTICS_Handle *ret);


static void
insert_ai (struct GNUNET_STATISTICS_Handle *h,
	   struct GNUNET_STATISTICS_GetHandle *ai)
{
  GNUNET_CONTAINER_DLL_insert_after (h->action_head, h->action_tail,
				     h->action_tail, ai);
  if (h->action_head == ai)
    schedule_action (h);
}


static void
schedule_watch_request (struct GNUNET_STATISTICS_Handle *h,
			struct GNUNET_STATISTICS_WatchEntry *watch)
{

  struct GNUNET_STATISTICS_GetHandle *ai;
  size_t slen;
  size_t nlen;
  size_t nsize;

  GNUNET_assert (h != NULL);
  if (GNUNET_YES != try_connect (h))
    {
      schedule_action (h);
      return;
    }
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
  insert_ai (h, ai);
}


/**
 * Try to (re)connect to the statistics service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_STATISTICS_Handle *ret)
{
  unsigned int i;

  if (ret->client != NULL)
    return GNUNET_YES;
  ret->client = GNUNET_CLIENT_connect ("statistics", ret->cfg);
  if (ret->client != NULL)
    {
      for (i = 0; i < ret->watches_size; i++)
	schedule_watch_request (ret, ret->watches[i]);
      return GNUNET_YES;
    }
#if DEBUG_STATISTICS
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Failed to connect to statistics service!\n"));
#endif
  return GNUNET_NO;
}


/**
 * Free memory associated with the given action item.
 */
static void
free_action_item (struct GNUNET_STATISTICS_GetHandle *ai)
{
  GNUNET_free_non_null (ai->subsystem);
  GNUNET_free_non_null (ai->name);
  GNUNET_free (ai);
}


/**
 * GET processing is complete, tell client about it.
 */
static void
finish (struct GNUNET_STATISTICS_Handle *h, int code)
{
  struct GNUNET_STATISTICS_GetHandle *pos = h->current;

  h->current = NULL;
  schedule_action (h);
  if (pos != NULL)
    {
      if (pos->cont != NULL)
	pos->cont (pos->cls, code);
      free_action_item (pos);
    }
}


/**
 * Process the message.
 *
 * @return GNUNET_OK if the message was well-formed
 */
static int
process_message (struct GNUNET_STATISTICS_Handle *h,
		 const struct GNUNET_MessageHeader *msg)
{
  char *service;
  char *name;
  const struct GNUNET_STATISTICS_ReplyMessage *smsg;
  uint16_t size;

  if (h->current->aborted)
    {
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Iteration was aborted, ignoring VALUE\n");
#endif
      return GNUNET_OK;		/* don't bother */
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
#if DEBUG_STATISTICS
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received valid statistic on `%s:%s': %llu\n", service, name,
       GNUNET_ntohll (smsg->value));
#endif
  if (GNUNET_OK !=
      h->current->proc (h->current->cls, service, name,
			GNUNET_ntohll (smsg->value),
			0 !=
			(ntohl (smsg->uid) & GNUNET_STATISTICS_PERSIST_BIT)))
    {
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Processing of remaining statistics aborted by client.\n");
#endif
      h->current->aborted = GNUNET_YES;
    }
#if DEBUG_STATISTICS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "VALUE processed successfully\n");
#endif
  return GNUNET_OK;
}


static int
process_watch_value (struct GNUNET_STATISTICS_Handle *h,
		     const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_STATISTICS_WatchValueMessage *wvm;
  struct GNUNET_STATISTICS_WatchEntry *w;
  uint32_t wid;

  if (sizeof (struct GNUNET_STATISTICS_WatchValueMessage) !=
      ntohs (msg->size))
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
  (void) w->proc (w->proc_cls, w->subsystem, w->name,
		  GNUNET_ntohll (wvm->value),
		  0 != (ntohl (wvm->flags) & GNUNET_STATISTICS_PERSIST_BIT));
  return GNUNET_OK;
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

  if (msg == NULL)
    {
      if (NULL != h->client)
	{
	  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
	  h->client = NULL;
	}
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
	   "Error receiving statistics from service, is the service running?\n");
#endif
      finish (h, GNUNET_SYSERR);
      return;
    }
  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_STATISTICS_END:
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Received end of statistics marker\n");
#endif
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
      finish (h, GNUNET_OK);
      return;
    case GNUNET_MESSAGE_TYPE_STATISTICS_VALUE:
      if (GNUNET_OK == process_message (h, msg))
	{
	  /* finally, look for more! */
#if DEBUG_STATISTICS
	  LOG (GNUNET_ERROR_TYPE_DEBUG,
	       "Processing VALUE done, now reading more\n");
#endif
	  GNUNET_CLIENT_receive (h->client, &receive_stats, h,
				 GNUNET_TIME_absolute_get_remaining
				 (h->current->timeout));
	  h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
	  return;
	}
      GNUNET_break (0);
      break;
    case GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE:
      if (GNUNET_OK == process_watch_value (h, msg))
	{
	  h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
	  GNUNET_assert (h->watches_size > 0);
	  GNUNET_CLIENT_receive (h->client, &receive_stats, h,
				 GNUNET_TIME_UNIT_FOREVER_REL);
	  return;
	}
      GNUNET_break (0);
      break;
    default:
      GNUNET_break (0);
      break;
    }
  if (NULL != h->client)
    {
      GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
      h->client = NULL;
    }
  finish (h, GNUNET_SYSERR);
}


/**
 * Transmit a GET request (and if successful, start to receive
 * the response).
 */
static size_t
transmit_get (struct GNUNET_STATISTICS_Handle *handle, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr;
  size_t slen1;
  size_t slen2;
  uint16_t msize;

  if (buf == NULL)
    {
      /* timeout / error */
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Transmission of request for statistics failed!\n");
#endif
      finish (handle, GNUNET_SYSERR);
      return 0;
    }
  slen1 = strlen (handle->current->subsystem) + 1;
  slen2 = strlen (handle->current->name) + 1;
  msize = slen1 + slen2 + sizeof (struct GNUNET_MessageHeader);
  GNUNET_assert (msize <= size);
  hdr = (struct GNUNET_MessageHeader *) buf;
  hdr->size = htons (msize);
  hdr->type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_GET);
  GNUNET_assert (slen1 + slen2 ==
		 GNUNET_STRINGS_buffer_fill ((char *) &hdr[1], slen1 + slen2,
					     2, handle->current->subsystem,
					     handle->current->name));
  if (!handle->receiving)
    {
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Transmission of GET done, now reading response\n");
#endif
      handle->receiving = GNUNET_YES;
      GNUNET_CLIENT_receive (handle->client, &receive_stats, handle,
			     GNUNET_TIME_absolute_get_remaining
			     (handle->current->timeout));
    }
  return msize;
}


/**
 * Transmit a WATCH request (and if successful, start to receive
 * the response).
 */
static size_t
transmit_watch (struct GNUNET_STATISTICS_Handle *handle, size_t size,
		void *buf)
{
  struct GNUNET_MessageHeader *hdr;
  size_t slen1;
  size_t slen2;
  uint16_t msize;

  if (buf == NULL)
    {
      /* timeout / error */
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Transmission of request for statistics failed!\n");
#endif
      finish (handle, GNUNET_SYSERR);
      return 0;
    }
#if DEBUG_STATISTICS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transmitting watch request for `%s'\n",
       handle->current->name);
#endif
  slen1 = strlen (handle->current->subsystem) + 1;
  slen2 = strlen (handle->current->name) + 1;
  msize = slen1 + slen2 + sizeof (struct GNUNET_MessageHeader);
  GNUNET_assert (msize <= size);
  hdr = (struct GNUNET_MessageHeader *) buf;
  hdr->size = htons (msize);
  hdr->type = htons (GNUNET_MESSAGE_TYPE_STATISTICS_WATCH);
  GNUNET_assert (slen1 + slen2 ==
		 GNUNET_STRINGS_buffer_fill ((char *) &hdr[1], slen1 + slen2,
					     2, handle->current->subsystem,
					     handle->current->name));
  if (GNUNET_YES != handle->receiving)
    {
      handle->receiving = GNUNET_YES;
      GNUNET_CLIENT_receive (handle->client, &receive_stats, handle,
			     GNUNET_TIME_UNIT_FOREVER_REL);
    }
  finish (handle, GNUNET_OK);
  return msize;
}


/**
 * Transmit a SET/UPDATE request.
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
      finish (handle, GNUNET_SYSERR);
      return 0;
    }

  slen = strlen (handle->current->subsystem) + 1;
  nlen = strlen (handle->current->name) + 1;
  nsize = sizeof (struct GNUNET_STATISTICS_SetMessage) + slen + nlen;
  if (size < nsize)
    {
      GNUNET_break (0);
      finish (handle, GNUNET_SYSERR);
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
  finish (handle, GNUNET_OK);
  return nsize;
}


static size_t
transmit_action (void *cls, size_t size, void *buf)
{
  struct GNUNET_STATISTICS_Handle *handle = cls;
  size_t ret;

  handle->th = NULL;
  switch (handle->current->type)
    {
    case ACTION_GET:
      ret = transmit_get (handle, size, buf);
      break;
    case ACTION_SET:
    case ACTION_UPDATE:
      ret = transmit_set (handle, size, buf);
      break;
    case ACTION_WATCH:
      ret = transmit_watch (handle, size, buf);
      break;
    default:
      ret = 0;
      GNUNET_break (0);
      break;
    }
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

  GNUNET_assert (subsystem != NULL);
  GNUNET_assert (cfg != NULL);
  ret = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_Handle));
  ret->cfg = cfg;
  ret->subsystem = GNUNET_strdup (subsystem);
  ret->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  if (GNUNET_YES != try_connect (ret))
    {
      GNUNET_free (ret->subsystem);
      GNUNET_free (ret);
      return NULL;
    }
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
  struct GNUNET_STATISTICS_GetHandle *prev;
  struct GNUNET_TIME_Relative timeout;
  int i;

  if (h == NULL)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != h->backoff_task)
    GNUNET_SCHEDULER_cancel (h->backoff_task);
  if (sync_first)
    {
      if (h->current != NULL)
	{
	  if (h->current->type == ACTION_GET)
	    {
	      GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
	      h->th = NULL;
	      free_action_item (h->current);
	      h->current = NULL;
	    }
	}
      pos = h->action_head;
      prev = NULL;
      while (pos != NULL)
	{
	  next = pos->next;
	  if (pos->type == ACTION_GET)
	    {
	      if (prev == NULL)
		h->action_head = next;
	      else
		prev->next = next;
	      free_action_item (pos);
	    }
	  else
	    {
	      prev = pos;
	    }
	  pos = next;
	}
      h->action_tail = prev;
      if (h->current == NULL)
	{
	  h->current = h->action_head;
	  if (h->action_head != NULL)
	    {
	      h->action_head = h->action_head->next;
	      if (h->action_head == NULL)
		h->action_tail = NULL;
	    }
	}
      h->do_destroy = GNUNET_YES;
      if ((h->current != NULL) && (h->th == NULL))
	{
	  timeout = GNUNET_TIME_absolute_get_remaining (h->current->timeout);
	  h->th =
	    GNUNET_CLIENT_notify_transmit_ready (h->client, h->current->msize,
						 timeout, GNUNET_YES,
						 &transmit_action, h);
	  GNUNET_assert (NULL != h->th);
	}
      if (h->th != NULL)
	return;
    }
  if (NULL != h->th)
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
      h->th = NULL;
    }
  if (h->current != NULL)
    free_action_item (h->current);
  while (NULL != (pos = h->action_head))
    {
      h->action_head = pos->next;
      free_action_item (pos);
    }
  if (h->client != NULL)
    {
      GNUNET_CLIENT_disconnect (h->client, GNUNET_YES);
      h->client = NULL;
    }
  for (i = 0; i < h->watches_size; i++)
    {
      GNUNET_free (h->watches[i]->subsystem);
      GNUNET_free (h->watches[i]->name);
      GNUNET_free (h->watches[i]);
    }
  GNUNET_array_grow (h->watches, h->watches_size, 0);
  GNUNET_free (h->subsystem);
  GNUNET_free (h);
}


static void
finish_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  h->backoff_task = GNUNET_SCHEDULER_NO_TASK;
  finish (h, GNUNET_SYSERR);
}


/**
 * Schedule the next action to be performed.
 */
static void
schedule_action (struct GNUNET_STATISTICS_Handle *h)
{
  struct GNUNET_TIME_Relative timeout;

  if (h->current != NULL)
    return;			/* action already pending */
  if (GNUNET_YES != try_connect (h))
    {
      h->backoff_task =
	GNUNET_SCHEDULER_add_delayed (h->backoff, &finish_task, h);
      h->backoff = GNUNET_TIME_relative_multiply (h->backoff, 2);
      h->backoff =
	GNUNET_TIME_relative_min (h->backoff,
				  GNUNET_CONSTANTS_SERVICE_TIMEOUT);
      return;
    }

  /* schedule next action */
  h->current = h->action_head;
  if (NULL == h->current)
    {
      if (h->do_destroy)
	{
	  h->do_destroy = GNUNET_NO;
	  GNUNET_STATISTICS_destroy (h, GNUNET_YES);
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
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Failed to transmit request to statistics service.\n");
#endif
      finish (h, GNUNET_SYSERR);
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

  GNUNET_assert (handle != NULL);
  GNUNET_assert (proc != NULL);
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  if (GNUNET_YES != try_connect (handle))
    {
#if DEBUG_STATISTICS
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Failed to connect to statistics service, can not get value `%s:%s'.\n",
	   strlen (subsystem) ? subsystem : "*", strlen (name) ? name : "*");
#endif
      return NULL;
    }
  if (subsystem == NULL)
    subsystem = "";
  if (name == NULL)
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
  insert_ai (handle, ai);
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
  if (gh->sh->current == gh)
    {
      gh->aborted = GNUNET_YES;
    }
  else
    {
      GNUNET_CONTAINER_DLL_remove (gh->sh->action_head, gh->sh->action_tail,
				   gh);
      GNUNET_free (gh->name);
      GNUNET_free (gh->subsystem);
      GNUNET_free (gh);
    }
}


/**
 * Watch statistics from the peer (be notified whenever they change).
 * Note that the only way to cancel a "watch" request is to destroy
 * the statistics handle given as the first argument to this call.
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

  if (handle == NULL)
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


static void
add_setter_action (struct GNUNET_STATISTICS_Handle *h, const char *name,
		   int make_persistent, uint64_t value, enum ActionType type)
{
  struct GNUNET_STATISTICS_GetHandle *ai;
  size_t slen;
  size_t nlen;
  size_t nsize;
  int64_t delta;

  GNUNET_assert (h != NULL);
  GNUNET_assert (name != NULL);
  if (GNUNET_YES != try_connect (h))
    return;
  slen = strlen (h->subsystem) + 1;
  nlen = strlen (name) + 1;
  nsize = sizeof (struct GNUNET_STATISTICS_SetMessage) + slen + nlen;
  if (nsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      return;
    }
  ai = h->action_head;
  while (ai != NULL)
    {
      if ((0 == strcmp (ai->subsystem, h->subsystem)) &&
	  (0 == strcmp (ai->name, name)) && ((ai->type == ACTION_UPDATE) ||
					     (ai->type == ACTION_SET)))
	{
	  if (ai->type == ACTION_SET)
	    {
	      if (type == ACTION_UPDATE)
		{
		  delta = (int64_t) value;
		  if (delta > 0)
		    {
		      ai->value += delta;
		    }
		  else
		    {
		      if (ai->value < -delta)
			ai->value = 0;
		      else
			ai->value += delta;
		    }
		}
	      else
		{
		  ai->value = value;
		}
	    }
	  else
	    {
	      if (type == ACTION_UPDATE)
		{
		  delta = (int64_t) value;
		  ai->value += delta;
		}
	      else
		{
		  ai->value = value;
		  ai->type = type;
		}
	    }
	  ai->timeout =
	    GNUNET_TIME_relative_to_absolute (SET_TRANSMIT_TIMEOUT);
	  ai->make_persistent = make_persistent;
	  return;
	}
      ai = ai->next;
    }
  ai = GNUNET_malloc (sizeof (struct GNUNET_STATISTICS_GetHandle));
  ai->sh = h;
  ai->subsystem = GNUNET_strdup (h->subsystem);
  ai->name = GNUNET_strdup (name);
  ai->timeout = GNUNET_TIME_relative_to_absolute (SET_TRANSMIT_TIMEOUT);
  ai->make_persistent = make_persistent;
  ai->msize = nsize;
  ai->value = value;
  ai->type = type;
  insert_ai (h, ai);
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
  if (handle == NULL)
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
			  const char *name, int64_t delta,
			  int make_persistent)
{
  if (handle == NULL)
    return;
  if (delta == 0)
    return;
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  add_setter_action (handle, name, make_persistent, (uint64_t) delta,
		     ACTION_UPDATE);
}


/* end of statistics_api.c */
