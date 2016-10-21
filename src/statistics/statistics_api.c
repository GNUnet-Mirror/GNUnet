/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file statistics/statistics_api.c
 * @brief API of the statistics service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
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
   * Closure for @e proc
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
   * Closure for @e proc and @e cont.
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
   * Is this a #ACTION_GET, #ACTION_SET, #ACTION_UPDATE or #ACTION_WATCH?
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
   * Message queue to the service.
   */
  struct GNUNET_MQ_Handle *mq;

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
  struct GNUNET_SCHEDULER_Task *backoff_task;

  /**
   * Task for running #do_destroy().
   */
  struct GNUNET_SCHEDULER_Task *destroy_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Maximum heap size observed so far (if available).
   */
  uint64_t peak_heap_size;

  /**
   * Maximum resident set side observed so far (if available).
   */
  uint64_t peak_rss;

  /**
   * Size of the @e watches array.
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
 * Obtain statistics about this process's memory consumption and
 * report those as well (if they changed).
 */
static void
update_memory_statistics (struct GNUNET_STATISTICS_Handle *h)
{
#if ENABLE_HEAP_STATISTICS
  uint64_t current_heap_size = 0;
  uint64_t current_rss = 0;

  if (GNUNET_NO != h->do_destroy)
    return;
#if HAVE_MALLINFO
  {
    struct mallinfo mi;

    mi = mallinfo();
    current_heap_size = mi.uordblks + mi.fordblks;
  }
#endif
#if HAVE_GETRUSAGE
  {
    struct rusage ru;

    if (0 == getrusage (RUSAGE_SELF, &ru))
    {
      current_rss = 1024LL * ru.ru_maxrss;
    }
  }
#endif
  if (current_heap_size > h->peak_heap_size)
  {
    h->peak_heap_size = current_heap_size;
    GNUNET_STATISTICS_set (h,
			   "# peak heap size",
			   current_heap_size,
			   GNUNET_NO);
  }
  if (current_rss > h->peak_rss)
  {
    h->peak_rss = current_rss;
    GNUNET_STATISTICS_set (h,
			   "# peak resident set size",
			   current_rss,
			   GNUNET_NO);
  }
#endif
}


/**
 * Reconnect at a later time, respecting back-off.
 *
 * @param h statistics handle
 */
static void
reconnect_later (struct GNUNET_STATISTICS_Handle *h);


/**
 * Schedule the next action to be performed.
 *
 * @param cls statistics handle to reconnect
 */
static void
schedule_action (void *cls);


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

  slen = strlen (watch->subsystem) + 1;
  nlen = strlen (watch->name) + 1;
  nsize = sizeof (struct GNUNET_MessageHeader) + slen + nlen;
  if (nsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  ai = GNUNET_new (struct GNUNET_STATISTICS_GetHandle);
  ai->sh = h;
  ai->subsystem = GNUNET_strdup (watch->subsystem);
  ai->name = GNUNET_strdup (watch->name);
  ai->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  ai->msize = nsize;
  ai->type = ACTION_WATCH;
  ai->proc = watch->proc;
  ai->cls = watch->proc_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->action_head,
                                    h->action_tail,
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

  h->receiving = GNUNET_NO;
  if (NULL != (c = h->current))
  {
    h->current = NULL;
    if ( (NULL != c->cont) &&
	 (GNUNET_YES != c->aborted) )
    {
      c->cont (c->cls,
               GNUNET_SYSERR);
      c->cont = NULL;
    }
    free_action_item (c);
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
}


/**
 * Process a #GNUNET_MESSAGE_TYPE_STATISTICS_VALUE message.
 *
 * @param cls statistics handle
 * @param smsg message received from the service, never NULL
 * @return #GNUNET_OK if the message was well-formed
 */
static int
check_statistics_value (void *cls,
                        const struct GNUNET_STATISTICS_ReplyMessage *smsg)
{
  const char *service;
  const char *name;
  uint16_t size;

  size = ntohs (smsg->header.size);
  size -= sizeof (struct GNUNET_STATISTICS_ReplyMessage);
  if (size !=
      GNUNET_STRINGS_buffer_tokenize ((const char *) &smsg[1],
                                      size,
                                      2,
                                      &service,
                                      &name))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a #GNUNET_MESSAGE_TYPE_STATISTICS_VALUE message.
 *
 * @param cls statistics handle
 * @param msg message received from the service, never NULL
 * @return #GNUNET_OK if the message was well-formed
 */
static void
handle_statistics_value (void *cls,
                         const struct GNUNET_STATISTICS_ReplyMessage *smsg)
{
  struct GNUNET_STATISTICS_Handle *h = cls;
  const char *service;
  const char *name;
  uint16_t size;

  if (h->current->aborted)
    return;           /* iteration aborted, don't bother */

  size = ntohs (smsg->header.size);
  size -= sizeof (struct GNUNET_STATISTICS_ReplyMessage);
  GNUNET_assert (size ==
                 GNUNET_STRINGS_buffer_tokenize ((const char *) &smsg[1],
                                                 size,
                                                 2,
                                                 &service,
                                                 &name));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received valid statistic on `%s:%s': %llu\n",
       service, name,
       GNUNET_ntohll (smsg->value));
  if (GNUNET_OK !=
      h->current->proc (h->current->cls,
                        service,
                        name,
                        GNUNET_ntohll (smsg->value),
                        0 !=
                        (ntohl (smsg->uid) & GNUNET_STATISTICS_PERSIST_BIT)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Processing of remaining statistics aborted by client.\n");
    h->current->aborted = GNUNET_YES;
  }
}


/**
 * We have received a watch value from the service.  Process it.
 *
 * @param cls statistics handle
 * @param msg the watch value message
 */
static void
handle_statistics_watch_value (void *cls,
                               const struct GNUNET_STATISTICS_WatchValueMessage *wvm)
{
  struct GNUNET_STATISTICS_Handle *h = cls;
  struct GNUNET_STATISTICS_WatchEntry *w;
  uint32_t wid;

  GNUNET_break (0 == ntohl (wvm->reserved));
  wid = ntohl (wvm->wid);
  if (wid >= h->watches_size)
  {
    do_disconnect (h);
    reconnect_later (h);
    return;
  }
  w = h->watches[wid];
  if (NULL == w)
    return;
  (void) w->proc (w->proc_cls,
                  w->subsystem,
                  w->name,
                  GNUNET_ntohll (wvm->value),
                  0 != (ntohl (wvm->flags) & GNUNET_STATISTICS_PERSIST_BIT));
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_STATISTICS_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  if (GNUNET_NO != h->do_destroy)
  {
    h->do_destroy = GNUNET_NO;
    if (NULL != h->destroy_task)
    {
      GNUNET_SCHEDULER_cancel (h->destroy_task);
      h->destroy_task = NULL;
    }
    GNUNET_STATISTICS_destroy (h,
                               GNUNET_NO);
    return;
  }
  do_disconnect (h);
  reconnect_later (h);
}


/**
 * Task used to destroy the statistics handle.
 *
 * @param cls the `struct GNUNET_STATISTICS_Handle`
 */
static void
do_destroy (void *cls)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  h->destroy_task = NULL;
  h->do_destroy = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Running final destruction\n");
  GNUNET_STATISTICS_destroy (h,
                             GNUNET_NO);
}


/**
 * Handle a #GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT_CONFIRM
 * message. We receive this message at the end of the shutdown when
 * the service confirms that all data has been written to disk.
 *
 * @param cls our `struct GNUNET_STATISTICS_Handle *`
 * @param msg the message
 */
static void
handle_disconnect_confirm (void *cls,
			   const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  if (GNUNET_SYSERR != h->do_destroy)
  {
    /* not in shutdown, why do we get 'TEST'? */
    GNUNET_break (0);
    do_disconnect (h);
    reconnect_later (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received DISCONNNECT_CONFIRM message from statistics, can complete disconnect\n");
  if (NULL != h->destroy_task)
    GNUNET_SCHEDULER_cancel (h->destroy_task);
  h->destroy_task = GNUNET_SCHEDULER_add_now (&do_destroy,
                                              h);
}


/**
 * Handle a #GNUNET_MESSAGE_TYPE_STATISTICS_END message. We receive
 * this message in response to a query to indicate that there are no
 * further matching results.
 *
 * @param cls our `struct GNUNET_STATISTICS_Handle *`
 * @param msg the message
 */
static void
handle_statistics_end (void *cls,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_STATISTICS_Handle *h = cls;
  struct GNUNET_STATISTICS_GetHandle *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received end of statistics marker\n");
  if (NULL == (c = h->current))
  {
    GNUNET_break (0);
    do_disconnect (h);
    reconnect_later (h);
    return;
  }
  h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  h->current = NULL;
  schedule_action (h);
  if (NULL != c->cont)
  {
    c->cont (c->cls,
             GNUNET_OK);
    c->cont = NULL;
  }
  free_action_item (c);
}


/**
 * Try to (re)connect to the statistics service.
 *
 * @param h statistics handle to reconnect
 * @return #GNUNET_YES on success, #GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_STATISTICS_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (disconnect_confirm,
                             GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT_CONFIRM,
                             struct GNUNET_MessageHeader,
                             h),
    GNUNET_MQ_hd_fixed_size (statistics_end,
                             GNUNET_MESSAGE_TYPE_STATISTICS_END,
                             struct GNUNET_MessageHeader,
                             h),
    GNUNET_MQ_hd_var_size (statistics_value,
                           GNUNET_MESSAGE_TYPE_STATISTICS_VALUE,
                           struct GNUNET_STATISTICS_ReplyMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (statistics_watch_value,
                             GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE,
                             struct GNUNET_STATISTICS_WatchValueMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_STATISTICS_GetHandle *gh;
  struct GNUNET_STATISTICS_GetHandle *gn;

  if (NULL != h->backoff_task)
    return GNUNET_NO;
  if (NULL != h->mq)
    return GNUNET_YES;
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "statistics",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to connect to statistics service!\n");
    return GNUNET_NO;
  }
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
  for (unsigned int i = 0; i < h->watches_size; i++)
    if (NULL != h->watches[i])
      schedule_watch_request (h,
                              h->watches[i]);
  return GNUNET_YES;
}


/**
 * We've waited long enough, reconnect now.
 *
 * @param cls the `struct GNUNET_STATISTICS_Handle` to reconnect
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  h->backoff_task = NULL;
  schedule_action (h);
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

  GNUNET_assert (NULL == h->backoff_task);
  if (GNUNET_YES == h->do_destroy)
  {
    /* So we are shutting down and the service is not reachable.
     * Chances are that it's down for good and we are not going to connect to
     * it anymore.
     * Give up and don't sync the rest of the data.
     */
    loss = GNUNET_NO;
    for (gh = h->action_head; NULL != gh; gh = gh->next)
      if ( (gh->make_persistent) &&
	   (ACTION_SET == gh->type) )
	loss = GNUNET_YES;
    if (GNUNET_YES == loss)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Could not save some persistent statistics\n"));
    if (NULL != h->destroy_task)
      GNUNET_SCHEDULER_cancel (h->destroy_task);
    h->destroy_task = GNUNET_SCHEDULER_add_now (&do_destroy,
                                                h);
    return;
  }
  h->backoff_task
    = GNUNET_SCHEDULER_add_delayed (h->backoff,
                                    &reconnect_task,
                                    h);
  h->backoff = GNUNET_TIME_STD_BACKOFF (h->backoff);
}



/**
 * Transmit a GET request (and if successful, start to receive
 * the response).
 *
 * @param handle statistics handle
 */
static void
transmit_get (struct GNUNET_STATISTICS_Handle *handle)
{
  struct GNUNET_STATISTICS_GetHandle *c;
  struct GNUNET_MessageHeader *hdr;
  struct GNUNET_MQ_Envelope *env;
  size_t slen1;
  size_t slen2;

  GNUNET_assert (NULL != (c = handle->current));
  slen1 = strlen (c->subsystem) + 1;
  slen2 = strlen (c->name) + 1;
  env = GNUNET_MQ_msg_extra (hdr,
                             slen1 + slen2,
                             GNUNET_MESSAGE_TYPE_STATISTICS_GET);
  GNUNET_assert (slen1 + slen2 ==
                 GNUNET_STRINGS_buffer_fill ((char *) &hdr[1],
                                             slen1 + slen2,
                                             2,
                                             c->subsystem,
                                             c->name));
  GNUNET_MQ_notify_sent (env,
                         &schedule_action,
                         handle);
  GNUNET_MQ_send (handle->mq,
                  env);
}


/**
 * Transmit a WATCH request (and if successful, start to receive
 * the response).
 *
 * @param handle statistics handle
 */
static void
transmit_watch (struct GNUNET_STATISTICS_Handle *handle)
{
  struct GNUNET_MessageHeader *hdr;
  struct GNUNET_MQ_Envelope *env;
  size_t slen1;
  size_t slen2;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting watch request for `%s'\n",
       handle->current->name);
  slen1 = strlen (handle->current->subsystem) + 1;
  slen2 = strlen (handle->current->name) + 1;
  env = GNUNET_MQ_msg_extra (hdr,
                             slen1 + slen2,
                             GNUNET_MESSAGE_TYPE_STATISTICS_WATCH);
  GNUNET_assert (slen1 + slen2 ==
                 GNUNET_STRINGS_buffer_fill ((char *) &hdr[1],
                                             slen1 + slen2,
                                             2,
                                             handle->current->subsystem,
                                             handle->current->name));
  GNUNET_MQ_notify_sent (env,
                         &schedule_action,
                         handle);
  GNUNET_MQ_send (handle->mq,
                  env);
  GNUNET_assert (NULL == handle->current->cont);
  free_action_item (handle->current);
  handle->current = NULL;
  schedule_action (handle);
}


/**
 * Transmit a SET/UPDATE request.
 *
 * @param handle statistics handle
 */
static void
transmit_set (struct GNUNET_STATISTICS_Handle *handle)
{
  struct GNUNET_STATISTICS_SetMessage *r;
  struct GNUNET_MQ_Envelope *env;
  size_t slen;
  size_t nlen;

  slen = strlen (handle->current->subsystem) + 1;
  nlen = strlen (handle->current->name) + 1;
  env = GNUNET_MQ_msg_extra (r,
                             slen + nlen,
                             GNUNET_MESSAGE_TYPE_STATISTICS_SET);
  r->flags = 0;
  r->value = GNUNET_htonll (handle->current->value);
  if (handle->current->make_persistent)
    r->flags |= htonl (GNUNET_STATISTICS_SETFLAG_PERSISTENT);
  if (handle->current->type == ACTION_UPDATE)
    r->flags |= htonl (GNUNET_STATISTICS_SETFLAG_RELATIVE);
  GNUNET_assert (slen + nlen ==
                 GNUNET_STRINGS_buffer_fill ((char *) &r[1],
                                             slen + nlen,
                                             2,
                                             handle->current->subsystem,
                                             handle->current->name));
  GNUNET_assert (NULL == handle->current->cont);
  free_action_item (handle->current);
  handle->current = NULL;
  update_memory_statistics (handle);
  GNUNET_MQ_notify_sent (env,
                         &schedule_action,
                         handle);
  GNUNET_MQ_send (handle->mq,
                  env);
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
  struct GNUNET_STATISTICS_Handle *h;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            "statistics",
                                            "DISABLE"))
    return NULL;
  h = GNUNET_new (struct GNUNET_STATISTICS_Handle);
  h->cfg = cfg;
  h->subsystem = GNUNET_strdup (subsystem);
  h->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  return h;
}


/**
 * Destroy a handle (free all state associated with
 * it).
 *
 * @param h statistics handle to destroy
 * @param sync_first set to #GNUNET_YES if pending SET requests should
 *        be completed
 */
void
GNUNET_STATISTICS_destroy (struct GNUNET_STATISTICS_Handle *h,
                           int sync_first)
{
  struct GNUNET_STATISTICS_GetHandle *pos;
  struct GNUNET_STATISTICS_GetHandle *next;

  if (NULL == h)
    return;
  GNUNET_assert (GNUNET_NO == h->do_destroy); /* Don't call twice. */
  if ( (sync_first) &&
       (NULL != h->mq) &&
       (0 != GNUNET_MQ_get_length (h->mq)) )
  {
    if ( (NULL != h->current) &&
         (ACTION_GET == h->current->type) )
      h->current->aborted = GNUNET_YES;
    next = h->action_head;
    while (NULL != (pos = next))
    {
      next = pos->next;
      if ( (ACTION_GET == pos->type) ||
           (ACTION_WATCH == pos->type) )
      {
	GNUNET_CONTAINER_DLL_remove (h->action_head,
				     h->action_tail,
				     pos);
        free_action_item (pos);
      }
    }
    h->do_destroy = GNUNET_YES;
    schedule_action (h);
    GNUNET_assert (NULL == h->destroy_task);
    h->destroy_task
      = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (h->backoff,
                                                                     5),
                                      &do_destroy,
                                      h);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deferring destruction\n");
    return; /* do not finish destruction just yet */
  }
  /* do clean up all */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning all up\n");
  while (NULL != (pos = h->action_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->action_head,
				 h->action_tail,
				 pos);
    free_action_item (pos);
  }
  do_disconnect (h);
  if (NULL != h->backoff_task)
  {
    GNUNET_SCHEDULER_cancel (h->backoff_task);
    h->backoff_task = NULL;
  }
  if (NULL != h->destroy_task)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (h->destroy_task);
    h->destroy_task = NULL;
  }
  for (unsigned int i = 0; i < h->watches_size; i++)
  {
    if (NULL == h->watches[i])
      continue;
    GNUNET_free (h->watches[i]->subsystem);
    GNUNET_free (h->watches[i]->name);
    GNUNET_free (h->watches[i]);
  }
  GNUNET_array_grow (h->watches,
                     h->watches_size,
                     0);
  GNUNET_free (h->subsystem);
  GNUNET_free (h);
}


/**
 * Schedule the next action to be performed.
 *
 * @param cls statistics handle
 */
static void
schedule_action (void *cls)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  if (NULL != h->backoff_task)
    return;                     /* action already pending */
  if (GNUNET_YES != try_connect (h))
  {
    reconnect_later (h);
    return;
  }
  if (0 < GNUNET_MQ_get_length (h->mq))
    return; /* Wait for queue to be reduced more */    
  /* schedule next action */
  while (NULL == h->current)
  {
    h->current = h->action_head;
    if (NULL == h->current)
    {
      struct GNUNET_MessageHeader *hdr;
      struct GNUNET_MQ_Envelope *env;

      if (GNUNET_YES != h->do_destroy)
        return; /* nothing to do */
      /* let service know that we're done */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Notifying service that we are done\n");
      h->do_destroy = GNUNET_SYSERR; /* in 'TEST' mode */
      env = GNUNET_MQ_msg (hdr,
                           GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT);
      GNUNET_MQ_notify_sent (env,
                             &schedule_action,
                             h);
      GNUNET_MQ_send (h->mq,
                      env);
      return;
    }
    GNUNET_CONTAINER_DLL_remove (h->action_head,
                                 h->action_tail,
                                 h->current);
    switch (h->current->type)
    {
    case ACTION_GET:
      transmit_get (h);
      break;
    case ACTION_SET:
    case ACTION_UPDATE:
      transmit_set (h);
      break;
    case ACTION_WATCH:
      transmit_watch (h);
      break;
    default:
      GNUNET_assert (0);
      break;
    }
  }
}


/**
 * Get statistic from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, NULL for our subsystem
 * @param name name of the statistic value, NULL for all values
 * @param cont continuation to call when done (can be NULL)
 *        This callback CANNOT destroy the statistics handle in the same call.
 * @param proc function to call on each value
 * @param cls closure for @a cont and @a proc
 * @return NULL on error
 */
struct GNUNET_STATISTICS_GetHandle *
GNUNET_STATISTICS_get (struct GNUNET_STATISTICS_Handle *handle,
                       const char *subsystem,
                       const char *name,
                       GNUNET_STATISTICS_Callback cont,
                       GNUNET_STATISTICS_Iterator proc,
                       void *cls)
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
  ai = GNUNET_new (struct GNUNET_STATISTICS_GetHandle);
  ai->sh = handle;
  ai->subsystem = GNUNET_strdup (subsystem);
  ai->name = GNUNET_strdup (name);
  ai->cont = cont;
  ai->proc = proc;
  ai->cls = cls;
  ai->type = ACTION_GET;
  ai->msize = slen1 + slen2 + sizeof (struct GNUNET_MessageHeader);
  GNUNET_CONTAINER_DLL_insert_tail (handle->action_head,
				    handle->action_tail,
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
  gh->cont = NULL;
  if (gh->sh->current == gh)
  {
    gh->aborted = GNUNET_YES;
    return;
  }
  GNUNET_CONTAINER_DLL_remove (gh->sh->action_head,
                               gh->sh->action_tail,
                               gh);
  GNUNET_free (gh->name);
  GNUNET_free (gh->subsystem);
  GNUNET_free (gh);
}


/**
 * Watch statistics from the peer (be notified whenever they change).
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STATISTICS_watch (struct GNUNET_STATISTICS_Handle *handle,
                         const char *subsystem,
                         const char *name,
                         GNUNET_STATISTICS_Iterator proc,
                         void *proc_cls)
{
  struct GNUNET_STATISTICS_WatchEntry *w;

  if (NULL == handle)
    return GNUNET_SYSERR;
  w = GNUNET_new (struct GNUNET_STATISTICS_WatchEntry);
  w->subsystem = GNUNET_strdup (subsystem);
  w->name = GNUNET_strdup (name);
  w->proc = proc;
  w->proc_cls = proc_cls;
  GNUNET_array_append (handle->watches,
                       handle->watches_size,
                       w);
  schedule_watch_request (handle,
                          w);
  return GNUNET_OK;
}


/**
 * Stop watching statistics from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error (no such watch)
 */
int
GNUNET_STATISTICS_watch_cancel (struct GNUNET_STATISTICS_Handle *handle,
				const char *subsystem,
                                const char *name,
				GNUNET_STATISTICS_Iterator proc,
                                void *proc_cls)
{
  struct GNUNET_STATISTICS_WatchEntry *w;

  if (NULL == handle)
    return GNUNET_SYSERR;
  for (unsigned int i=0;i<handle->watches_size;i++)
  {
    w = handle->watches[i];
    if (NULL == w)
      continue;
    if ( (w->proc == proc) &&
	 (w->proc_cls == proc_cls) &&
	 (0 == strcmp (w->name,
		       name)) &&
	 (0 == strcmp (w->subsystem,
		       subsystem)) )
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
 * @param type type of the action (#ACTION_SET or #ACTION_UPDATE)
 */
static void
add_setter_action (struct GNUNET_STATISTICS_Handle *h,
                   const char *name,
                   int make_persistent,
                   uint64_t value,
                   enum ActionType type)
{
  struct GNUNET_STATISTICS_GetHandle *ai;
  size_t slen;
  size_t nlen;
  size_t nsize;
  int64_t delta;

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
    if (! ( (0 == strcmp (ai->subsystem,
			  h->subsystem)) &&
	    (0 == strcmp (ai->name,
			  name)) &&
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
    ai->timeout
      = GNUNET_TIME_relative_to_absolute (SET_TRANSMIT_TIMEOUT);
    ai->make_persistent
      = make_persistent;
    return;
  }
  /* no existing entry matches, create a fresh one */
  ai = GNUNET_new (struct GNUNET_STATISTICS_GetHandle);
  ai->sh = h;
  ai->subsystem = GNUNET_strdup (h->subsystem);
  ai->name = GNUNET_strdup (name);
  ai->timeout = GNUNET_TIME_relative_to_absolute (SET_TRANSMIT_TIMEOUT);
  ai->make_persistent = make_persistent;
  ai->msize = nsize;
  ai->value = value;
  ai->type = type;
  GNUNET_CONTAINER_DLL_insert_tail (h->action_head,
                                    h->action_tail,
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
                       const char *name,
                       uint64_t value,
                       int make_persistent)
{
  if (NULL == handle)
    return;
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  add_setter_action (handle,
                     name,
                     make_persistent,
                     value,
                     ACTION_SET);
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
                          const char *name,
                          int64_t delta,
                          int make_persistent)
{
  if (NULL == handle)
    return;
  if (0 == delta)
    return;
  GNUNET_assert (GNUNET_NO == handle->do_destroy);
  add_setter_action (handle,
                     name,
                     make_persistent,
                     (uint64_t) delta,
                     ACTION_UPDATE);
}


/* end of statistics_api.c */
