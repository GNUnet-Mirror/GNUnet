/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 *
 * @file gns/gns_api.c
 * @brief library to access the GNS service
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "gns.h"
#include "gnunet_gns_service.h"

/* TODO into gnunet_protocols */
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT 24
#define GNUNET_MESSAGE_TYPE_GNS_SHORTEN 25
#define GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT 26
#define GNUNET_MESSAGE_TYPE_GNS_GET_AUTH 27
#define GNUNET_MESSAGE_TYPE_GNS_GET_AUTH_RESULT 28

/**
 * A QueueEntry.
 */
struct GNUNET_GNS_QueueEntry
{
  /**
   * DLL
   */
  struct GNUNET_GNS_QueueEntry *next;
  
  /**
   * DLL
   */
  struct GNUNET_GNS_QueueEntry *prev;

  /* request id */
  uint32_t r_id;
  
  /* handle to gns */
  struct GNUNET_GNS_Handle *gns_handle;
  
  /* processor to call on shorten result */
  GNUNET_GNS_ShortenResultProcessor shorten_proc;
  
  /* processor to call on lookup result */
  GNUNET_GNS_LookupResultProcessor lookup_proc;

  /* processor to call on authority lookup result */
  GNUNET_GNS_GetAuthResultProcessor auth_proc;
  
  /* processor closure */
  void *proc_cls;
  
};


/**
 * Entry in our list of messages to be (re-)transmitted.
 */
struct PendingMessage
{
  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *prev;

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *next;

  /**
   * Size of the message.
   */
  size_t size;

};


/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;
  
  uint32_t r_id;
  
  /**
   * Head of linked list of shorten messages we would like to transmit.
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of shorten messages we would like to transmit.
   */
  struct PendingMessage *pending_tail;
  
  /**
   * Head of linked list of shorten messages we would like to transmit.
   */
  struct GNUNET_GNS_QueueEntry *shorten_head;

  /**
   * Tail of linked list of shorten messages we would like to transmit.
   */
  struct GNUNET_GNS_QueueEntry *shorten_tail;
  
  /**
   * Head of linked list of lookup messages we would like to transmit.
   */
  struct GNUNET_GNS_QueueEntry *lookup_head;

  /**
   * Tail of linked list of lookup messages we would like to transmit.
   */
  struct GNUNET_GNS_QueueEntry *lookup_tail;
  
  /**
   * Head of linked list of authority lookup messages we would like to transmit.
   */
  struct GNUNET_GNS_QueueEntry *get_auth_head;

  /**
   * Tail of linked list of authority lookup messages we would like to transmit.
   */
  struct GNUNET_GNS_QueueEntry *get_auth_tail;

  /**
   * Reconnect task
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Did we start our receive loop yet?
   */
  int in_receive;

  /**
   * Reconnect necessary
   */
  int reconnect;
};

/**
 * Try to send messages from list of messages to send
 * @param handle GNS_Handle
 */
static void
process_pending_messages (struct GNUNET_GNS_Handle *handle);


/**
 * Reconnect to GNS service.
 *
 * @param h the handle to the namestore service
 */
static void
reconnect (struct GNUNET_GNS_Handle *h)
{
  GNUNET_assert (NULL == h->client);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Trying to connect to GNS...\n");
  h->client = GNUNET_CLIENT_connect ("gns", h->cfg);
  GNUNET_assert (NULL != h->client);
}

/**
 * Reconnect to GNS
 *
 * @param cls the handle
 * @param tc task context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_GNS_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (h);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_GNS_Handle *h)
{
  h->reconnect = GNUNET_NO;
  GNUNET_CLIENT_disconnect (h->client);
  h->client = NULL;
  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                    &reconnect_task,
                                                    h);
}

/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf);

/**
 * Handler for messages received from the GNS service
 *
 * @param cls the 'struct GNUNET_GNS_Handle'
 * @param msg the incoming message
 */
static void
process_message (void *cls, const struct GNUNET_MessageHeader *msg);

/**
 * Try to send messages from list of messages to send
 */
static void
process_pending_messages (struct GNUNET_GNS_Handle *handle)
{
  struct PendingMessage *p;

  if (handle->client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         "process_pending_messages called, but client is null\n");
    return;
  }
  
  if (handle->th != NULL)
    return;
  
  if (NULL == (p = handle->pending_head))
    return;
  
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Trying to transmit %d bytes...\n", p->size);

  handle->th =
    GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                         p->size,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_NO, &transmit_pending,
                                         handle);
  if (NULL != handle->th)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "notify_transmit_ready returned NULL!\n");
}


/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_GNS_Handle *handle = cls;
  struct PendingMessage *p;
  size_t tsize;
  char *cbuf;

  handle->th = NULL;
  
  if ((size == 0) || (buf == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission to GNS service failed!\n");
    force_reconnect(handle);
    return 0;
  }
  
  tsize = 0;
  cbuf = buf;

  if (NULL == (p = handle->pending_head))
    return 0;

  while ((NULL != (p = handle->pending_head)) && (p->size <= size))
  {
    memcpy (&cbuf[tsize], &p[1], p->size);
    tsize += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail, p);
    if (GNUNET_YES != handle->in_receive)
    {
      GNUNET_CLIENT_receive (handle->client, &process_message, handle,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      handle->in_receive = GNUNET_YES;
    }
    GNUNET_free(p);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %d bytes\n", tsize);

  process_pending_messages(handle);
  return tsize;
}

/**
 * Process a given reply that might match the given
 * request.
 *
 * @param qe a queue entry
 * @param msg the shorten msg received
 */
static void
process_shorten_reply (struct GNUNET_GNS_QueueEntry *qe,
                       const struct GNUNET_GNS_ClientShortenResultMessage *msg)
{
  struct GNUNET_GNS_Handle *h = qe->gns_handle;
  const char *short_name;

  GNUNET_CONTAINER_DLL_remove(h->shorten_head, h->shorten_tail, qe);

  short_name = (char*)(&msg[1]);

  if (ntohs (((struct GNUNET_MessageHeader*)msg)->size) <
      sizeof (struct GNUNET_GNS_ClientShortenResultMessage))
  {
    GNUNET_break (0);
    force_reconnect (h);
    GNUNET_free(qe);
    return;
  }
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received shortened reply `%s' from GNS service\n",
              short_name);
  
  GNUNET_CLIENT_receive (h->client, &process_message, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  qe->shorten_proc(qe->proc_cls, short_name);
  GNUNET_free(qe);

}


/**
 * Process a given reply that might match the given
 * request.
 *
 * @param qe the handle to the request
 * @param msg the message to process
 */
static void
process_get_auth_reply (struct GNUNET_GNS_QueueEntry *qe,
                       const struct GNUNET_GNS_ClientGetAuthResultMessage *msg)
{
  struct GNUNET_GNS_Handle *h = qe->gns_handle;
  const char *auth_name;

  GNUNET_CONTAINER_DLL_remove(h->get_auth_head, h->get_auth_tail, qe);

  auth_name = (char*)(&msg[1]);

  if (ntohs (((struct GNUNET_MessageHeader*)msg)->size) <
      sizeof (struct GNUNET_GNS_ClientGetAuthResultMessage))
  {
    GNUNET_free(qe);
    GNUNET_break (0);
    force_reconnect (h);
    return;
  }
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received GET_AUTH reply `%s' from GNS service\n",
              auth_name);
  
  GNUNET_CLIENT_receive (h->client, &process_message, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  qe->auth_proc(qe->proc_cls, auth_name);
  GNUNET_free(qe);

}
/**
 * Process a given reply to the lookup request
 *
 * @param qe a queue entry
 * @param msg the lookup message received
 */
static void
process_lookup_reply (struct GNUNET_GNS_QueueEntry *qe,
                      const struct GNUNET_GNS_ClientLookupResultMessage *msg)
{
  struct GNUNET_GNS_Handle *h = qe->gns_handle;
  int rd_count = ntohl(msg->rd_count);
  size_t len = ntohs (((struct GNUNET_MessageHeader*)msg)->size);
  struct GNUNET_NAMESTORE_RecordData rd[rd_count];

  GNUNET_CONTAINER_DLL_remove(h->lookup_head, h->lookup_tail, qe);

  if (len < sizeof (struct GNUNET_GNS_ClientLookupResultMessage))
  {
    GNUNET_free(qe);
    GNUNET_break (0);
    force_reconnect (h);
    return;
  }

  len -= sizeof(struct GNUNET_GNS_ClientLookupResultMessage);

  GNUNET_CLIENT_receive (h->client, &process_message, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  if (GNUNET_SYSERR == GNUNET_NAMESTORE_records_deserialize (len,
                                                             (char*)&msg[1],
                                                             rd_count,
                                                             rd))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to serialize lookup reply from GNS service!\n");
    qe->lookup_proc(qe->proc_cls, 0, NULL);
  }
  else
  {
  
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received lookup reply from GNS service (count=%d)\n",
                ntohl(msg->rd_count));
    qe->lookup_proc(qe->proc_cls, rd_count, rd);
  }
  GNUNET_free(qe);
}

/**
 * Handler for messages received from the GNS service
 *
 * @param cls the 'struct GNUNET_GNS_Handle'
 * @param msg the incoming message
 */
static void
process_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_GNS_Handle *handle = cls;
  struct GNUNET_GNS_QueueEntry *qe;
  const struct GNUNET_GNS_ClientLookupResultMessage *lookup_msg;
  const struct GNUNET_GNS_ClientShortenResultMessage *shorten_msg;
  const struct GNUNET_GNS_ClientGetAuthResultMessage *get_auth_msg;
  uint16_t type;
  uint32_t r_id;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got message\n");
  if (msg == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
         "Error receiving data from GNS service, reconnecting\n");
    force_reconnect (handle);
    return;
  }

  type = ntohs (msg->type);

  if (type == GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got lookup msg\n");
    lookup_msg = (const struct GNUNET_GNS_ClientLookupResultMessage *) msg;
    r_id = ntohl (lookup_msg->id);
    
    if (r_id > handle->r_id)
    {
      /** no request found */
      GNUNET_break_op (0);
      GNUNET_CLIENT_receive (handle->client, &process_message, handle,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      return;
    }

    for (qe = handle->lookup_head; qe != NULL; qe = qe->next)
    {
      if (qe->r_id == r_id)
        break;
    }
    if (qe)
      process_lookup_reply(qe, lookup_msg);
    
    return;

  }
  else if (type == GNUNET_MESSAGE_TYPE_GNS_SHORTEN_RESULT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got SHORTEN_RESULT msg\n");
    shorten_msg = (struct GNUNET_GNS_ClientShortenResultMessage *) msg;
    
    r_id = ntohl (shorten_msg->id);
    
    if (r_id > handle->r_id)
    {
      /** no request found */
      GNUNET_break_op (0);
      GNUNET_CLIENT_receive (handle->client, &process_message, handle,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      return;
    }

    for (qe = handle->shorten_head; qe != NULL; qe = qe->next)
    {
      if (qe->r_id == r_id)
        break;
    }
    if (qe)
      process_shorten_reply(qe, shorten_msg);
    return;
  }
  else if (type == GNUNET_MESSAGE_TYPE_GNS_GET_AUTH_RESULT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got GET_AUTH_RESULT msg\n");
    get_auth_msg = (struct GNUNET_GNS_ClientGetAuthResultMessage *) msg;

    r_id = ntohl (get_auth_msg->id);

    if (r_id > handle->r_id)
    {
      /** no request found */
      GNUNET_break_op (0);
      GNUNET_CLIENT_receive (handle->client, &process_message, handle,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      return;
    }

    for (qe = handle->get_auth_head; qe != NULL; qe = qe->next)
    {
      if (qe->r_id == r_id)
        break;
    }
    if (qe)
      process_get_auth_reply(qe, get_auth_msg);
    return;
  }


  if (GNUNET_YES == handle->reconnect)
    force_reconnect (handle);
  
}


/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_GNS_Handle *
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_GNS_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_GNS_Handle));
  handle->reconnect = GNUNET_NO;
  handle->cfg = cfg;
  reconnect (handle);
  //handle->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect_task, handle);
  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  handle->r_id = 0;
  handle->in_receive = GNUNET_NO;
  return handle;
}


/**
 * Shutdown connection with the GNS service.
 *
 * @param handle handle of the GNS connection to stop
 */
void
GNUNET_GNS_disconnect (struct GNUNET_GNS_Handle *handle)
{
  GNUNET_CLIENT_disconnect (handle->client);
  if (GNUNET_SCHEDULER_NO_TASK != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free(handle);
  /* disco from GNS */
}

/*
 * Helper function to generate request ids
 * 
 * @param h handle
 * @return a new id
 */
static uint32_t
get_request_id (struct GNUNET_GNS_Handle *h)
{
  uint32_t r_id = h->r_id;
  h->r_id++;
  return r_id;
}

/**
 * Perform an asynchronous Lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param zone the zone to start the resolution in
 * @param type the record type to look up
 * @param proc processor to call on result
 * @param proc_cls closure for processor
 * @return handle to the get
 */
struct GNUNET_GNS_QueueEntry *
GNUNET_GNS_lookup_zone (struct GNUNET_GNS_Handle *handle,
                   const char * name,
                   struct GNUNET_CRYPTO_ShortHashCode *zone,
                   enum GNUNET_GNS_RecordType type,
                   GNUNET_GNS_LookupResultProcessor proc,
                   void *proc_cls)
{
  /* IPC to shorten gns names, return shorten_handle */
  struct GNUNET_GNS_ClientLookupMessage *lookup_msg;
  struct GNUNET_GNS_QueueEntry *qe;
  size_t msize;
  struct PendingMessage *pending;

  if (NULL == name)
  {
    return NULL;
  }

  msize = sizeof (struct GNUNET_GNS_ClientLookupMessage) + strlen(name) + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to lookup %s in GNS\n", name);

  qe = GNUNET_malloc(sizeof (struct GNUNET_GNS_QueueEntry));
  qe->gns_handle = handle;
  qe->lookup_proc = proc;
  qe->proc_cls = proc_cls;
  qe->r_id = get_request_id(handle);
  GNUNET_CONTAINER_DLL_insert_tail(handle->lookup_head,
                                   handle->lookup_tail, qe);

  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  memset(pending, 0, (sizeof (struct PendingMessage) + msize));
  
  pending->size = msize;

  lookup_msg = (struct GNUNET_GNS_ClientLookupMessage *) &pending[1];
  lookup_msg->header.type = htons (GNUNET_MESSAGE_TYPE_GNS_LOOKUP);
  lookup_msg->header.size = htons (msize);
  lookup_msg->id = htonl(qe->r_id);

  if (NULL != zone)
  {
    lookup_msg->use_default_zone = htonl(0);
    memcpy(&lookup_msg->zone, zone, sizeof(struct GNUNET_CRYPTO_ShortHashCode));
  }
  else
  {
    lookup_msg->use_default_zone = htonl(1);
    memset(&lookup_msg->zone, 0, sizeof(struct GNUNET_CRYPTO_ShortHashCode));
  }

  lookup_msg->type = htonl(type);

  memcpy(&lookup_msg[1], name, strlen(name));

  GNUNET_CONTAINER_DLL_insert_tail (handle->pending_head, handle->pending_tail,
                               pending);
  
  process_pending_messages (handle);
  return qe;
}

/**
 * Perform an asynchronous Lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param type the record type to look up
 * @param proc processor to call on result
 * @param proc_cls closure for processor
 * @return handle to the get
 */
struct GNUNET_GNS_QueueEntry *
GNUNET_GNS_lookup (struct GNUNET_GNS_Handle *handle,
                   const char * name,
                   enum GNUNET_GNS_RecordType type,
                   GNUNET_GNS_LookupResultProcessor proc,
                   void *proc_cls)
{
  return GNUNET_GNS_lookup_zone (handle, name, NULL, type, proc, proc_cls);
}

/**
 * Perform a name shortening operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param zone the zone to start the resolution in
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the operation
 */
struct GNUNET_GNS_QueueEntry *
GNUNET_GNS_shorten_zone (struct GNUNET_GNS_Handle *handle,
                    const char * name,
                    struct GNUNET_CRYPTO_ShortHashCode *zone,
                    GNUNET_GNS_ShortenResultProcessor proc,
                    void *proc_cls)
{
  /* IPC to shorten gns names, return shorten_handle */
  struct GNUNET_GNS_ClientShortenMessage *shorten_msg;
  struct GNUNET_GNS_QueueEntry *qe;
  size_t msize;
  struct PendingMessage *pending;

  if (NULL == name)
  {
    return NULL;
  }

  msize = sizeof (struct GNUNET_GNS_ClientShortenMessage) + strlen(name) + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to shorten %s in GNS\n", name);

  qe = GNUNET_malloc(sizeof (struct GNUNET_GNS_QueueEntry));
  qe->gns_handle = handle;
  qe->shorten_proc = proc;
  qe->proc_cls = proc_cls;
  qe->r_id = get_request_id(handle);
  GNUNET_CONTAINER_DLL_insert_tail(handle->shorten_head,
                                   handle->shorten_tail, qe);

  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  memset(pending, 0, (sizeof (struct PendingMessage) + msize));
  
  pending->size = msize;

  shorten_msg = (struct GNUNET_GNS_ClientShortenMessage *) &pending[1];
  shorten_msg->header.type = htons (GNUNET_MESSAGE_TYPE_GNS_SHORTEN);
  shorten_msg->header.size = htons (msize);
  shorten_msg->id = htonl(qe->r_id);
  
  if (NULL != zone)
  {
    shorten_msg->use_default_zone = htonl(0);
    memcpy(&shorten_msg->zone, zone,
           sizeof(struct GNUNET_CRYPTO_ShortHashCode));
  }
  else
  {
    shorten_msg->use_default_zone = htonl(1);
    memset(&shorten_msg->zone, 0, sizeof(struct GNUNET_CRYPTO_ShortHashCode));
  }

  memcpy(&shorten_msg[1], name, strlen(name));

  GNUNET_CONTAINER_DLL_insert_tail (handle->pending_head, handle->pending_tail,
                               pending);
  
  process_pending_messages (handle);
  return qe;
}

/**
 * Perform a name shortening operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the operation
 */
struct GNUNET_GNS_QueueEntry *
GNUNET_GNS_shorten (struct GNUNET_GNS_Handle *handle,
                    const char * name,
                    GNUNET_GNS_ShortenResultProcessor proc,
                    void *proc_cls)
{
  return GNUNET_GNS_shorten_zone (handle, name, NULL, proc, proc_cls);
}
/**
 * Perform an authority lookup for a given name.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up authority for
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the operation
 */
struct GNUNET_GNS_QueueEntry *
GNUNET_GNS_get_authority (struct GNUNET_GNS_Handle *handle,
                    const char * name,
                    GNUNET_GNS_GetAuthResultProcessor proc,
                    void *proc_cls)
{
  struct GNUNET_GNS_ClientGetAuthMessage *get_auth_msg;
  struct GNUNET_GNS_QueueEntry *qe;
  size_t msize;
  struct PendingMessage *pending;

  if (NULL == name)
  {
    return NULL;
  }

  msize = sizeof (struct GNUNET_GNS_ClientGetAuthMessage) + strlen(name) + 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to look up authority for %s in GNS\n", name);

  qe = GNUNET_malloc(sizeof (struct GNUNET_GNS_QueueEntry));
  qe->gns_handle = handle;
  qe->auth_proc = proc;
  qe->proc_cls = proc_cls;
  qe->r_id = get_request_id(handle);
  GNUNET_CONTAINER_DLL_insert_tail(handle->get_auth_head,
                                   handle->get_auth_tail, qe);

  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  memset(pending, 0, (sizeof (struct PendingMessage) + msize));
  
  pending->size = msize;

  get_auth_msg = (struct GNUNET_GNS_ClientGetAuthMessage *) &pending[1];
  get_auth_msg->header.type = htons (GNUNET_MESSAGE_TYPE_GNS_GET_AUTH);
  get_auth_msg->header.size = htons (msize);
  get_auth_msg->id = htonl(qe->r_id);

  memcpy(&get_auth_msg[1], name, strlen(name));

  GNUNET_CONTAINER_DLL_insert_tail (handle->pending_head, handle->pending_tail,
                               pending);
  
  process_pending_messages (handle);
  return qe;
}


/* end of gns_api.c */
