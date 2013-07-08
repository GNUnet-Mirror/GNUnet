/*
     This file is part of GNUnet.
     (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file namestore/namestore_api.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_constants.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"


#define LOG(kind,...) GNUNET_log_from (kind, "namestore-api",__VA_ARGS__)


/**
 * An QueueEntry used to store information for a pending
 * NAMESTORE record operation
 */
struct GNUNET_NAMESTORE_QueueEntry
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_QueueEntry *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_QueueEntry *prev;

  /**
   * Main handle to access the namestore.
   */
  struct GNUNET_NAMESTORE_Handle *nsh;

  /**
   * Continuation to call
   */
  GNUNET_NAMESTORE_ContinuationWithStatus cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Function to call with the records we get back; or NULL.
   */
  GNUNET_NAMESTORE_RecordProcessor proc;

  /**
   * Closure for 'proc'.
   */
  void *proc_cls;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t op_id;

};


/**
 * Handle for a zone iterator operation
 */
struct GNUNET_NAMESTORE_ZoneIterator
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_ZoneIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_NAMESTORE_ZoneIterator *prev;

  /**
   * Main handle to access the namestore.
   */
  struct GNUNET_NAMESTORE_Handle *h;

  /**
   * The continuation to call with the results
   */
  GNUNET_NAMESTORE_RecordProcessor proc;

  /**
   * Closure for 'proc'.
   */
  void* proc_cls;

  /**
   * If this iterator iterates over a specific zone this value contains the
   * short hash of the zone
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t op_id;

  /**
   * GNUNET_YES if this iterator iterates over a specific zone
   * GNUNET_NO if this iterator iterates over all zones
   *
   * Zone is stored GNUNET_CRYPTO_ShortHashCode 'zone';
   */
  int has_zone;
};


/**
 * Message in linked list we should send to the service.  The
 * actual binary message follows this struct.
 */
struct PendingMessage
{

  /**
   * Kept in a DLL.
   */
  struct PendingMessage *next;

  /**
   * Kept in a DLL.
   */
  struct PendingMessage *prev;

  /**
   * Size of the message.
   */
  size_t size;

  /**
   * Is this the 'START' message?
   */
  int is_init;
};


/**
 * Connection to the NAMESTORE service.
 */
struct GNUNET_NAMESTORE_Handle
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

  /**
   * Head of linked list of pending messages to send to the service
   */
  struct PendingMessage * pending_head;

  /**
   * Tail of linked list of pending messages to send to the service
   */
  struct PendingMessage * pending_tail;

  /**
   * Head of pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry * op_head;

  /**
   * Tail of pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry * op_tail;

  /**
   * Head of pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator * z_head;

  /**
   * Tail of pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator * z_tail;

  /**
   * Reconnect task
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;

  /**
   * The last operation id used for a NAMESTORE operation
   */
  uint32_t last_op_id_used;

};


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *h);


/**
 * Handle an incoming message of type 'GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE'
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return GNUNET_OK on success, GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_lookup_name_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
                             const struct LookupNameResponseMessage * msg,
                             size_t size)
{
  const char *name;
  const char * rd_tmp;
  const struct GNUNET_CRYPTO_EccSignature *signature;
  struct GNUNET_TIME_Absolute expire;
  const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *public_key_tmp;
  size_t exp_msg_len;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;
  int contains_sig;
  int rd_count;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received `%s'\n", "LOOKUP_NAME_RESPONSE");
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  contains_sig = ntohs (msg->contains_sig);
  expire = GNUNET_TIME_absolute_ntoh (msg->expire);
  exp_msg_len = sizeof (struct LookupNameResponseMessage) +
      sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded) +
      name_len + rd_len;
  if (msg_len != exp_msg_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name = (const char *) &msg[1];
  if ( (name_len > 0) &&
       ('\0' != name[name_len -1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rd_tmp = &name[name_len];
  {
    struct GNUNET_NAMESTORE_RecordData rd[rd_count];

    if (GNUNET_OK != GNUNET_NAMESTORE_records_deserialize(rd_len, rd_tmp, rd_count, rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_NO == contains_sig)
      signature = NULL;
    else
      signature = &msg->signature;
    if (0 == name_len)
      name = NULL;
    if (NULL != name)
      public_key_tmp = &msg->public_key;
    else
      public_key_tmp = NULL;    
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls, public_key_tmp, expire, name, rd_count, (rd_count > 0) ? rd : NULL, signature);      
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type 'GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE'
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return GNUNET_OK on success, GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_record_put_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
			    const struct RecordPutResponseMessage* msg,
			    size_t size)
{
  int res;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received `%s'\n",
       "RECORD_PUT_RESPONSE");
  res = ntohl (msg->op_result);
  /* TODO: add actual error message from namestore to response... */
  if (NULL != qe->cont)    
    qe->cont (qe->cont_cls, res, (GNUNET_OK == res) ? NULL : _("Namestore failed to add record"));
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type 'GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE'
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return GNUNET_OK on success, GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_record_create_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
			       const struct RecordCreateResponseMessage* msg,
			       size_t size)
{
  int res;
  const char *emsg;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received `%s'\n",
       "RECORD_CREATE_RESPONSE");
  /* TODO: add actual error message from namestore to response... */
  res = ntohl (msg->op_result);
  if (GNUNET_SYSERR == res)
    emsg = _("Namestore failed to add record\n");
  else
    emsg = NULL;
  if (NULL != qe->cont)    
    qe->cont (qe->cont_cls, res, emsg);
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type 'GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE'
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return GNUNET_OK on success, GNUNET_NO if we notified the client about
 *         the error, GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_zone_to_name_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
			      const struct ZoneToNameResponseMessage* msg,
			      size_t size)
{
  int res;
  struct GNUNET_TIME_Absolute expire;
  size_t name_len;
  size_t rd_ser_len;
  unsigned int rd_count;
  const char * name_tmp;
  const char * rd_tmp;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Received `%s'\n",
       "ZONE_TO_NAME_RESPONSE");
  res = ntohs (msg->res);
  switch (res)
  {
  case GNUNET_SYSERR:
    LOG (GNUNET_ERROR_TYPE_DEBUG, "An error occured during zone to name operation\n");
    break;
  case GNUNET_NO:
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Namestore has no result for zone to name mapping \n");
    break;
  case GNUNET_YES:
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Namestore has result for zone to name mapping \n");
    name_len = ntohs (msg->name_len);
    rd_count = ntohs (msg->rd_count);
    rd_ser_len = ntohs (msg->rd_len);
    expire = GNUNET_TIME_absolute_ntoh(msg->expire);
    name_tmp = (const char *) &msg[1];
    if ( (name_len > 0) &&
	 ('\0' != name_tmp[name_len -1]) )
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    rd_tmp = &name_tmp[name_len];
    {
      struct GNUNET_NAMESTORE_RecordData rd[rd_count];
      if (GNUNET_OK != GNUNET_NAMESTORE_records_deserialize(rd_ser_len, rd_tmp, rd_count, rd))
      {
	GNUNET_break (0);
	return GNUNET_SYSERR;
      }
      /* normal end, call continuation with result */
      if (NULL != qe->proc)
	qe->proc (qe->proc_cls, &msg->zone_key, expire, name_tmp, rd_count, rd, &msg->signature);           
      /* return is important here: break would call continuation with error! */
      return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* error case, call continuation with error */
  if (NULL != qe->proc)
    qe->proc (qe->proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL, 0, NULL, NULL);
  return GNUNET_OK;
}


/**
 * Handle incoming messages for record operations
 *
 * @param qe the respective zone iteration handle
 * @param msg the message we received
 * @param type the message type in HBO
 * @param size the message size
 * @return GNUNET_OK on success, GNUNET_NO if we notified the client about
 *         the error, GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
manage_record_operations (struct GNUNET_NAMESTORE_QueueEntry *qe,
                          const struct GNUNET_MessageHeader *msg,
                          uint16_t type, 
			  size_t size)
{
  /* handle different message type */
  switch (type) 
  {
  case GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE:
    if (size < sizeof (struct LookupNameResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_lookup_name_response (qe, (const struct LookupNameResponseMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE:
    if (size != sizeof (struct RecordPutResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_record_put_response (qe, (const struct RecordPutResponseMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE:
    if (size != sizeof (struct RecordCreateResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_record_create_response (qe, (const struct RecordCreateResponseMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE:
    if (size < sizeof (struct ZoneToNameResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_zone_to_name_response (qe, (const struct ZoneToNameResponseMessage *) msg, size);
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Handle a response from NAMESTORE service for a zone iteration request
 *
 * @param ze the respective iterator for this operation
 * @param msg the message containing the respoonse
 * @param size the message size
 * @return GNUNET_YES on success, 'ze' should be kept, GNUNET_NO on success if 'ze' should
 *         not be kept any longer, GNUNET_SYSERR on error (disconnect) and 'ze' should be kept
 */
static int
handle_zone_iteration_response (struct GNUNET_NAMESTORE_ZoneIterator *ze,
                                const struct LookupNameResponseMessage *msg,
                                size_t size)
{
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded pubdummy;
  size_t msg_len;
  size_t exp_msg_len;
  size_t name_len;
  size_t rd_len;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;
  struct GNUNET_TIME_Absolute expire;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received `%s'\n",
       "ZONE_ITERATION_RESPONSE");
  msg_len = ntohs (msg->gns_header.header.size);
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  expire = GNUNET_TIME_absolute_ntoh (msg->expire);
  exp_msg_len = sizeof (struct LookupNameResponseMessage) + name_len + rd_len;
  if (msg_len != exp_msg_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  memset (&pubdummy, '\0', sizeof (pubdummy));
  if ((0 == name_len) && (0 == (memcmp (&msg->public_key, &pubdummy, sizeof (pubdummy)))))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration is completed!\n");
    if (NULL != ze->proc)
      ze->proc(ze->proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL , 0, NULL, NULL);
    return GNUNET_NO;
  }
  name_tmp = (const char *) &msg[1];
  if ((name_tmp[name_len -1] != '\0') || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rd_ser_tmp = (const char *) &name_tmp[name_len];
  {
    struct GNUNET_NAMESTORE_RecordData rd[rd_count];

    if (GNUNET_OK != GNUNET_NAMESTORE_records_deserialize (rd_len, rd_ser_tmp, rd_count, rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (NULL != ze->proc)
      ze->proc(ze->proc_cls, &msg->public_key, expire, name_tmp, rd_count, rd, &msg->signature);
    return GNUNET_YES;
  }
}


/**
 * Handle incoming messages for zone iterations
 *
 * @param ze the respective zone iteration handle
 * @param msg the message we received
 * @param type the message type in HBO
 * @param size the message size
 * @return GNUNET_YES on success, 'ze' should be kept, GNUNET_NO on success if 'ze' should
 *         not be kept any longer, GNUNET_SYSERR on error (disconnect) and 'ze' should be kept
 */
static int
manage_zone_operations (struct GNUNET_NAMESTORE_ZoneIterator *ze,
                        const struct GNUNET_MessageHeader *msg,
                        int type, size_t size)
{
  /* handle different message type */
  switch (type) 
  {
  case GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE:
    if (size < sizeof (struct LookupNameResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_zone_iteration_response (ze, (const struct LookupNameResponseMessage *) msg, size);
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the 'struct GNUNET_NAMESTORE_SchedulingHandle'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_namestore_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  const struct GNUNET_NAMESTORE_Header *gm;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_NAMESTORE_ZoneIterator *ze;
  uint16_t size;
  uint16_t type;
  uint32_t r_id;
  int ret;

  if (NULL == msg)
  {
    force_reconnect (h);
    return;
  }
  size = ntohs (msg->size);
  type = ntohs (msg->type);
  if (size < sizeof (struct GNUNET_NAMESTORE_Header))
  {
    GNUNET_break_op (0);
    GNUNET_CLIENT_receive (h->client, &process_namestore_message, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  gm = (const struct GNUNET_NAMESTORE_Header *) msg;
  r_id = ntohl (gm->r_id);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received message type %u size %u op %u\n", 
       (unsigned int) type,
       (unsigned int) size, 
       (unsigned int) r_id);

  /* Is it a record related operation ? */
  for (qe = h->op_head; qe != NULL; qe = qe->next)
    if (qe->op_id == r_id)
      break;
  if (NULL != qe)
  {
    ret = manage_record_operations (qe, msg, type, size);
    if (GNUNET_OK != ret)    
    {
      /* protocol error, need to reconnect */
      h->reconnect = GNUNET_YES;
    }
    if (GNUNET_SYSERR != ret)
    {
      /* client was notified about success or failure, clean up 'qe' */
      GNUNET_CONTAINER_DLL_remove (h->op_head,
				   h->op_tail,
				   qe);
      GNUNET_free (qe);
    }
  }

  /* Is it a zone iteration operation ? */
  for (ze = h->z_head; ze != NULL; ze = ze->next)
    if (ze->op_id == r_id)
      break;
  if (NULL != ze)
  {
    ret = manage_zone_operations (ze, msg, type, size);
    if (GNUNET_NO == ret)
    {
      /* end of iteration, clean up 'ze' */
      GNUNET_CONTAINER_DLL_remove (h->z_head,
				   h->z_tail,
				   ze);
      GNUNET_free (ze);
    }
    if (GNUNET_SYSERR == ret)
    {
      /* protocol error, need to reconnect */
      h->reconnect = GNUNET_YES;
    }
  }
  if (GNUNET_YES == h->reconnect)
  {
    force_reconnect (h);
    return;
  }
  GNUNET_CLIENT_receive (h->client, &process_namestore_message, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param h handle to use
 */
static void
do_transmit (struct GNUNET_NAMESTORE_Handle *h);


/**
 * We can now transmit a message to NAMESTORE. Do it.
 *
 * @param cls the 'struct GNUNET_NAMESTORE_Handle'
 * @param size number of bytes we can transmit
 * @param buf where to copy the messages
 * @return number of bytes copied into buf
 */
static size_t
transmit_message_to_namestore (void *cls, size_t size, void *buf)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct PendingMessage *p;
  size_t ret;
  char *cbuf;

  h->th = NULL;
  if ((0 == size) || (NULL == buf))
  {
    force_reconnect (h);
    return 0;
  }
  ret = 0;
  cbuf = buf;
  while ((NULL != (p = h->pending_head)) && (p->size <= size))
  {
    memcpy (&cbuf[ret], &p[1], p->size);
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (h->pending_head, h->pending_tail, p);
    if (GNUNET_YES == p->is_init)
      GNUNET_CLIENT_receive (h->client, &process_namestore_message, h,
                             GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (p);
  }
  do_transmit (h);
  return ret;
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param h handle to use
 */
static void
do_transmit (struct GNUNET_NAMESTORE_Handle *h)
{
  struct PendingMessage *p;

  if (NULL != h->th)
    return; /* transmission request already pending */
  if (NULL == (p = h->pending_head))
    return; /* transmission queue empty */
  if (NULL == h->client)
    return;                     /* currently reconnecting */
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, p->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_message_to_namestore,
                                           h);
}


/**
 * Reconnect to namestore service.
 *
 * @param h the handle to the NAMESTORE service
 */
static void
reconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  struct PendingMessage *p;
  struct StartMessage *init;

  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("namestore", h->cfg);
  GNUNET_assert (NULL != h->client);
  if ((NULL == (p = h->pending_head)) || (GNUNET_YES != p->is_init))
  {
    p = GNUNET_malloc (sizeof (struct PendingMessage) +
                       sizeof (struct StartMessage));
    p->size = sizeof (struct StartMessage);
    p->is_init = GNUNET_YES;
    init = (struct StartMessage *) &p[1];
    init->header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_START);
    init->header.size = htons (sizeof (struct StartMessage));
    GNUNET_CONTAINER_DLL_insert (h->pending_head, h->pending_tail, p);
  }
  do_transmit (h);
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (h);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  h->reconnect = GNUNET_NO;
  GNUNET_CLIENT_disconnect (h->client);
  h->client = NULL;
  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
						    &reconnect_task,
						    h);
}


/**
 * Get a fresh operation id to distinguish between namestore requests
 *
 * @param h the namestore handle
 * @return next operation id to use
 */
static uint32_t
get_op_id (struct GNUNET_NAMESTORE_Handle *h)
{
  return h->last_op_id_used++;
}


/**
 * Initialize the connection with the NAMESTORE service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_NAMESTORE_Handle *
GNUNET_NAMESTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAMESTORE_Handle *h;

  h = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Handle));
  h->cfg = cfg;
  h->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect_task, h);
  h->last_op_id_used = 0;
  return h;
}


/**
 * Disconnect from the namestore service (and free associated
 * resources).
 *
 * @param h handle to the namestore
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  struct PendingMessage *p;
  struct GNUNET_NAMESTORE_QueueEntry *q;
  struct GNUNET_NAMESTORE_ZoneIterator *z;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  GNUNET_assert (NULL != h);
  while (NULL != (p = h->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->pending_head, h->pending_tail, p);
    GNUNET_free (p);
  }
  GNUNET_break (NULL == h->op_head);
  while (NULL != (q = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, q);
    GNUNET_free (q);
  }
  GNUNET_break (NULL == h->z_head);
  while (NULL != (z = h->z_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->z_head, h->z_tail, z);
    GNUNET_free (z);
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (h);
}


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  This API is used when we cache signatures from other
 * authorities.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param freshness when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put (struct GNUNET_NAMESTORE_Handle *h,
			     const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *zone_key,
			     const char *name,
			     struct GNUNET_TIME_Absolute freshness,
			     unsigned int rd_count,
			     const struct GNUNET_NAMESTORE_RecordData *rd,
			     const struct GNUNET_CRYPTO_EccSignature *signature,
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  struct RecordPutMessage * msg;
  char * rd_ser;
  char * name_tmp;
  size_t msg_size;
  size_t name_len;
  size_t rd_ser_len;
  uint32_t rid;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != zone_key);
  GNUNET_assert (NULL != name);
  GNUNET_assert (NULL != rd);
  GNUNET_assert (NULL != signature);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Storing %u records under name `%s'\n",
       rd_count,
       name);
  name_len = strlen(name) + 1;
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return NULL;
  }
  rid = get_op_id (h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  /* setup msg */
  rd_ser_len = GNUNET_NAMESTORE_records_get_size(rd_count, rd);
  msg_size = sizeof (struct RecordPutMessage) + name_len  + rd_ser_len;
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct RecordPutMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->signature = *signature;
  msg->name_len = htons (name_len);
  msg->expire = GNUNET_TIME_absolute_hton (freshness);
  msg->rd_len = htons (rd_ser_len);
  msg->rd_count = htons (rd_count);
  msg->public_key = *zone_key;
  name_tmp = (char *) &msg[1];
  memcpy (name_tmp, name, name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize(rd_count, rd, rd_ser_len, rd_ser);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Sending `%s' message for name `%s' with size %u\n", 
       "NAMESTORE_RECORD_PUT", 
       name, msg_size);
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  return qe;
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param public_key public key of the zone
 * @param freshness block expiration
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @return GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *public_key,
                                   const struct GNUNET_TIME_Absolute freshness,
				   const char *name,
				   unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd,
				   const struct GNUNET_CRYPTO_EccSignature *signature)
{
  size_t rd_ser_len;
  size_t name_len;
  char *name_tmp;
  char *rd_ser;
  struct GNUNET_CRYPTO_EccSignaturePurpose *sig_purpose;
  struct GNUNET_TIME_AbsoluteNBO *expire_tmp;
  struct GNUNET_TIME_AbsoluteNBO expire_nbo = GNUNET_TIME_absolute_hton (freshness);
  uint32_t sig_len;

  GNUNET_assert (NULL != public_key);
  GNUNET_assert (NULL != name);
  GNUNET_assert (NULL != rd);
  GNUNET_assert (NULL != signature);
  name_len = strlen (name) + 1;
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  sig_len = sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) + sizeof (struct GNUNET_TIME_AbsoluteNBO) + rd_ser_len + name_len;
  {
    char sig_buf[sig_len] GNUNET_ALIGN;

    sig_purpose = (struct GNUNET_CRYPTO_EccSignaturePurpose *) sig_buf;
    sig_purpose->size = htonl (sig_len);
    sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
    expire_tmp = (struct GNUNET_TIME_AbsoluteNBO *) &sig_purpose[1];
    memcpy (expire_tmp, &expire_nbo, sizeof (struct GNUNET_TIME_AbsoluteNBO));
    name_tmp = (char *) &expire_tmp[1];
    memcpy (name_tmp, name, name_len);
    rd_ser = &name_tmp[name_len];
    GNUNET_assert (rd_ser_len ==
		   GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser));
    return GNUNET_CRYPTO_ecc_verify (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN, sig_purpose, signature, public_key);
  }
}


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  This API is used by the authority of a zone.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of records in 'rd' array
 * @param rd record data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put_by_authority (struct GNUNET_NAMESTORE_Handle *h,
					  const struct GNUNET_CRYPTO_EccPrivateKey *pkey,
					  const char *name,
					  unsigned int rd_count,
					  const struct GNUNET_NAMESTORE_RecordData *rd,
					  GNUNET_NAMESTORE_ContinuationWithStatus cont,
					  void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  char * name_tmp;
  char * pkey_tmp;
  char * rd_ser;
  size_t rd_ser_len;
  size_t msg_size;
  size_t name_len;
  size_t key_len;
  uint32_t rid;
  struct RecordCreateMessage * msg;
  struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded * pkey_enc;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != pkey);
  GNUNET_assert (NULL != name);
  name_len = strlen(name) + 1;
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return NULL;
  }
  rid = get_op_id (h);
  qe = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  pkey_enc = GNUNET_CRYPTO_ecc_encode_key (pkey);
  GNUNET_assert (NULL != pkey_enc);

  /* setup msg */
  key_len = ntohs (pkey_enc->size);
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  msg_size = sizeof (struct RecordCreateMessage) + key_len + name_len + rd_ser_len;
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct RecordCreateMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->name_len = htons (name_len);
  msg->rd_count = htons (rd_count);
  msg->rd_len = htons (rd_ser_len);
  msg->pkey_len = htons (key_len);
  msg->expire = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS);
  pkey_tmp = (char *) &msg[1];
  memcpy (pkey_tmp, pkey_enc, key_len);
  name_tmp = &pkey_tmp[key_len];
  memcpy (name_tmp, name, name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser);
  GNUNET_free (pkey_enc);

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Sending `%s' message for name `%s' with size %u\n", 
       "NAMESTORE_RECORD_CREATE", name, msg_size);
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  return qe;
}


/**
 * Get a result for a particular key from the namestore.  The processor
 * will only be called once.  
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param name name to look up
 * @param record_type desired record type, 0 for all
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_record (struct GNUNET_NAMESTORE_Handle *h, 
			      const struct GNUNET_CRYPTO_ShortHashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  struct LookupNameMessage * msg;
  size_t msg_size;
  size_t name_len;
  uint32_t rid;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != zone);
  GNUNET_assert (NULL != name);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looking for record of type %u under name `%s'\n",
       record_type,
       name);
  name_len = strlen (name) + 1;
  if ((name_len == 0) || (name_len > MAX_NAME_LEN))
  {
    GNUNET_break (0);
    return NULL;
  }

  rid = get_op_id(h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->proc = proc;
  qe->proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  msg_size = sizeof (struct LookupNameMessage) + name_len;
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct LookupNameMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->record_type = htonl (record_type);
  msg->name_len = htonl (name_len);
  msg->zone = *zone;
  memcpy (&msg[1], name, name_len);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending `%s' message for name `%s'\n", "NAMESTORE_LOOKUP_NAME", name);
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  return qe;
}


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the processor.
 *
 * @param h handle to the namestore
 * @param zone hash of public key of the zone to look up in, never NULL
 * @param value_zone hash of the public key of the target zone (value), never NULL
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_to_name (struct GNUNET_NAMESTORE_Handle *h,
                               const struct GNUNET_CRYPTO_ShortHashCode *zone,
                               const struct GNUNET_CRYPTO_ShortHashCode *value_zone,
                               GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  struct ZoneToNameMessage * msg;
  size_t msg_size;
  uint32_t rid;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != zone);
  GNUNET_assert (NULL != value_zone);
  rid = get_op_id(h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->proc = proc;
  qe->proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  msg_size = sizeof (struct ZoneToNameMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneToNameMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->zone = *zone;
  msg->value_zone = *value_zone;

  /* transmit message */
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  return qe;
}


/**
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). This MUST lock the GNUNET_NAMESTORE_Handle
 * for any other calls than GNUNET_NAMESTORE_zone_iterator_next and
 * GNUNET_NAMESTORE_zone_iteration_stop.  "proc" will be called once
 * immediately, and then again after
 * "GNUNET_NAMESTORE_zone_iterator_next" is invoked.
 *
 * @param h handle to the namestore
 * @param zone zone to access, NULL for all zones
 * @param must_have_flags flags that must be set for the record to be returned
 * @param must_not_have_flags flags that must NOT be set for the record to be returned
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a name of NULL.
 * @param proc_cls closure for proc
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (struct GNUNET_NAMESTORE_Handle *h,
				       const struct GNUNET_CRYPTO_ShortHashCode *zone,
				       enum GNUNET_NAMESTORE_RecordFlags must_have_flags,
				       enum GNUNET_NAMESTORE_RecordFlags must_not_have_flags,
				       GNUNET_NAMESTORE_RecordProcessor proc,
				       void *proc_cls)
{
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct PendingMessage *pe;
  struct ZoneIterationStartMessage * msg;
  size_t msg_size;
  uint32_t rid;

  GNUNET_assert (NULL != h);
  rid = get_op_id(h);
  it = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_ZoneIterator));
  it->h = h;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->op_id = rid;
  if (NULL != zone)
  {
    it->zone = *zone;
    it->has_zone = GNUNET_YES;
  }
  else
  {
    memset (&it->zone, '\0', sizeof (it->zone));
    it->has_zone = GNUNET_NO;
  }
  GNUNET_CONTAINER_DLL_insert_tail (h->z_head, h->z_tail, it);

  msg_size = sizeof (struct ZoneIterationStartMessage);
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneIterationStartMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  if (NULL != zone)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Sending `%s' message for zone `%s'\n", 
	 "ZONE_ITERATION_START", GNUNET_NAMESTORE_short_h2s(zone));
    msg->zone = *zone;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Sending `%s' message for all zones\n", "ZONE_ITERATION_START");
    memset (&msg->zone, '\0', sizeof (msg->zone));
  }
  msg->must_have_flags = ntohs (must_have_flags);
  msg->must_not_have_flags = ntohs (must_not_have_flags);
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  return it;
}


/**
 * Calls the record processor specified in GNUNET_NAMESTORE_zone_iteration_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iterator_next (struct GNUNET_NAMESTORE_ZoneIterator *it)
{
  struct GNUNET_NAMESTORE_Handle *h;
  struct ZoneIterationNextMessage * msg;
  struct PendingMessage *pe;
  size_t msg_size;

  GNUNET_assert (NULL != it);
  h = it->h;
  msg_size = sizeof (struct ZoneIterationNextMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneIterationNextMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (it->op_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "ZONE_ITERATION_NEXT");
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
}


/**
 * Stops iteration and releases the namestore handle for further calls.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it)
{
  struct GNUNET_NAMESTORE_Handle *h;
  struct PendingMessage *pe;
  size_t msg_size;
  struct ZoneIterationStopMessage * msg;

  GNUNET_assert (NULL != it);
  h = it->h;
  GNUNET_CONTAINER_DLL_remove (h->z_head,
			       h->z_tail,
			       it);
  msg_size = sizeof (struct ZoneIterationStopMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneIterationStopMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (it->op_id);
  if (GNUNET_YES == it->has_zone)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Sending `%s' message for zone `%s'\n", "ZONE_ITERATION_STOP", GNUNET_NAMESTORE_short_h2s(&it->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Sending `%s' message for all zones\n", "ZONE_ITERATION_STOP");
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  GNUNET_free (it);
}


/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe)
{
  struct GNUNET_NAMESTORE_Handle *h = qe->nsh;

  GNUNET_assert (NULL != qe);
  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);
  GNUNET_free(qe);
}


/* end of namestore_api.c */
