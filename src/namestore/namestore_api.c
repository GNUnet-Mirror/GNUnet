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
#include "gnunet_gns_service.h"
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
  GNUNET_NAMESTORE_RecordMonitor proc;

  /**
   * Closure for @e proc.
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
  GNUNET_NAMESTORE_RecordMonitor proc;

  /**
   * Closure for @e proc.
   */
  void* proc_cls;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey zone;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t op_id;

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
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of pending messages to send to the service
   */
  struct PendingMessage *pending_tail;

  /**
   * Head of pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry *op_head;

  /**
   * Tail of pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry *op_tail;

  /**
   * Head of pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator *z_head;

  /**
   * Tail of pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator *z_tail;

  /**
   * Reconnect task
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Delay introduced before we reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;

  /**
   * Did we start to receive yet?
   */
  int is_receiving;

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
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_record_store_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
			      const struct RecordStoreResponseMessage* msg,
			      size_t size)
{
  int res;
  const char *emsg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s' with result %i\n",
       "RECORD_STORE_RESPONSE",
       ntohl (msg->op_result));
  /* TODO: add actual error message from namestore to response... */
  res = ntohl (msg->op_result);
  if (GNUNET_SYSERR == res)
    emsg = _("Namestore failed to store record\n");
  else
    emsg = NULL;
  if (NULL != qe->cont)
    qe->cont (qe->cont_cls, res, emsg);
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_lookup_result (struct GNUNET_NAMESTORE_QueueEntry *qe,
                      const struct LabelLookupResponseMessage *msg,
                      size_t size)
{
  const char *name;
  const char *rd_tmp;
  size_t exp_msg_len;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;
  unsigned int rd_count;
  int found;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s'\n",
       "RECORD_LOOKUP_RESULT");

  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  found = ntohs (msg->found);
  exp_msg_len = sizeof (struct LabelLookupResponseMessage) + name_len + rd_len;
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
  if (GNUNET_NO == found)
  {
    /* label was not in namestore */
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls,
                &msg->private_key,
                name,
                0, NULL);
    return GNUNET_OK;
  }

  rd_tmp = &name[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize(rd_len, rd_tmp, rd_count, rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (0 == name_len)
      name = NULL;
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls,
                &msg->private_key,
                name,
                rd_count,
                (rd_count > 0) ? rd : NULL);
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_record_result (struct GNUNET_NAMESTORE_QueueEntry *qe,
		      const struct RecordResultMessage *msg,
		      size_t size)
{
  const char *name;
  const char *rd_tmp;
  size_t exp_msg_len;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;
  unsigned int rd_count;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s'\n",
       "RECORD_RESULT");
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  GNUNET_break (0 == ntohs (msg->reserved));
  exp_msg_len = sizeof (struct RecordResultMessage) + name_len + rd_len;
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
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize(rd_len, rd_tmp, rd_count, rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (0 == name_len)
      name = NULL;
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls,
		&msg->private_key,
		name,
		rd_count,
		(rd_count > 0) ? rd : NULL);
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE.
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_NO if we notified the client about
 *         the error, #GNUNET_SYSERR on error and we did NOT notify the client
 */
static int
handle_zone_to_name_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
			      const struct ZoneToNameResponseMessage *msg,
			      size_t size)
{
  int res;
  size_t name_len;
  size_t rd_ser_len;
  unsigned int rd_count;
  const char *name_tmp;
  const char *rd_tmp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s'\n",
       "ZONE_TO_NAME_RESPONSE");
  res = ntohs (msg->res);
  switch (res)
  {
  case GNUNET_SYSERR:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "An error occured during zone to name operation\n");
    break;
  case GNUNET_NO:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Namestore has no result for zone to name mapping \n");
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls, &msg->zone, NULL, 0, NULL);
    return GNUNET_NO;
  case GNUNET_YES:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Namestore has result for zone to name mapping \n");
    name_len = ntohs (msg->name_len);
    rd_count = ntohs (msg->rd_count);
    rd_ser_len = ntohs (msg->rd_len);
    name_tmp = (const char *) &msg[1];
    if ( (name_len > 0) &&
	 ('\0' != name_tmp[name_len -1]) )
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    rd_tmp = &name_tmp[name_len];
    {
      struct GNUNET_GNSRECORD_Data rd[rd_count];

      if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize(rd_ser_len, rd_tmp, rd_count, rd))
      {
	GNUNET_break (0);
	return GNUNET_SYSERR;
      }
      /* normal end, call continuation with result */
      if (NULL != qe->proc)
	qe->proc (qe->proc_cls,
		  &msg->zone,
		  name_tmp,
		  rd_count, rd);
      /* return is important here: break would call continuation with error! */
      return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* error case, call continuation with error */
  if (NULL != qe->proc)
    qe->proc (qe->proc_cls, NULL, NULL, 0, NULL);
  return GNUNET_NO;
}


/**
 * Handle incoming messages for record operations
 *
 * @param qe the respective zone iteration handle
 * @param msg the message we received
 * @param type the message type in host byte order
 * @param size the message size
 * @return #GNUNET_OK on success, #GNUNET_NO if we notified the client about
 *         the error, #GNUNET_SYSERR on error and we did NOT notify the client
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
  case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE:
    if (size != sizeof (struct RecordStoreResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_record_store_response (qe, (const struct RecordStoreResponseMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE:
    if (size < sizeof (struct ZoneToNameResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_zone_to_name_response (qe, (const struct ZoneToNameResponseMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT:
    if (size < sizeof (struct RecordResultMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_record_result (qe, (const struct RecordResultMessage *) msg, size);
  case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE:
    if (size < sizeof (struct LabelLookupResponseMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_lookup_result (qe, (const struct LabelLookupResponseMessage *) msg, size);
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
 * @return #GNUNET_YES on success, @a ze should be kept, #GNUNET_NO on success if @a ze should
 *         not be kept any longer, #GNUNET_SYSERR on error (disconnect) and @a ze should be kept
 */
static int
handle_zone_iteration_response (struct GNUNET_NAMESTORE_ZoneIterator *ze,
                                const struct RecordResultMessage *msg,
                                size_t size)
{
  static struct GNUNET_CRYPTO_EcdsaPrivateKey priv_dummy;
  size_t msg_len;
  size_t exp_msg_len;
  size_t name_len;
  size_t rd_len;
  unsigned rd_count;
  const char *name_tmp;
  const char *rd_ser_tmp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received `%s'\n",
       "ZONE_ITERATION_RESPONSE");
  msg_len = ntohs (msg->gns_header.header.size);
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  exp_msg_len = sizeof (struct RecordResultMessage) + name_len + rd_len;
  if (msg_len != exp_msg_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ( (0 == name_len) &&
       (0 == (memcmp (&msg->private_key,
		      &priv_dummy,
		      sizeof (priv_dummy)))) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Zone iteration completed!\n");
    if (NULL != ze->proc)
      ze->proc (ze->proc_cls, NULL, NULL, 0, NULL);
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
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    if (GNUNET_OK != GNUNET_GNSRECORD_records_deserialize (rd_len,
							   rd_ser_tmp,
							   rd_count,
							   rd))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (NULL != ze->proc)
      ze->proc (ze->proc_cls,
		&msg->private_key,
		name_tmp,
		rd_count, rd);
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
 * @return #GNUNET_YES on success, @a ze should be kept, #GNUNET_NO on success if @a ze should
 *         not be kept any longer, #GNUNET_SYSERR on error (disconnect) and @a ze should be kept
 */
static int
manage_zone_operations (struct GNUNET_NAMESTORE_ZoneIterator *ze,
                        const struct GNUNET_MessageHeader *msg,
                        int type, size_t size)
{
  /* handle different message type */
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT:
    if (size < sizeof (struct RecordResultMessage))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return handle_zone_iteration_response (ze,
					   (const struct RecordResultMessage *) msg,
					   size);
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the `struct GNUNET_NAMESTORE_SchedulingHandle`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_namestore_message (void *cls,
			   const struct GNUNET_MessageHeader *msg)
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
    GNUNET_CLIENT_receive (h->client,
			   &process_namestore_message, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  gm = (const struct GNUNET_NAMESTORE_Header *) msg;
  r_id = ntohl (gm->r_id);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message type %u size %u op %u\n",
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
    if (GNUNET_SYSERR == ret)
    {
      /* protocol error, need to reconnect */
      h->reconnect = GNUNET_YES;
    }
    else
    {
      /* client was notified about success or failure, clean up 'qe' */
      GNUNET_CONTAINER_DLL_remove (h->op_head,
				   h->op_tail,
				   qe);
      GNUNET_free (qe);
    }
  }
  /* Is it a zone iteration operation? */
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
 * @param cls the `struct GNUNET_NAMESTORE_Handle`
 * @param size number of bytes we can transmit
 * @param buf where to copy the messages
 * @return number of bytes copied into @a buf
 */
static size_t
transmit_message_to_namestore (void *cls,
			       size_t size,
			       void *buf)
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
  while ( (NULL != (p = h->pending_head)) &&
	  (p->size <= size) )
  {
    memcpy (&cbuf[ret], &p[1], p->size);
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (h->pending_head,
				 h->pending_tail,
				 p);
    if (GNUNET_NO == h->is_receiving)
    {
      h->is_receiving = GNUNET_YES;
      GNUNET_CLIENT_receive (h->client,
			     &process_namestore_message, h,
                             GNUNET_TIME_UNIT_FOREVER_REL);
    }
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
  GNUNET_break (NULL != h->th);
}


/**
 * Reconnect to namestore service.
 *
 * @param h the handle to the NAMESTORE service
 */
static void
reconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("namestore", h->cfg);
  GNUNET_assert (NULL != h->client);
  do_transmit (h);
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;

  h->reconnect_task = NULL;
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
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  h->reconnect = GNUNET_NO;
  GNUNET_CLIENT_disconnect (h->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Reconnecting to namestore\n");
  h->is_receiving = GNUNET_NO;
  h->client = NULL;
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
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

  h = GNUNET_new (struct GNUNET_NAMESTORE_Handle);
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
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
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
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  GNUNET_free (h);
}


/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param rd_count number of records in the 'rd' array
 * @param rd array of records with data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_store (struct GNUNET_NAMESTORE_Handle *h,
				const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
				const char *label,
				unsigned int rd_count,
				const struct GNUNET_GNSRECORD_Data *rd,
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  char *name_tmp;
  char *rd_ser;
  size_t rd_ser_len;
  size_t msg_size;
  size_t name_len;
  uint32_t rid;
  struct RecordStoreMessage *msg;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != pkey);
  GNUNET_assert (NULL != label);
  name_len = strlen (label) + 1;
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return NULL;
  }
  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  /* setup msg */
  rd_ser_len = GNUNET_GNSRECORD_records_get_size (rd_count, rd);
  msg_size = sizeof (struct RecordStoreMessage) + name_len + rd_ser_len;
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct RecordStoreMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->name_len = htons (name_len);
  msg->rd_count = htons (rd_count);
  msg->rd_len = htons (rd_ser_len);
  msg->reserved = htons (0);
  msg->private_key = *pkey;

  name_tmp = (char *) &msg[1];
  memcpy (name_tmp, label, name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_break (rd_ser_len ==
		GNUNET_GNSRECORD_records_serialize (rd_count, rd,
						    rd_ser_len,
						    rd_ser));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending `%s' message for name `%s' with size %u and %u records\n",
       "NAMESTORE_RECORD_STORE", label, msg_size,
       rd_count);
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
  return qe;
}

/**
 * Set the desired nick name for a zone
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param nick the nick name to set
 * @param cont continuation to call when done
 * @param cont_cls closure for 'cont'
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_set_nick (struct GNUNET_NAMESTORE_Handle *h,
                           const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                           const char *nick,
                           GNUNET_NAMESTORE_ContinuationWithStatus cont,
                           void *cont_cls)
{
  struct GNUNET_GNSRECORD_Data rd;

  memset (&rd, 0, sizeof (rd));
  rd.data = nick;
  rd.data_size = strlen (nick) +1;
  rd.record_type = GNUNET_GNSRECORD_TYPE_NICK;
  rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  rd.flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  return GNUNET_NAMESTORE_records_store(h, pkey, GNUNET_GNS_MASTERZONE_STR, 1, &rd, cont, cont_cls);
}


/**
 * Lookup an item in the namestore.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param rm function to call with the result (with 0 records if we don't have that label)
 * @param rm_cls closure for @a rm
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_lookup (struct GNUNET_NAMESTORE_Handle *h,
                                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                                 const char *label,
                                 GNUNET_NAMESTORE_RecordMonitor rm,
                                 void *rm_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  struct LabelLookupMessage * msg;
  size_t msg_size;
  size_t label_len;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != pkey);
  GNUNET_assert (NULL != label);

  if (1 == (label_len = strlen (label) + 1))
    return NULL;

  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->nsh = h;
  qe->proc = rm;
  qe->proc_cls = rm_cls;
  qe->op_id = get_op_id(h);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  msg_size = sizeof (struct LabelLookupMessage) + label_len;
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct LabelLookupMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (qe->op_id);
  msg->zone = *pkey;
  msg->label_len = htonl(label_len);
  memcpy (&msg[1], label, label_len);

  /* transmit message */
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
  return qe;
}


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the processor.
 *
 * @param h handle to the namestore
 * @param zone public key of the zone to look up in, never NULL
 * @param value_zone public key of the target zone (value), never NULL
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records
 * @param proc_cls closure for @a proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_to_name (struct GNUNET_NAMESTORE_Handle *h,
			       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
			       const struct GNUNET_CRYPTO_EcdsaPublicKey *value_zone,
			       GNUNET_NAMESTORE_RecordMonitor proc, void *proc_cls)
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
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->nsh = h;
  qe->proc = proc;
  qe->proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, qe);

  msg_size = sizeof (struct ZoneToNameMessage);
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct ZoneToNameMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->zone = *zone;
  msg->value_zone = *value_zone;

  /* transmit message */
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
  return qe;
}


/**
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). This MUST lock the struct GNUNET_NAMESTORE_Handle
 * for any other calls than #GNUNET_NAMESTORE_zone_iterator_next and
 * #GNUNET_NAMESTORE_zone_iteration_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_NAMESTORE_zone_iterator_next is invoked.
 *
 * @param h handle to the namestore
 * @param zone zone to access, NULL for all zones
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a name of NULL.
 * @param proc_cls closure for @a proc
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (struct GNUNET_NAMESTORE_Handle *h,
				       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
				       GNUNET_NAMESTORE_RecordMonitor proc,
				       void *proc_cls)
{
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct PendingMessage *pe;
  struct ZoneIterationStartMessage * msg;
  size_t msg_size;
  uint32_t rid;

  GNUNET_assert (NULL != h);
  rid = get_op_id(h);
  it = GNUNET_new (struct GNUNET_NAMESTORE_ZoneIterator);
  it->h = h;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->op_id = rid;
  if (NULL != zone)
    it->zone = *zone;
  GNUNET_CONTAINER_DLL_insert_tail (h->z_head, h->z_tail, it);

  msg_size = sizeof (struct ZoneIterationStartMessage);
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct ZoneIterationStartMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  if (NULL != zone)
    msg->zone = *zone;
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
  return it;
}


/**
 * Calls the record processor specified in #GNUNET_NAMESTORE_zone_iteration_start
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
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct ZoneIterationNextMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (it->op_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending `%s' message\n",
       "ZONE_ITERATION_NEXT");
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
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
  pe = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  msg = (struct ZoneIterationStopMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (it->op_id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending `%s' message\n",
	      "ZONE_ITERATION_STOP");
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit (h);
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
  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, qe);
  GNUNET_free(qe);
}


/* end of namestore_api.c */
