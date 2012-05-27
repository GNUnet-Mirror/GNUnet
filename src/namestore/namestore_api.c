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
 * @file namestore/namestore_api.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
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


#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

/**
 * A QueueEntry.
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

  struct GNUNET_NAMESTORE_Handle *nsh;

  uint32_t op_id;

  GNUNET_NAMESTORE_ContinuationWithStatus cont;
  void *cont_cls;

  GNUNET_NAMESTORE_RecordProcessor proc;
  void *proc_cls;

  char *data; /*stub data pointer*/
};


/**
 * Zone iterator
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

  uint32_t op_id;

  struct GNUNET_NAMESTORE_Handle *h;
  GNUNET_NAMESTORE_RecordProcessor proc;
  void* proc_cls;
  struct GNUNET_CRYPTO_ShortHashCode zone;
  uint32_t no_flags;
  uint32_t flags;
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
   * Reconnect task
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Pending messages to send to the service
   */

  struct PendingMessage * pending_head;
  struct PendingMessage * pending_tail;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;


  /**
   * Pending namestore queue entries
   */
  struct GNUNET_NAMESTORE_QueueEntry * op_head;
  struct GNUNET_NAMESTORE_QueueEntry * op_tail;

  uint32_t op_id;

  /**
   * Pending namestore zone iterator entries
   */
  struct GNUNET_NAMESTORE_ZoneIterator * z_head;
  struct GNUNET_NAMESTORE_ZoneIterator * z_tail;
};

struct GNUNET_NAMESTORE_SimpleRecord
{
  /**
   * DLL
   */
  struct GNUNET_NAMESTORE_SimpleRecord *next;

  /**
   * DLL
   */
  struct GNUNET_NAMESTORE_SimpleRecord *prev;
  
  const char *name;
  const struct GNUNET_CRYPTO_ShortHashCode *zone;
  uint32_t record_type;
  struct GNUNET_TIME_Absolute expiration;
  enum GNUNET_NAMESTORE_RecordFlags flags;
  size_t data_size;
  const void *data;
};



/**
 * Disconnect from service and then reconnect.
 *
 * @param h our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *h);

static void
handle_lookup_name_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
                             struct LookupNameResponseMessage * msg,
                             size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' \n",
              "LOOKUP_NAME_RESPONSE");

  struct GNUNET_NAMESTORE_Handle *h = qe->nsh;

  /* Operation done, remove */
  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);


  char *name;
  char * rd_tmp;

  struct GNUNET_CRYPTO_RsaSignature *signature = NULL;
  struct GNUNET_TIME_Absolute expire;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key_tmp;
  size_t exp_msg_len;
  size_t msg_len = 0;
  size_t name_len = 0;
  size_t rd_len = 0;
  int contains_sig = GNUNET_NO;
  int rd_count = 0;

  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  contains_sig = ntohs (msg->contains_sig);
  expire = GNUNET_TIME_absolute_ntoh(msg->expire);

  exp_msg_len = sizeof (struct LookupNameResponseMessage) +
      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
      name_len + rd_len;

  if (msg_len != exp_msg_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Message size describes with `%u' bytes but calculated size is %u bytes \n",
                msg_len, exp_msg_len);
    GNUNET_break_op (0);
    return;
  }

  name = (char *) &msg[1];
  if (name_len > 0)
  {
    GNUNET_assert ('\0' == name[name_len -1]);
    GNUNET_assert ((name_len - 1) == strlen(name));
  }
  rd_tmp = &name[name_len];

  /* deserialize records */
  struct GNUNET_NAMESTORE_RecordData rd[rd_count];
  if (GNUNET_OK != GNUNET_NAMESTORE_records_deserialize(rd_len, rd_tmp, rd_count, rd))
  {
    GNUNET_break_op (0);
    return;
  }


  /* reset values if values not contained */
  if (contains_sig == GNUNET_NO)
    signature = NULL;
  else
    signature = &msg->signature;
  if (name_len == 0)
    name = NULL;

  if (name != NULL)
      public_key_tmp =  &msg->public_key;
  else
      public_key_tmp = NULL;

  if (qe->proc != NULL)
  {
    qe->proc (qe->proc_cls, public_key_tmp, expire, name, rd_count, (rd_count > 0) ? rd : NULL, signature);
  }
  GNUNET_free (qe);
}


static void
handle_record_put_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
                             struct RecordPutResponseMessage* msg,
                             size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' \n",
              "RECORD_PUT_RESPONSE");

  struct GNUNET_NAMESTORE_Handle *h = qe->nsh;
  /* Operation done, remove */
  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);

  int res = ntohl (msg->op_result);

  if (res == GNUNET_OK)
  {
    if (qe->cont != NULL)
    {
      qe->cont (qe->cont_cls, res, _("Namestore added record successfully"));
    }

  }
  else if (res == GNUNET_SYSERR)
  {
    if (qe->cont != NULL)
    {
      qe->cont (qe->cont_cls, res, _("Namestore failed to add record"));
    }
  }
  else
  {
    GNUNET_break_op (0);
    return;
  }

  GNUNET_free (qe);
}


static void
handle_record_create_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
                             struct RecordCreateResponseMessage* msg,
                             size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' \n",
              "RECORD_CREATE_RESPONSE");

  struct GNUNET_NAMESTORE_Handle *h = qe->nsh;
  /* Operation done, remove */
  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);

  int res = ntohl (msg->op_result);
  if (res == GNUNET_YES)
  {
    if (qe->cont != NULL)
    {
      qe->cont (qe->cont_cls, res, _("Namestore added record successfully"));
    }

  }
  else if (res == GNUNET_NO)
  {
    if (qe->cont != NULL)
    {
      qe->cont (qe->cont_cls, res, _("Namestore record already existed"));
    }
  }
  else
  {
    if (qe->cont != NULL)
    {
      qe->cont (qe->cont_cls, GNUNET_SYSERR, _("Namestore failed to add record\n"));
    }
  }

  GNUNET_free (qe);
}


static void
handle_record_remove_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
                             struct RecordRemoveResponseMessage* msg,
                             size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' \n",
              "RECORD_REMOVE_RESPONSE");

  struct GNUNET_NAMESTORE_Handle *h = qe->nsh;
  /* Operation done, remove */
  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);

  int res = ntohl (msg->op_result);
  /**
   *  result:
   *  0 : successful
   *  1 : No records for entry
   *  2 : Could not find record to remove
   *  3 : Failed to create new signature
   *  4 : Failed to put new set of records in database
   */
  switch (res) {
    case 0:
      if (qe->cont != NULL)
      {
        qe->cont (qe->cont_cls, GNUNET_YES, _("Namestore removed record successfully"));
      }

      break;
    case 1:
      if (qe->cont != NULL)
      {
        qe->cont (qe->cont_cls, GNUNET_NO, _("No records for entry"));
      }

      break;
    case 2:
      if (qe->cont != NULL)
      {
        qe->cont (qe->cont_cls, GNUNET_NO, _("Could not find record to remove"));
      }

      break;
    case 3:
      if (qe->cont != NULL)
      {
        qe->cont (qe->cont_cls, GNUNET_SYSERR, _("Failed to create new signature"));
      }

      break;
    case 4:
      if (qe->cont != NULL)
      {
        qe->cont (qe->cont_cls, GNUNET_SYSERR, _("Failed to put new set of records in database"));
      }
      break;
    default:
        GNUNET_break_op (0);
      break;
  }

  GNUNET_free (qe);
}

static void
handle_zone_to_name_response (struct GNUNET_NAMESTORE_QueueEntry *qe,
                             struct ZoneToNameResponseMessage* msg,
                             size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' \n",
              "ZONE_TO_NAME_RESPONSE");

  struct GNUNET_NAMESTORE_Handle *h = qe->nsh;
  /* Operation done, remove */
  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);

  int res = ntohs (msg->res);

  struct GNUNET_TIME_Absolute expire;
  size_t name_len;
  size_t rd_ser_len;
  unsigned int rd_count;

  char * name_tmp;
  char * rd_tmp;

  if (res == GNUNET_SYSERR)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "An error occured during zone to name operation\n");
    if (qe->proc != NULL)
      qe->proc (qe->proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL, 0, NULL, NULL);
  }
  else if (res == GNUNET_NO)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Namestore has no result for zone to name mapping \n");
      if (qe->proc != NULL)
        qe->proc (qe->proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL, 0, NULL, NULL);
  }
  else if (res == GNUNET_YES)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Namestore has result for zone to name mapping \n");

    name_len = ntohs (msg->name_len);
    rd_count = ntohs (msg->rd_count);
    rd_ser_len = ntohs (msg->rd_len);
    expire = GNUNET_TIME_absolute_ntoh(msg->expire);

    name_tmp = (char *) &msg[1];
    if (name_len > 0)
    {
      GNUNET_assert ('\0' == name_tmp[name_len -1]);
      GNUNET_assert (name_len -1 == strlen(name_tmp));
    }
    rd_tmp = &name_tmp[name_len];

    struct GNUNET_NAMESTORE_RecordData rd[rd_count];
    if (GNUNET_OK != GNUNET_NAMESTORE_records_deserialize(rd_ser_len, rd_tmp, rd_count, rd))
    {
      GNUNET_break_op (0);
      return;
    }

    if (qe->proc != NULL)
      qe->proc (qe->proc_cls, &msg->zone_key, expire, name_tmp, rd_count, rd, &msg->signature);
  }
  else
    GNUNET_break_op (0);

  GNUNET_free (qe);
}


static void
manage_record_operations (struct GNUNET_NAMESTORE_QueueEntry *qe,
                          const struct GNUNET_MessageHeader *msg,
                          int type, size_t size)
{

  /* handle different message type */
  switch (type) {
    case GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE:
        if (size < sizeof (struct LookupNameResponseMessage))
        {
          GNUNET_break_op (0);
          break;
        }
        handle_lookup_name_response (qe, (struct LookupNameResponseMessage *) msg, size);
      break;
    case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE:
        if (size != sizeof (struct RecordPutResponseMessage))
        {
          GNUNET_break_op (0);
          break;
        }
        handle_record_put_response (qe, (struct RecordPutResponseMessage *) msg, size);
      break;
    case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE:
        if (size != sizeof (struct RecordCreateResponseMessage))
        {
          GNUNET_break_op (0);
          break;
        }
        handle_record_create_response (qe, (struct RecordCreateResponseMessage *) msg, size);
      break;
    case GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE_RESPONSE:
        if (size != sizeof (struct RecordRemoveResponseMessage))
        {
          GNUNET_break_op (0);
          break;
        }
        handle_record_remove_response (qe, (struct RecordRemoveResponseMessage *) msg, size);
      break;
    case GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE:
        if (size < sizeof (struct ZoneToNameResponseMessage))
        {
          GNUNET_break_op (0);
          break;
        }
        handle_zone_to_name_response (qe, (struct ZoneToNameResponseMessage *) msg, size);
      break;
    default:
      GNUNET_break_op (0);
      break;
  }
}

static void
handle_zone_iteration_response (struct GNUNET_NAMESTORE_ZoneIterator *ze,
                                struct ZoneIterationResponseMessage *msg,
                                size_t size)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received `%s' \n",
              "ZONE_ITERATION_RESPONSE");

  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pubdummy;
  size_t msg_len = 0;
  size_t exp_msg_len = 0;
  size_t name_len = 0;
  size_t rd_len = 0;
  unsigned rd_count = 0;

  char *name_tmp;
  char *rd_ser_tmp;
  struct GNUNET_TIME_Absolute expire;

  msg_len = ntohs (msg->gns_header.header.size);
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  expire = GNUNET_TIME_absolute_ntoh (msg->expire);

  exp_msg_len = sizeof (struct ZoneIterationResponseMessage) + name_len + rd_len;
  if (msg_len != exp_msg_len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Message size describes with `%u' bytes but calculated size is %u bytes \n",
                msg_len, exp_msg_len);
    GNUNET_break_op (0);
    return;
  }
  if (0 != ntohs (msg->reserved))
  {
    GNUNET_break_op (0);
    return;
  }

  memset (&pubdummy, '\0', sizeof (pubdummy));
  if ((0 == name_len) && (0 == (memcmp (&msg->public_key, &pubdummy, sizeof (pubdummy)))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Zone iteration is completed!\n");

    GNUNET_CONTAINER_DLL_remove(ze->h->z_head, ze->h->z_tail, ze);

    if (ze->proc != NULL)
      ze->proc(ze->proc_cls, NULL, GNUNET_TIME_UNIT_ZERO_ABS, NULL , 0, NULL, NULL);

    GNUNET_free (ze);
    return;
  }

  name_tmp = (char *) &msg[1];
  if ((name_tmp[name_len -1] != '\0') || (name_len > 256))
  {
    GNUNET_break_op (0);
    return;
  }
  rd_ser_tmp = (char *) &name_tmp[name_len];
  struct GNUNET_NAMESTORE_RecordData rd[rd_count];
  if (GNUNET_OK != GNUNET_NAMESTORE_records_deserialize (rd_len, rd_ser_tmp, rd_count, rd))
  {
    GNUNET_break_op (0);
    return;
  }

  if (ze->proc != NULL)
    ze->proc(ze->proc_cls, &msg->public_key, expire, name_tmp, rd_count, rd, &msg->signature);
}


static void
manage_zone_operations (struct GNUNET_NAMESTORE_ZoneIterator *ze,
                        const struct GNUNET_MessageHeader *msg,
                        int type, size_t size)
{

  /* handle different message type */
  switch (type) {
    case GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE:
        if (size < sizeof (struct ZoneIterationResponseMessage))
        {
          GNUNET_break_op (0);
          break;
        }
        handle_zone_iteration_response (ze, (struct ZoneIterationResponseMessage *) msg, size);
      break;
    default:
      GNUNET_break_op (0);
      break;
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
  struct GNUNET_NAMESTORE_Header * gm;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_NAMESTORE_ZoneIterator *ze;
  uint16_t size;
  uint16_t type;
  uint32_t r_id = UINT32_MAX;

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

  gm = (struct GNUNET_NAMESTORE_Header *) msg;
  r_id = ntohl (gm->r_id);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received message type %i size %i op %u\n", type, size, r_id);

  /* Find matching operation */
  if (r_id > h->op_id)
  {
    /* No matching pending operation found */
    GNUNET_break_op (0);
    GNUNET_CLIENT_receive (h->client, &process_namestore_message, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }

  /* Is it a record related operation ? */
  for (qe = h->op_head; qe != NULL; qe = qe->next)
  {
    if (qe->op_id == r_id)
      break;
  }
  if (qe != NULL)
  {
    manage_record_operations (qe, msg, type, size);
  }

  /* Is it a zone iteration operation ? */
  for (ze = h->z_head; ze != NULL; ze = ze->next)
  {
    if (ze->op_id == r_id)
      break;
  }
  if (ze != NULL)
  {
    manage_zone_operations (ze, msg, type, size);
  }

  GNUNET_CLIENT_receive (h->client, &process_namestore_message, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);

  if (GNUNET_YES == h->reconnect)
    force_reconnect (h);

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
  if ((size == 0) || (buf == NULL))
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
    return;
  if (NULL == (p = h->pending_head))
    return;
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
 * @param h the handle to the namestore service
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

static uint32_t
get_op_id (struct GNUNET_NAMESTORE_Handle *h)
{
  uint32_t op_id = h->op_id;
  h->op_id ++;
  return op_id;
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
  h->op_id = 0;
  return h;
}

static void
clean_up_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingMessage *p;
  struct GNUNET_NAMESTORE_QueueEntry *q;
  struct GNUNET_NAMESTORE_ZoneIterator *z;
  struct GNUNET_NAMESTORE_Handle *h = cls;
  GNUNET_assert (h != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  while (NULL != (p = h->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->pending_head, h->pending_tail, p);
    GNUNET_free (p);
  }

  while (NULL != (q = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, q);
    GNUNET_free (q);
  }

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
  GNUNET_free(h);
  h = NULL;
}


/**
 * Disconnect from the namestore service (and free associated
 * resources).
 *
 * @param h handle to the namestore
 * @param drop set to GNUNET_YES to delete all data in namestore (!)
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h, int drop)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from namestore service\n");
  GNUNET_SCHEDULER_add_now (&clean_up_task, h);
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
			     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			     const char *name,
			     struct GNUNET_TIME_Absolute freshness,
			     unsigned int rd_count,
			     const struct GNUNET_NAMESTORE_RecordData *rd,
			     const struct GNUNET_CRYPTO_RsaSignature *signature,
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;

  /* pointer to elements */
  char * rd_tmp;
  char * name_tmp;

  size_t msg_size = 0;
  size_t name_len = 0;
  size_t rd_ser_len = 0;
  uint32_t rid = 0;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != zone_key);
  GNUNET_assert (NULL != name);
  GNUNET_assert (NULL != rd);
  GNUNET_assert (NULL != signature);

  name_len = strlen(name) + 1;
  if (name_len > 256)
  {
    GNUNET_break (0);
    return NULL;
  }

  rid = get_op_id(h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail(h->op_head, h->op_tail, qe);

  /* set msg_size*/
  rd_ser_len = GNUNET_NAMESTORE_records_get_size(rd_count, rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(rd_count, rd, rd_ser_len, rd_ser);

  struct RecordPutMessage * msg;
  msg_size = sizeof (struct RecordPutMessage) + name_len  + rd_ser_len;

  /* create msg here */
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct RecordPutMessage *) &pe[1];
  name_tmp = (char *) &msg[1];
  rd_tmp = &name_tmp[name_len];

  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->signature = *signature;
  msg->name_len = htons (name_len);
  msg->expire = GNUNET_TIME_absolute_hton (freshness);
  msg->rd_len = htons (rd_ser_len);
  msg->rd_count = htons (rd_count);

  msg->public_key = *zone_key;
  memcpy (name_tmp, name, name_len);
  memcpy (rd_tmp, rd_ser, rd_ser_len);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for name `%s' with size %u\n", "NAMESTORE_RECORD_PUT", name, msg_size);

  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);

  return qe;
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param public_key public key of the zone
 * @param expire block expiration
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @return GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
                                   const struct GNUNET_TIME_Absolute expire,
				   const char *name,
				   unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd,
				   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  int res = GNUNET_SYSERR;
  size_t rd_ser_len = 0;
  size_t name_len = 0;
  char * name_tmp;
  char * rd_tmp;
  struct GNUNET_CRYPTO_RsaSignaturePurpose *sig_purpose;
  struct GNUNET_TIME_AbsoluteNBO *expire_tmp;
  struct GNUNET_TIME_AbsoluteNBO expire_nbo = GNUNET_TIME_absolute_hton(expire);

  GNUNET_assert (public_key != NULL);
  GNUNET_assert (name != NULL);
  GNUNET_assert (rd != NULL);
  GNUNET_assert (signature != NULL);


  rd_ser_len = GNUNET_NAMESTORE_records_get_size(rd_count, rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(rd_count, rd, rd_ser_len, rd_ser);

  name_len = strlen (name) + 1;
  if (name_len > 256)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  sig_purpose = GNUNET_malloc(sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) + sizeof (struct GNUNET_TIME_AbsoluteNBO) + rd_ser_len + name_len);
  sig_purpose->size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose)+ rd_ser_len + name_len);
  sig_purpose->purpose = htonl (GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN);
  expire_tmp = (struct GNUNET_TIME_AbsoluteNBO *) &sig_purpose[1];
  name_tmp = (char *) &expire_tmp[1];
  rd_tmp = &name_tmp[name_len];
  memcpy (expire_tmp, &expire_nbo, sizeof (struct GNUNET_TIME_AbsoluteNBO));
  memcpy (name_tmp, name, name_len);
  memcpy (rd_tmp, rd_ser, rd_ser_len);

  res = GNUNET_CRYPTO_rsa_verify(GNUNET_SIGNATURE_PURPOSE_GNS_RECORD_SIGN, sig_purpose, signature, public_key);

  GNUNET_free (sig_purpose);

  return res;
}

/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  This API is used by the authority of a zone.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd record data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_create (struct GNUNET_NAMESTORE_Handle *h,
				const struct GNUNET_CRYPTO_RsaPrivateKey *pkey,
				const char *name,
				const struct GNUNET_NAMESTORE_RecordData *rd,
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  char * name_tmp;
  char * pkey_tmp;
  char * rd_tmp;
  size_t rd_ser_len = 0;
  size_t msg_size = 0;
  size_t name_len = 0;
  size_t key_len = 0;
  uint32_t rid = 0;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != pkey);
  GNUNET_assert (NULL != name);
  GNUNET_assert (NULL != rd);

  name_len = strlen(name) + 1;
  if (name_len > 256)
  {
    GNUNET_break (0);
    return NULL;
  }

  rid = get_op_id(h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail(h->op_head, h->op_tail, qe);

  /* set msg_size*/
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded * pkey_enc = GNUNET_CRYPTO_rsa_encode_key (pkey);
  GNUNET_assert (pkey_enc != NULL);
  key_len = ntohs (pkey_enc->len);

  rd_ser_len = GNUNET_NAMESTORE_records_get_size(1, rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize(1, rd, rd_ser_len, rd_ser);

  struct RecordCreateMessage * msg;
  msg_size = sizeof (struct RecordCreateMessage) + key_len + name_len + rd_ser_len;

  /* create msg here */
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct RecordCreateMessage *) &pe[1];

  pkey_tmp = (char *) &msg[1];
  name_tmp = &pkey_tmp[key_len];
  rd_tmp = &name_tmp[name_len];

  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->name_len = htons (name_len);
  msg->rd_count = htons (1);
  msg->rd_len = htons (rd_ser_len);
  msg->pkey_len = htons (key_len);
  msg->expire = GNUNET_TIME_absolute_hton(GNUNET_TIME_UNIT_FOREVER_ABS);
  memcpy (pkey_tmp, pkey_enc, key_len);
  memcpy (name_tmp, name, name_len);
  memcpy (rd_tmp, rd_ser, rd_ser_len);
  GNUNET_free (pkey_enc);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for name `%s' with size %u\n", "NAMESTORE_RECORD_CREATE", name, msg_size);

  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
  return qe;
}


/**
 * Explicitly remove some content from the database.  The
 * "cont"inuation will be called with status "GNUNET_OK" if content
 * was removed, "GNUNET_NO" if no matching entry was found and
 * "GNUNET_SYSERR" on all other types of errors.
 * This API is used by the authority of a zone.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd record data, remove specific record,  NULL to remove the name and all records
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_remove (struct GNUNET_NAMESTORE_Handle *h,
				const struct GNUNET_CRYPTO_RsaPrivateKey *pkey,
				const char *name,
				const struct GNUNET_NAMESTORE_RecordData *rd,
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  char *pkey_tmp;
  char *rd_tmp;
  char *name_tmp;
  size_t rd_ser_len = 0;
  size_t msg_size = 0;
  size_t name_len = 0;
  size_t key_len = 0;
  uint32_t rid = 0;
  uint16_t rd_count = 1;

  GNUNET_assert (NULL != h);

  rid = get_op_id(h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail(h->op_head, h->op_tail, qe);

  /* set msg_size*/
  struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded * pkey_enc = GNUNET_CRYPTO_rsa_encode_key (pkey);
  GNUNET_assert (pkey_enc != NULL);
  key_len = ntohs (pkey_enc->len);

  if (NULL == rd)
    rd_count = 0;
  else
    rd_count = 1;
  rd_ser_len = GNUNET_NAMESTORE_records_get_size (rd_count, rd);
  char rd_ser[rd_ser_len];
  GNUNET_NAMESTORE_records_serialize (rd_count, rd, rd_ser_len, rd_ser);

  name_len = strlen (name) + 1;

  struct RecordRemoveMessage * msg;
  msg_size = sizeof (struct RecordRemoveMessage) + key_len + name_len + rd_ser_len;

  /* create msg here */
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct RecordRemoveMessage *) &pe[1];

  pkey_tmp = (char *) &msg[1];
  name_tmp = &pkey_tmp[key_len];
  rd_tmp = &name_tmp[name_len];

  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->name_len = htons (name_len);
  msg->rd_len = htons (rd_ser_len);
  msg->rd_count = htons (rd_count);
  msg->pkey_len = htons (key_len);
  memcpy (pkey_tmp, pkey_enc, key_len);
  memcpy (name_tmp, name, name_len);
  memcpy (rd_tmp, rd_ser, rd_ser_len);

  GNUNET_free (pkey_enc);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for name `%s' with size %u\n", "NAMESTORE_RECORD_REMOVE", name, msg_size);

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
  size_t msg_size = 0;
  size_t name_len = 0;
  uint32_t rid = 0;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != zone);
  GNUNET_assert (NULL != name);

  name_len = strlen (name) + 1;
  if ((name_len == 0) || (name_len > 256))
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
  GNUNET_CONTAINER_DLL_insert_tail(h->op_head, h->op_tail, qe);

  /* set msg_size*/
  msg_size = sizeof (struct LookupNameMessage) + name_len;
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);

  /* create msg here */
  struct LookupNameMessage * msg;
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for name `%s'\n", "NAMESTORE_LOOKUP_NAME", name);

  /* transmit message */
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
  size_t msg_size = 0;
  uint32_t rid = 0;

  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != zone);
  GNUNET_assert (NULL != value_zone);

  rid = get_op_id(h);
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  qe->nsh = h;
  qe->proc = proc;
  qe->proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail(h->op_head, h->op_tail, qe);

  /* set msg_size*/
  msg_size = sizeof (struct ZoneToNameMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);

  /* create msg here */
  struct ZoneToNameMessage * msg;
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneToNameMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  msg->zone = *zone;
  msg->value_zone = *value_zone;

  char * z_tmp = GNUNET_strdup (GNUNET_short_h2s (zone));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for zone `%s' in zone `%s'\n",
      "NAMESTORE_ZONE_TO_NAME",
      z_tmp,
      GNUNET_short_h2s (value_zone));
  GNUNET_free (z_tmp);

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
  size_t msg_size = 0;
  uint32_t rid = 0;

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
  GNUNET_CONTAINER_DLL_insert_tail(h->z_head, h->z_tail, it);

  /* set msg_size*/
  msg_size = sizeof (struct ZoneIterationStartMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);

  /* create msg here */
  struct ZoneIterationStartMessage * msg;
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneIterationStartMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (rid);
  if (NULL != zone)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for zone `%s'\n", "ZONE_ITERATION_START", GNUNET_short_h2s(zone));
    msg->zone = *zone;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for all zones\n", "ZONE_ITERATION_START");
    memset (&msg->zone, '\0', sizeof (msg->zone));
  }
  msg->must_have_flags = ntohs (must_have_flags);
  msg->must_not_have_flags = ntohs (must_not_have_flags);



  /* transmit message */
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
  struct PendingMessage *pe;
  size_t msg_size = 0;

  GNUNET_assert (NULL != it);
  h = it->h;
  struct GNUNET_NAMESTORE_ZoneIterator *tmp = it->h->z_head;

  while (tmp != NULL)
  {
    if (tmp == it)
      break;
    tmp = tmp->next;
  }
  GNUNET_assert (NULL != tmp);

  /* set msg_size*/
  msg_size = sizeof (struct ZoneIterationNextMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);

  /* create msg here */
  struct ZoneIterationNextMessage * msg;
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneIterationNextMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (it->op_id);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message\n", "ZONE_ITERATION_NEXT");

  /* transmit message */
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
  GNUNET_assert (NULL != it);
  struct PendingMessage *pe;
  size_t msg_size = 0;
  struct GNUNET_NAMESTORE_Handle *h = it->h;
  struct GNUNET_NAMESTORE_ZoneIterator *tmp = it->h->z_head;

  while (tmp != NULL)
  {
    if (tmp == it)
      break;
    tmp = tmp->next;
  }
  GNUNET_assert (NULL != tmp);

  /* set msg_size*/
  msg_size = sizeof (struct ZoneIterationStopMessage);
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);

  /* create msg here */
  struct ZoneIterationStopMessage * msg;
  pe->size = msg_size;
  pe->is_init = GNUNET_NO;
  msg = (struct ZoneIterationStopMessage *) &pe[1];
  msg->gns_header.header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP);
  msg->gns_header.header.size = htons (msg_size);
  msg->gns_header.r_id = htonl (it->op_id);

  if (GNUNET_YES == it->has_zone)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for zone `%s'\n", "ZONE_ITERATION_STOP", GNUNET_short_h2s(&it->zone));
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message for all zones\n", "ZONE_ITERATION_STOP");

  /* transmit message */
  GNUNET_CONTAINER_DLL_insert_tail (h->pending_head, h->pending_tail, pe);
  do_transmit(h);
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

  GNUNET_assert (qe != NULL);

  GNUNET_CONTAINER_DLL_remove(h->op_head, h->op_tail, qe);
  GNUNET_free(qe);

}

/* end of namestore_api.c */
