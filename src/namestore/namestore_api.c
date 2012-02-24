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
 * @file gns/namestore_api.c
 * @brief API to access the NAMESTORE service
 * @author Martin Schanzenbach
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_namestore_service.h"
#include "namestore.h"
#define DEBUG_GNS_API GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

/**
 * A QueueEntry.
 */
struct GNUNET_NAMESTORE_QueueEntry
{
  struct GNUNET_NAMESTORE_QueueEntry *next;
  struct GNUNET_NAMESTORE_QueueEntry *prev;

  uint64_t op_id;

  char *data; /*stub data pointer*/
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
   * Pending namestore operations
   */

  struct GNUNET_NAMESTORE_QueueEntry * op_head;
  struct GNUNET_NAMESTORE_QueueEntry * op_tail;

  uint64_t op_id;
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
  const GNUNET_HashCode *zone;
  uint32_t record_type;
  struct GNUNET_TIME_Absolute expiration;
  enum GNUNET_NAMESTORE_RecordFlags flags;
  size_t data_size;
  const void *data;
};

/**
 * Disconnect from service and then reconnect.
 *
 * @param nsh our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *nsh);


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
  struct GNUNET_NAMESTORE_Handle *nsh = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  uint16_t size;
  uint16_t type;
  uint64_t op_id = UINT64_MAX;

  if (NULL == msg)
  {
    force_reconnect (nsh);
    return;
  }

  size = ntohs (msg->size);
  type = ntohs (msg->type);

  /* find matching operation */
  if (op_id > nsh->op_id)
  {
    GNUNET_break_op (0);
    GNUNET_CLIENT_receive (nsh->client, &process_namestore_message, nsh,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  for (qe = nsh->op_head; qe != NULL; qe = qe->next)
  {
    if (qe->op_id == op_id)
      break;
  }
  if (qe == NULL)
  {
    GNUNET_break_op (0);
    GNUNET_CLIENT_receive (nsh->client, &process_namestore_message, nsh,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }

  switch (type) {
    case GNUNET_MESSAGE_TYPE_TEST:
      /* handle message here */
      break;
    default:
      break;
  }
  size++; // FIXME: just working around compiler warning here...
  GNUNET_CLIENT_receive (nsh->client, &process_namestore_message, nsh,
                         GNUNET_TIME_UNIT_FOREVER_REL);

  if (GNUNET_YES == nsh->reconnect)
    force_reconnect (nsh);
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param nsh handle to use
 */
static void
do_transmit (struct GNUNET_NAMESTORE_Handle *nsh);


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
  struct GNUNET_NAMESTORE_Handle *nsh = cls;
  struct PendingMessage *p;
  size_t ret;
  char *cbuf;

  nsh->th = NULL;
  if ((size == 0) || (buf == NULL))
  {
    force_reconnect (nsh);
    return 0;
  }
  ret = 0;
  cbuf = buf;
  while ((NULL != (p = nsh->pending_head)) && (p->size <= size))
  {
    memcpy (&cbuf[ret], &p[1], p->size);
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (nsh->pending_head, nsh->pending_tail, p);
    if (GNUNET_YES == p->is_init)
      GNUNET_CLIENT_receive (nsh->client, &process_namestore_message, nsh,
                             GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (p);
  }
  do_transmit (nsh);
  return ret;
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param nsh handle to use
 */
static void
do_transmit (struct GNUNET_NAMESTORE_Handle *nsh)
{
  struct PendingMessage *p;

  if (NULL != nsh->th)
    return;
  if (NULL == (p = nsh->pending_head))
    return;
  if (NULL == nsh->client)
    return;                     /* currently reconnecting */

  nsh->th = GNUNET_CLIENT_notify_transmit_ready (nsh->client, p->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_message_to_namestore,
                                           nsh);
}


/**
 * Try again to connect to namestore service.
 *
 * @param cls the handle to the namestore service
 * @param tc scheduler context
 */
static void
reconnect (struct GNUNET_NAMESTORE_Handle *nsh)
{
  struct PendingMessage *p;
  struct StartMessage *init;

  GNUNET_assert (NULL == nsh->client);
  nsh->client = GNUNET_CLIENT_connect ("namestore", nsh->cfg);
  GNUNET_assert (NULL != nsh->client);

  if ((NULL == (p = nsh->pending_head)) || (GNUNET_YES != p->is_init))
  {
    p = GNUNET_malloc (sizeof (struct PendingMessage) +
                       sizeof (struct StartMessage));
    p->size = sizeof (struct StartMessage);
    p->is_init = GNUNET_YES;
    init = (struct StartMessage *) &p[1];
    init->header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_START);
    init->header.size = htons (sizeof (struct StartMessage));
    GNUNET_CONTAINER_DLL_insert (nsh->pending_head, nsh->pending_tail, p);
  }
  do_transmit (nsh);
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
  struct GNUNET_NAMESTORE_Handle *nsh = cls;

  nsh->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (nsh);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param nsh our handle
 */
static void
force_reconnect (struct GNUNET_NAMESTORE_Handle *nsh)
{
  nsh->reconnect = GNUNET_NO;
  GNUNET_CLIENT_disconnect (nsh->client, GNUNET_NO);
  nsh->client = NULL;
  nsh->reconnect_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &reconnect_task,
                                    nsh);
}

static void
enqeue_namestore_operation (struct GNUNET_NAMESTORE_Handle *nsh, struct GNUNET_NAMESTORE_QueueEntry *qe)
{
  qe->op_id = nsh->op_id;
  nsh->op_id ++;
  GNUNET_CONTAINER_DLL_insert(nsh->op_head, nsh->op_tail, qe);
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
  struct GNUNET_NAMESTORE_Handle *nsh;

  nsh = GNUNET_malloc (sizeof (struct GNUNET_NAMESTORE_Handle));
  nsh->cfg = cfg;
  nsh->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect_task, nsh);
  nsh->op_id = 0;
  return nsh;
}

/**
 * Shutdown connection with the NAMESTORE service.
 *
 * @param handle handle of the NAMESTORE connection to stop
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *nsh, int drop)
{
  struct PendingMessage *p;
  struct GNUNET_NAMESTORE_QueueEntry *q;

  while (NULL != (p = nsh->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (nsh->pending_head, nsh->pending_tail, p);
    GNUNET_free (p);
  }

  while (NULL != (q = nsh->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (nsh->op_head, nsh->op_tail, q);
    GNUNET_free (q);
  }

  if (NULL != nsh->client)
  {
    GNUNET_CLIENT_disconnect (nsh->client, GNUNET_NO);
    nsh->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != nsh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (nsh->reconnect_task);
    nsh->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free(nsh);
  nsh = NULL;
}


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  This API is used when we cache signatures from other
 * authorities.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param expire when does the corresponding block in the DHT expire (until
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
			     const GNUNET_HashCode *zone,
			     const char *name,
			     struct GNUNET_TIME_Absolute expire,
			     unsigned int rd_count,
			     const struct GNUNET_NAMESTORE_RecordData *rd,
			     const struct GNUNET_CRYPTO_RsaSignature *signature,
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct PendingMessage *pe;
  size_t msg_size = 0;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  enqeue_namestore_operation(h, qe);

  /* set msg_size*/
  pe = GNUNET_malloc(sizeof (struct PendingMessage) + msg_size);

  /* create msg here */

  GNUNET_CONTAINER_DLL_insert (h->pending_head, h->pending_tail, pe);
  do_transmit(h);

#if 0
  struct GNUNET_NAMESTORE_SimpleRecord *sr;
  sr = GNUNET_malloc(sizeof(struct GNUNET_NAMESTORE_SimpleRecord));
  sr->name = name;
  sr->record_type = record_type;
  sr->expiration = expiration;
  sr->flags = flags;
  sr->data_size = data_size;
  sr->data = data;
  GNUNET_CONTAINER_DLL_insert(h->records_head, h->records_tail, sr);
#endif
  return qe;
}


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param public_key public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @return GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
				   const char *name,
				   unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd,
				   const struct GNUNET_CRYPTO_RsaSignature *signature)
{
  return GNUNET_SYSERR;
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
  return NULL;
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
 * @param rd record data
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
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
#if 0
  struct GNUNET_NAMESTORE_SimpleRecord *iter;
  for (iter=h->records_head; iter != NULL; iter=iter->next)
  {
    if (strcmp ( iter->name, name ) &&
        iter->record_type == record_type &&
        GNUNET_CRYPTO_hash_cmp (iter->zone, zone))
      break;
  }
  if (iter)
    GNUNET_CONTAINER_DLL_remove(h->records_head,
                                h->records_tail,
                                iter);
#endif
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
			      const GNUNET_HashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));

#if 0
  struct GNUNET_NAMESTORE_SimpleRecord *iter;
  for (iter=h->records_head; iter != NULL; iter=iter->next)
  {
    proc(proc_cls, iter->zone, iter->name, iter->record_type,
       iter->expiration,
       iter->flags,
       NULL /*sig loc*/,
       iter->data_size /*size*/,
       iter->data /* data */);
  }
  proc(proc_cls, zone, name, record_type,
       GNUNET_TIME_absolute_get_forever(), 0, NULL, 0, NULL); /*TERMINATE*/
#endif

  GNUNET_assert (NULL != h);

  struct PendingMessage * p;
  struct LookupNameMessage * msg;
  size_t msg_len = sizeof (struct LookupNameMessage);

  p = GNUNET_malloc (sizeof (struct PendingMessage) + msg_len);
  p->size = msg_len;
  p->is_init = GNUNET_NO;
  msg = (struct LookupNameMessage *) &p[1];
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME);
  msg->header.size = htons (msg_len);
  GNUNET_CONTAINER_DLL_insert (h->pending_head, h->pending_tail, p);
  do_transmit (h);

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
				       const GNUNET_HashCode *zone,
				       enum GNUNET_NAMESTORE_RecordFlags must_have_flags,
				       enum GNUNET_NAMESTORE_RecordFlags must_not_have_flags,
				       GNUNET_NAMESTORE_RecordProcessor proc,
				       void *proc_cls)
{
  return NULL;
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
}


/**
 * Stops iteration and releases the namestore handle for further calls.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it)
{
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
  if (qe)
    GNUNET_free(qe);
}

/* end of namestore_api.c */
