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

  struct PendingMessage * pending_head;
  struct PendingMessage * pending_tail;

  /**
   * Should we reconnect to service due to some serious error?
   */
  int reconnect;
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
      GNUNET_CLIENT_receive (nsh->client,/* &process_namestore_message*/ NULL, nsh,
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
  nsh->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &reconnect_task,
                                    nsh);
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
  return nsh;
}


/**
 * Shutdown connection with the NAMESTORE service.
 *
 * @param handle handle of the NAMESTORE connection to stop
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *handle, int drop)
{
  GNUNET_free(handle);
}

/**
 * Sign a record.  This function is used by the authority of the zone
 * to add a record.
 *
 * @param h handle to the namestore
 * @param zone_privkey private key of the zone
 * @param record_hash hash of the record to be signed
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_extend (struct GNUNET_NAMESTORE_Handle *h,
             const struct GNUNET_CRYPTO_RsaPrivateKey *zone_privkey,
             const GNUNET_HashCode *record_hash,
             GNUNET_NAMESTORE_ContinuationWithSignature cont,
             void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Rebalance the signature tree of our zone.  This function should
 * be called "rarely" to rebalance the tree.
 *
 * @param h handle to the namestore
 * @param zone_privkey private key for the zone to rebalance
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_rebalance (struct GNUNET_NAMESTORE_Handle *h,
          const struct GNUNET_CRYPTO_RsaPrivateKey *zone_privkey,
          GNUNET_NAMESTORE_ContinuationWithStatus cont,
          void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Provide the root of a signature tree.  This function is 
 * used by non-authorities as the first operation when 
 * adding a foreign zone.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param signature signature of the top-level entry of the zone
 * @param revision revision number of the zone
 * @param top_hash top-level hash of the zone
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_start (struct GNUNET_NAMESTORE_Handle *h,
                              const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                              const struct GNUNET_CRYPTO_RsaSignature *signature,
                              uint32_t revision,
                              const GNUNET_HashCode *top_hash,
                              GNUNET_NAMESTORE_ContinuationWithSignature cont,
                              void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Store part of a signature B-tree in the namestore.  This function
 * is used by non-authorities to cache parts of a zone's signature tree.
 * Note that the tree must be build top-down.  This function must check
 * that the nodes being added are valid, and if not refuse the operation.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth - 1), NULL for root
 * @param top_sig signature at the top, NULL if 'loc.depth > 0'
 * @param num_entries number of entries at this node in the B-tree
 * @param entries the 'num_entries' entries to store (hashes over the
 *                records)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_put (struct GNUNET_NAMESTORE_Handle *h,
                            const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
                            const struct GNUNET_NAMESTORE_SignatureLocation *loc,
                            const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
                            const struct GNUNET_CRYPTO_RsaSignature *sig,
                            unsigned int num_entries,
                            const GNUNET_HashCode *entries,
                            GNUNET_NAMESTORE_ContinuationWithStatus cont,
                            void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}

/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  The operation must fail if there is no matching
 * entry in the signature tree.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param sig_loc where is the information about the signature for this record stored?
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put (struct GNUNET_NAMESTORE_Handle *h,
                             const GNUNET_HashCode *zone,
                             const char *name,
                             uint32_t record_type,
                             struct GNUNET_TIME_Absolute expiration,
                             enum GNUNET_NAMESTORE_RecordFlags flags,
                             const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
                             size_t data_size,
                             const void *data,
                             GNUNET_NAMESTORE_ContinuationWithStatus cont,
                             void *cont_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
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
 * Explicitly remove some content from the database.  The
 * "cont"inuation will be called with status "GNUNET_OK" if content
 * was removed, "GNUNET_NO" if no matching entry was found and
 * "GNUNET_SYSERR" on all other types of errors.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_remove (struct GNUNET_NAMESTORE_Handle *h,
                                const GNUNET_HashCode *zone,
                                const char *name,
                                uint32_t record_type,
                                size_t size,
                                const void *data,
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
 * @param record_type desired record type
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_name (struct GNUNET_NAMESTORE_Handle *h, 
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
  return qe;
}


/**
 * Get the hash of a record (what will be signed in the Stree for
 * the record).
 *
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and.
 *             GNS specification for GNS extensions)
 * @param record_hash hash of the record (set)
 */
void
GNUNET_NAMESTORE_record_hash (struct GNUNET_NAMESTORE_Handle *h,
                              const GNUNET_HashCode *zone,
                              const char *name,
                              uint32_t record_type,
                              struct GNUNET_TIME_Absolute expiration,
                              enum GNUNET_NAMESTORE_RecordFlags flags,
                              size_t data_size,
                              const void *data,
                              GNUNET_HashCode *record_hash)
{
  char* teststring = "namestore-stub";
  GNUNET_CRYPTO_hash(teststring, strlen(teststring), record_hash);
}

/**
 * Obtain part of a signature B-tree.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param sig_loc location to look up
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_stree (struct GNUNET_NAMESTORE_Handle *h,
                      const GNUNET_HashCode *zone,
                      const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
                      GNUNET_NAMESTORE_StreeProcessor proc, void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
}


/**
 * Get all records of a zone.
 *
 * @param h handle to the namestore
 * @param zone zone to access
 * @param proc function to call on a random value; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a zone and name of NULL.
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_transfer (struct GNUNET_NAMESTORE_Handle *h,
                                const GNUNET_HashCode *zone,
                                GNUNET_NAMESTORE_RecordProcessor proc,
                                void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  qe = GNUNET_malloc(sizeof (struct GNUNET_NAMESTORE_QueueEntry));
  return qe;
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
