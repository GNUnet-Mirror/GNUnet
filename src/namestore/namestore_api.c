/*
     This file is part of GNUnet.
     Copyright (C) 2010-2013, 2016 GNUnet e.V.

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
  struct GNUNET_NAMESTORE_Handle *h;

  /**
   * Continuation to call
   */
  GNUNET_NAMESTORE_ContinuationWithStatus cont;

  /**
   * Closure for @e cont.
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
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

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
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e error_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_NAMESTORE_RecordMonitor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

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
 * Connection to the NAMESTORE service.
 */
struct GNUNET_NAMESTORE_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to the service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

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
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay introduced before we reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

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
 * Find the queue entry that matches the @a rid
 *
 * @param h namestore handle
 * @param rid id to look up
 * @return NULL if @a rid was not found
 */
static struct GNUNET_NAMESTORE_QueueEntry *
find_qe (struct GNUNET_NAMESTORE_Handle *h,
         uint32_t rid)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  for (qe = h->op_head; qe != NULL; qe = qe->next)
    if (qe->op_id == rid)
      return qe;
  return NULL;
}


/**
 * Find the zone iteration entry that matches the @a rid
 *
 * @param h namestore handle
 * @param rid id to look up
 * @return NULL if @a rid was not found
 */
static struct GNUNET_NAMESTORE_ZoneIterator *
find_zi (struct GNUNET_NAMESTORE_Handle *h,
         uint32_t rid)
{
  struct GNUNET_NAMESTORE_ZoneIterator *ze;

  for (ze = h->z_head; ze != NULL; ze = ze->next)
    if (ze->op_id == rid)
      return ze;
  return NULL;
}


/**
 * Free @a qe.
 *
 * @param qe entry to free
 */
static void
free_qe (struct GNUNET_NAMESTORE_QueueEntry *qe)
{
  struct GNUNET_NAMESTORE_Handle *h = qe->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               qe);
  if (NULL != qe->env)
    GNUNET_MQ_discard (qe->env);
  GNUNET_free (qe);
}


/**
 * Free @a ze.
 *
 * @param ze entry to free
 */
static void
free_ze (struct GNUNET_NAMESTORE_ZoneIterator *ze)
{
  struct GNUNET_NAMESTORE_Handle *h = ze->h;

  GNUNET_CONTAINER_DLL_remove (h->z_head,
                               h->z_tail,
                               ze);
  if (NULL != ze->env)
    GNUNET_MQ_discard (ze->env);
  GNUNET_free (ze);
}


/**
 * Check that @a rd_buf of lenght @a rd_len contains
 * @a rd_count records.
 *
 * @param rd_len length of @a rd_buf
 * @param rd_buf buffer with serialized records
 * @param rd_count number of records expected
 * @return #GNUNET_OK if @a rd_buf is well-formed
 */
static int
check_rd (size_t rd_len,
          const void *rd_buf,
          unsigned int rd_count)
{
  struct GNUNET_GNSRECORD_Data rd[rd_count];

  if (GNUNET_OK !=
      GNUNET_GNSRECORD_records_deserialize (rd_len,
                                            rd_buf,
                                            rd_count,
                                            rd))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_record_store_response (void *cls,
			      const struct RecordStoreResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  int res;
  const char *emsg;

  qe = find_qe (h,
                ntohl (msg->gns_header.r_id));
  res = ntohl (msg->op_result);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received RECORD_STORE_RESPONSE with result %d\n",
       res);
  /* TODO: add actual error message from namestore to response... */
  if (GNUNET_SYSERR == res)
    emsg = _("Namestore failed to store record\n");
  else
    emsg = NULL;
  if (NULL != qe->cont)
    qe->cont (qe->cont_cls,
              res,
              emsg);
  free_qe (qe);
}


/**
 * Check validity of an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_lookup_result (void *cls,
                     const struct LabelLookupResponseMessage *msg)
{
  const char *name;
  size_t exp_msg_len;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;

  rd_len = ntohs (msg->rd_len);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  exp_msg_len = sizeof (*msg) + name_len + rd_len;
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
  if (GNUNET_NO == ntohs (msg->found))
  {
    if (0 != ntohs (msg->rd_count))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    return GNUNET_OK;
  }
  return check_rd (rd_len,
                   &name[name_len],
                   ntohs (msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_lookup_result (void *cls,
                      const struct LabelLookupResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  const char *name;
  const char *rd_tmp;
  size_t name_len;
  size_t rd_len;
  unsigned int rd_count;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received RECORD_LOOKUP_RESULT\n");
  qe = find_qe (h,
                ntohl (msg->gns_header.r_id));
  if (NULL == qe)
    return;
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  name = (const char *) &msg[1];
  if (GNUNET_NO == ntohs (msg->found))
  {
    /* label was not in namestore */
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls,
                &msg->private_key,
                name,
                0,
                NULL);
    free_qe (qe);
    return;
  }

  rd_tmp = &name[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_GNSRECORD_records_deserialize (rd_len,
                                                         rd_tmp,
                                                         rd_count,
                                                         rd));
    if (0 == name_len)
      name = NULL;
    if (NULL != qe->proc)
      qe->proc (qe->proc_cls,
                &msg->private_key,
                name,
                rd_count,
                (rd_count > 0) ? rd : NULL);
  }
  free_qe (qe);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_record_result (void *cls,
                     const struct RecordResultMessage *msg)
{
  const char *name;
  size_t msg_len;
  size_t name_len;
  size_t rd_len;

  rd_len = ntohs (msg->rd_len);
  msg_len = ntohs (msg->gns_header.header.size);
  name_len = ntohs (msg->name_len);
  if (0 != ntohs (msg->reserved))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (msg_len != sizeof (struct RecordResultMessage) + name_len + rd_len)
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
  return check_rd (rd_len,
                   &name[name_len],
                   ntohs (msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_record_result (void *cls,
		      const struct RecordResultMessage *msg)
{
  static struct GNUNET_CRYPTO_EcdsaPrivateKey priv_dummy;
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_NAMESTORE_ZoneIterator *ze;
  const char *name;
  const char *rd_tmp;
  size_t name_len;
  size_t rd_len;
  unsigned int rd_count;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received RECORD_RESULT\n");
  rd_len = ntohs (msg->rd_len);
  rd_count = ntohs (msg->rd_count);
  name_len = ntohs (msg->name_len);
  ze = find_zi (h,
                ntohl (msg->gns_header.r_id));
  qe = find_qe (h,
                ntohl (msg->gns_header.r_id));
  if ( (NULL == ze) &&
       (NULL == qe) )
    return; /* rid not found */
  if ( (NULL != ze) &&
       (NULL != qe) )
  {
    GNUNET_break (0);   /* rid ambigous */
    force_reconnect (h);
    return;
  }
  if ( (0 == name_len) &&
       (0 == (memcmp (&msg->private_key,
		      &priv_dummy,
		      sizeof (priv_dummy)))) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Zone iteration completed!\n");
    if (NULL == ze)
    {
      GNUNET_break (0);
      force_reconnect (h);
      return;
    }
    if (NULL != ze->finish_cb)
      ze->finish_cb (ze->finish_cb_cls);
    free_ze (ze);
    return;
  }

  name = (const char *) &msg[1];
  rd_tmp = &name[name_len];
  {
    struct GNUNET_GNSRECORD_Data rd[rd_count];

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_GNSRECORD_records_deserialize(rd_len,
                                                        rd_tmp,
                                                        rd_count,
                                                        rd));
    if (0 == name_len)
      name = NULL;
    if (NULL != qe)
    {
      if (NULL != qe->proc)
        qe->proc (qe->proc_cls,
                  &msg->private_key,
                  name,
                  rd_count,
                  (rd_count > 0) ? rd : NULL);
      free_qe (qe);
      return;
    }
    if (NULL != ze)
    {
      if (NULL != ze->proc)
        ze->proc (ze->proc_cls,
                  &msg->private_key,
                  name,
                  rd_count,
                  rd);
      return;
    }
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE.
 *
 * @param qe the respective entry in the message queue
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if message malformed
 */
static int
check_zone_to_name_response (void *cls,
                             const struct ZoneToNameResponseMessage *msg)
{
  size_t name_len;
  size_t rd_ser_len;
  const char *name_tmp;

  if (GNUNET_OK != ntohs (msg->res))
    return GNUNET_OK;
  name_len = ntohs (msg->name_len);
  rd_ser_len = ntohs (msg->rd_len);
  if (ntohs (msg->gns_header.header.size) !=
      sizeof (struct ZoneToNameResponseMessage) + name_len + rd_ser_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  name_tmp = (const char *) &msg[1];
  if ( (name_len > 0) &&
       ('\0' != name_tmp[name_len -1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return check_rd (rd_ser_len,
                   &name_tmp[name_len],
                   ntohs (msg->rd_count));
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE.
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_zone_to_name_response (void *cls,
			      const struct ZoneToNameResponseMessage *msg)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  int res;
  size_t name_len;
  size_t rd_ser_len;
  unsigned int rd_count;
  const char *name_tmp;
  const char *rd_tmp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received ZONE_TO_NAME_RESPONSE\n");
  qe = find_qe (h,
                ntohl (msg->gns_header.r_id));
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
    free_qe (qe);
    return;
  case GNUNET_YES:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Namestore has result for zone to name mapping \n");
    name_len = ntohs (msg->name_len);
    rd_count = ntohs (msg->rd_count);
    rd_ser_len = ntohs (msg->rd_len);
    name_tmp = (const char *) &msg[1];
    rd_tmp = &name_tmp[name_len];
    {
      struct GNUNET_GNSRECORD_Data rd[rd_count];

      GNUNET_assert (GNUNET_OK ==
                     GNUNET_GNSRECORD_records_deserialize (rd_ser_len,
                                                           rd_tmp,
                                                           rd_count,
                                                           rd));
      /* normal end, call continuation with result */
      if (NULL != qe->proc)
	qe->proc (qe->proc_cls,
		  &msg->zone,
		  name_tmp,
		  rd_count,
                  rd);
      /* return is important here: break would call continuation with error! */
      free_qe (qe);
      return;
    }
  default:
    GNUNET_break (0);
    force_reconnect (h);
    return;
  }
  /* error case, call continuation with error */
  if (NULL != qe->error_cb)
    qe->error_cb (qe->error_cb_cls);
  free_qe (qe);
}



/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NAMESTORE_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NAMESTORE_Handle *h = cls;

  force_reconnect (h);
}


/**
 * Reconnect to namestore service.
 *
 * @param h the handle to the NAMESTORE service
 */
static void
reconnect (struct GNUNET_NAMESTORE_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (record_store_response,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE,
                             struct RecordStoreResponseMessage,
                             h),
    GNUNET_MQ_hd_var_size (zone_to_name_response,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE,
                           struct ZoneToNameResponseMessage,
                           h),
    GNUNET_MQ_hd_var_size (record_result,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT,
                           struct RecordResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (lookup_result,
                           GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE,
                           struct LabelLookupResponseMessage,
                           h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "namestore",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  /* re-transmit pending requests that waited for a reconnect... */
  for (it = h->z_head; NULL != it; it = it->next)
  {
    GNUNET_MQ_send (h->mq,
                    it->env);
    it->env = NULL;
  }
  for (qe = h->op_head; NULL != qe; qe = qe->next)
  {
    GNUNET_MQ_send (h->mq,
                    qe->env);
    qe->env = NULL;
  }
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
reconnect_task (void *cls)
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
  struct GNUNET_NAMESTORE_ZoneIterator *ze;
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  while (NULL != (ze = h->z_head))
  {
    if (NULL != ze->error_cb)
      ze->error_cb (ze->error_cb_cls);
    free_ze (ze);
  }
  while (NULL != (qe = h->op_head))
  {
    if (NULL != qe->error_cb)
      qe->error_cb (qe->error_cb_cls);
    if (NULL != qe->cont)
      qe->cont (qe->cont_cls,
                GNUNET_SYSERR,
                "failure in communication with namestore service");
    free_qe (qe);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Reconnecting to namestore\n");
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
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
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
  struct GNUNET_NAMESTORE_QueueEntry *q;
  struct GNUNET_NAMESTORE_ZoneIterator *z;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Cleaning up\n");
  GNUNET_break (NULL == h->op_head);
  while (NULL != (q = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 q);
    GNUNET_free (q);
  }
  GNUNET_break (NULL == h->z_head);
  while (NULL != (z = h->z_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->z_head,
                                 h->z_tail,
                                 z);
    GNUNET_free (z);
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
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
 * @param rd_count number of records in the @a rd array
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
  struct GNUNET_MQ_Envelope *env;
  char *name_tmp;
  char *rd_ser;
  size_t rd_ser_len;
  size_t name_len;
  uint32_t rid;
  struct RecordStoreMessage *msg;

  name_len = strlen (label) + 1;
  if (name_len > MAX_NAME_LEN)
  {
    GNUNET_break (0);
    return NULL;
  }
  rid = get_op_id (h);
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    qe);

  /* setup msg */
  rd_ser_len = GNUNET_GNSRECORD_records_get_size (rd_count,
                                                  rd);
  env = GNUNET_MQ_msg_extra (msg,
                             name_len + rd_ser_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE);
  msg->gns_header.r_id = htonl (rid);
  msg->name_len = htons (name_len);
  msg->rd_count = htons (rd_count);
  msg->rd_len = htons (rd_ser_len);
  msg->reserved = htons (0);
  msg->private_key = *pkey;

  name_tmp = (char *) &msg[1];
  GNUNET_memcpy (name_tmp,
                 label,
                 name_len);
  rd_ser = &name_tmp[name_len];
  GNUNET_assert (rd_ser_len ==
                 GNUNET_GNSRECORD_records_serialize (rd_count,
                                                     rd,
                                                     rd_ser_len,
                                                     rd_ser));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending NAMESTORE_RECORD_STORE message for name `%s' with %u records\n",
       label,
       rd_count);

  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
  return qe;
}


/**
 * Set the desired nick name for a zone
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param nick the nick name to set
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
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

  if (NULL == h->mq)
    return NULL;
  memset (&rd, 0, sizeof (rd));
  rd.data = nick;
  rd.data_size = strlen (nick) +1;
  rd.record_type = GNUNET_GNSRECORD_TYPE_NICK;
  rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  rd.flags |= GNUNET_GNSRECORD_RF_PRIVATE;
  return GNUNET_NAMESTORE_records_store (h,
                                         pkey,
                                         GNUNET_GNS_MASTERZONE_STR,
                                         1,
                                         &rd,
                                         cont,
                                         cont_cls);
}


/**
 * Lookup an item in the namestore.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param error_cb function to call on error (i.e. disconnect)
 * @param error_cb_cls closure for @a error_cb
 * @param rm function to call with the result (with 0 records if we don't have that label)
 * @param rm_cls closure for @a rm
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_lookup (struct GNUNET_NAMESTORE_Handle *h,
                                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                                 const char *label,
                                 GNUNET_SCHEDULER_TaskCallback error_cb,
                                 void *error_cb_cls,
                                 GNUNET_NAMESTORE_RecordMonitor rm,
                                 void *rm_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct LabelLookupMessage *msg;
  size_t label_len;

  if (1 == (label_len = strlen (label) + 1))
  {
    GNUNET_break (0);
    return NULL;
  }

  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->error_cb = error_cb;
  qe->error_cb_cls = error_cb_cls;
  qe->proc = rm;
  qe->proc_cls = rm_cls;
  qe->op_id = get_op_id(h);
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    qe);

  env = GNUNET_MQ_msg_extra (msg,
                             label_len,
                             GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP);
  msg->gns_header.r_id = htonl (qe->op_id);
  msg->zone = *pkey;
  msg->label_len = htonl (label_len);
  GNUNET_memcpy (&msg[1],
          label,
          label_len);
  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
  return qe;
}


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the processor.
 *
 * @param h handle to the namestore
 * @param zone public key of the zone to look up in, never NULL
 * @param value_zone public key of the target zone (value), never NULL
 * @param error_cb function to call on error (i.e. disconnect)
 * @param error_cb_cls closure for @a error_cb
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
                               GNUNET_SCHEDULER_TaskCallback error_cb,
                               void *error_cb_cls,
			       GNUNET_NAMESTORE_RecordMonitor proc,
                               void *proc_cls)
{
  struct GNUNET_NAMESTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneToNameMessage *msg;
  uint32_t rid;

  rid = get_op_id(h);
  qe = GNUNET_new (struct GNUNET_NAMESTORE_QueueEntry);
  qe->h = h;
  qe->error_cb = error_cb;
  qe->error_cb_cls = error_cb_cls;
  qe->proc = proc;
  qe->proc_cls = proc_cls;
  qe->op_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    qe);

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME);
  msg->gns_header.r_id = htonl (rid);
  msg->zone = *zone;
  msg->value_zone = *value_zone;
  if (NULL == h->mq)
    qe->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
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
 * @param error_cb function to call on error (i.e. disconnect)
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (struct GNUNET_NAMESTORE_Handle *h,
				       const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
                                       GNUNET_SCHEDULER_TaskCallback error_cb,
                                       void *error_cb_cls,
				       GNUNET_NAMESTORE_RecordMonitor proc,
				       void *proc_cls,
                                       GNUNET_SCHEDULER_TaskCallback finish_cb,
                                       void *finish_cb_cls)
{
  struct GNUNET_NAMESTORE_ZoneIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneIterationStartMessage *msg;
  uint32_t rid;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ZONE_ITERATION_START message\n");
  rid = get_op_id (h);
  it = GNUNET_new (struct GNUNET_NAMESTORE_ZoneIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->op_id = rid;
  if (NULL != zone)
    it->zone = *zone;
  GNUNET_CONTAINER_DLL_insert_tail (h->z_head,
                                    h->z_tail,
                                    it);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START);
  msg->gns_header.r_id = htonl (rid);
  if (NULL != zone)
    msg->zone = *zone;
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
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
  struct GNUNET_NAMESTORE_Handle *h = it->h;
  struct ZoneIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ZONE_ITERATION_NEXT message\n");
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT);
  msg->gns_header.r_id = htonl (it->op_id);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Stops iteration and releases the namestore handle for further calls.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it)
{
  struct GNUNET_NAMESTORE_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct ZoneIterationStopMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending ZONE_ITERATION_STOP message\n");
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP);
  msg->gns_header.r_id = htonl (it->op_id);
  GNUNET_MQ_send (h->mq,
                  env);
  free_ze (it);
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
  free_qe (qe);
}


/* end of namestore_api.c */
