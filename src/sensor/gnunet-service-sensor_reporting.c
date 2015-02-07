/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file sensor/gnunet-service-sensor_reporting.c
 * @brief sensor service reporting functionality
 * @author Omar Tarabai
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "sensor.h"
#include "gnunet_peerstore_service.h"
#include "gnunet_core_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_applications.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-reporting",__VA_ARGS__)

/**
 * Retry time when failing to connect to collection point
 */
#define CP_RETRY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)


/**
 * When we are still generating a proof-of-work and we need to send an anomaly
 * report, we queue them until the generation is complete
 */
struct AnomalyReportingQueueItem
{

  /**
   * DLL
   */
  struct AnomalyReportingQueueItem *prev;

  /**
   * DLL
   */
  struct AnomalyReportingQueueItem *next;

  /**
   * Message queue belonging to the peer that is the destination of the report
   */
  struct GNUNET_MQ_Handle *dest_mq;

  /**
   * Report type
   */
  int type;

};

struct AnomalyInfo
{

  /**
   * DLL
   */
  struct AnomalyInfo *prev;

  /**
   * DLL
   */
  struct AnomalyInfo *next;

  /**
   * Sensor information
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Current anomalous status of sensor
   */
  int anomalous;

  /**
   * List of peers that reported an anomaly for this sensor
   */
  struct GNUNET_CONTAINER_MultiPeerMap *anomalous_neighbors;

  /**
   * Report block with proof-of-work and signature
   */
  struct GNUNET_SENSOR_crypto_pow_block *report_block;

  /**
   * Context of an operation creating pow and signature
   */
  struct GNUNET_SENSOR_crypto_pow_context *report_creation_cx;

  /**
   * Head of the queue of pending report destinations
   */
  struct AnomalyReportingQueueItem *reporting_queue_head;

  /**
   * Head of the queue of pending report destinations
   */
  struct AnomalyReportingQueueItem *reporting_queue_tail;

};

struct ValueInfo
{

  /**
   * DLL
   */
  struct ValueInfo *prev;

  /**
   * DLL
   */
  struct ValueInfo *next;

  /**
   * Sensor information
   */
  struct GNUNET_SENSOR_SensorInfo *sensor;

  /**
   * Last value read from sensor
   */
  void *last_value;

  /**
   * Size of @e last_value
   */
  size_t last_value_size;

  /**
   * Timestamp of last value reading
   */
  struct GNUNET_TIME_Absolute last_value_timestamp;

  /**
   * Has the last value seen already been reported to collection point?
   */
  int last_value_reported;

  /**
   * Watcher of sensor values
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * Collection point reporting task (or NULL)
   */
  struct GNUNET_SCHEDULER_Task *reporting_task;

};

/**
 * Information about a connected CORE peer.
 * Note that we only know about a connected peer if it is running the same
 * application (sensor anomaly reporting) as us.
 */
struct CorePeer
{

  /**
   * DLL
   */
  struct CorePeer *prev;

  /**
   * DLL
   */
  struct CorePeer *next;

  /**
   * Peer identity of connected peer
   */
  struct GNUNET_PeerIdentity *peer_id;

  /**
   * Message queue for messages to be sent to this peer
   */
  struct GNUNET_MQ_Handle *mq;

};

/**
 * Information about a connected CADET peer (collection point).
 */
struct CadetPeer
{

  /**
   * DLL
   */
  struct CadetPeer *prev;

  /**
   * DLL
   */
  struct CadetPeer *next;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * CADET channel handle
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Message queue for messages to be sent to this peer
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * CADET transmit handle
   */
  struct GNUNET_CADET_TransmitHandle *th;

  /**
   * Task used to try reconnection to collection point after failure
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Are we currently destroying the channel and its context?
   */
  int destroying;

};


/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Multihashmap of loaded sensors
 */
static struct GNUNET_CONTAINER_MultiHashMap *sensors;

/**
 * Handle to peerstore service
 */
static struct GNUNET_PEERSTORE_Handle *peerstore;

/**
 * Handle to core service
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Handle to CADET service
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * My peer id
 */
static struct GNUNET_PeerIdentity mypeerid;

/**
 * My private key
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *private_key;

/**
 * Head of DLL of anomaly info structs
 */
static struct AnomalyInfo *ai_head;

/**
 * Tail of DLL of anomaly info structs
 */
static struct AnomalyInfo *ai_tail;

/**
 * Head of DLL of value info structs
 */
static struct ValueInfo *vi_head;

/**
 * Tail of DLL of value info structs
 */
static struct ValueInfo *vi_tail;

/**
 * Head of DLL of CORE peers
 */
static struct CorePeer *corep_head;

/**
 * Tail of DLL of CORE peers
 */
static struct CorePeer *corep_tail;

/**
 * Head of DLL of CADET peers
 */
static struct CadetPeer *cadetp_head;

/**
 * Tail of DLL of CADET peers
 */
static struct CadetPeer *cadetp_tail;

/**
 * Is the module started?
 */
static int module_running = GNUNET_NO;

/**
 * Number of known neighborhood peers
 */
static int neighborhood;

/**
 * Parameter that defines the complexity of the proof-of-work
 */
static long long unsigned int pow_matching_bits;



/**
 * Try reconnecting to collection point and send last queued message
 */
static void
cp_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/******************************************************************************/
/******************************      CLEANUP     ******************************/
/******************************************************************************/

/**
 * Destroy anomaly info struct
 *
 * @param ai struct to destroy
 */
static void
destroy_anomaly_info (struct AnomalyInfo *ai)
{
  struct AnomalyReportingQueueItem *ar_item;

  ar_item = ai->reporting_queue_head;
  while (NULL != ar_item)
  {
    GNUNET_CONTAINER_DLL_remove (ai->reporting_queue_head,
                                 ai->reporting_queue_tail, ar_item);
    GNUNET_free (ar_item);
    ar_item = ai->reporting_queue_head;
  }
  if (NULL != ai->report_creation_cx)
  {
    GNUNET_SENSOR_crypto_pow_sign_cancel (ai->report_creation_cx);
    ai->report_creation_cx = NULL;
  }
  if (NULL != ai->report_block)
  {
    GNUNET_free (ai->report_block);
    ai->report_block = NULL;
  }
  if (NULL != ai->anomalous_neighbors)
  {
    GNUNET_CONTAINER_multipeermap_destroy (ai->anomalous_neighbors);
    ai->anomalous_neighbors = NULL;
  }
  GNUNET_free (ai);
}


/**
 * Destroy value info struct
 *
 * @param vi struct to destroy
 */
static void
destroy_value_info (struct ValueInfo *vi)
{
  if (NULL != vi->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (vi->wc);
    vi->wc = NULL;
  }
  if (NULL != vi->reporting_task)
  {
    GNUNET_SCHEDULER_cancel (vi->reporting_task);
    vi->reporting_task = NULL;
  }
  if (NULL != vi->last_value)
  {
    GNUNET_free (vi->last_value);
    vi->last_value = NULL;
  }
  GNUNET_free (vi);
}


/**
 * Destroy core peer struct
 *
 * @param corep struct to destroy
 */
static void
destroy_core_peer (struct CorePeer *corep)
{
  struct AnomalyInfo *ai;
  struct AnomalyReportingQueueItem *ar_item;

  ai = ai_head;
  while (NULL != ai)
  {
    GNUNET_assert (NULL != ai->anomalous_neighbors);
    GNUNET_CONTAINER_multipeermap_remove_all (ai->anomalous_neighbors,
                                              corep->peer_id);
    /* Remove the core peer from any reporting queues */
    ar_item = ai->reporting_queue_head;
    while (NULL != ar_item)
    {
      if (ar_item->dest_mq == corep->mq)
      {
        GNUNET_CONTAINER_DLL_remove (ai->reporting_queue_head,
                                     ai->reporting_queue_tail, ar_item);
        break;
      }
      ar_item = ar_item->next;
    }
    ai = ai->next;
  }
  if (NULL != corep->mq)
  {
    GNUNET_MQ_destroy (corep->mq);
    corep->mq = NULL;
  }
  GNUNET_free (corep);
}


/**
 * Destroy cadet peer struct
 *
 * @param cadetp struct to destroy
 */
static void
destroy_cadet_peer (struct CadetPeer *cadetp)
{
  cadetp->destroying = GNUNET_YES;
  if (NULL != cadetp->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (cadetp->reconnect_task);
    cadetp->reconnect_task = NULL;
  }
  if (NULL != cadetp->mq)
  {
    GNUNET_MQ_destroy (cadetp->mq);
    cadetp->mq = NULL;
  }
  if (NULL != cadetp->channel)
  {
    GNUNET_CADET_channel_destroy (cadetp->channel);
    cadetp->channel = NULL;
  }
  GNUNET_free (cadetp);
}


/**
 * Stop sensor reporting module
 */
void
SENSOR_reporting_stop ()
{
  struct ValueInfo *vi;
  struct CorePeer *corep;
  struct AnomalyInfo *ai;
  struct CadetPeer *cadetp;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Stopping sensor anomaly reporting module.\n");
  module_running = GNUNET_NO;
  neighborhood = 0;
  /* Destroy value info's */
  vi = vi_head;
  while (NULL != vi)
  {
    GNUNET_CONTAINER_DLL_remove (vi_head, vi_tail, vi);
    destroy_value_info (vi);
    vi = vi_head;
  }
  /* Destroy core peers */
  corep = corep_head;
  while (NULL != corep)
  {
    GNUNET_CONTAINER_DLL_remove (corep_head, corep_tail, corep);
    destroy_core_peer (corep);
    corep = corep_head;
  }
  /* Destroy anomaly info's */
  ai = ai_head;
  while (NULL != ai)
  {
    GNUNET_CONTAINER_DLL_remove (ai_head, ai_tail, ai);
    destroy_anomaly_info (ai);
    ai = ai_head;
  }
  /* Destroy cadet peers */
  cadetp = cadetp_head;
  while (NULL != cadetp)
  {
    GNUNET_CONTAINER_DLL_remove (cadetp_head, cadetp_tail, cadetp);
    destroy_cadet_peer (cadetp);
    cadetp = cadetp_head;
  }
  /* Disconnect from other services */
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != peerstore)
  {
    GNUNET_PEERSTORE_disconnect (peerstore, GNUNET_NO);
    peerstore = NULL;
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
}


/******************************************************************************/
/******************************      HELPERS     ******************************/
/******************************************************************************/


/**
 * Gets the anomaly info struct related to the given sensor
 *
 * @param sensor Sensor to search by
 */
static struct AnomalyInfo *
get_anomaly_info_by_sensor (struct GNUNET_SENSOR_SensorInfo *sensor)
{
  struct AnomalyInfo *ai;

  ai = ai_head;
  while (NULL != ai)
  {
    if (ai->sensor == sensor)
    {
      return ai;
    }
    ai = ai->next;
  }
  return NULL;
}


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
cp_mq_ntr (void *cls, size_t size, void *buf)
{
  struct CadetPeer *cadetp = cls;
  const struct GNUNET_MessageHeader *msg = GNUNET_MQ_impl_current (cadetp->mq);
  uint16_t msize;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "cp_mq_ntr()\n");
  cadetp->th = NULL;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Sending anomaly report to collection point failed."
         " Retrying connection in %s.\n",
         GNUNET_STRINGS_relative_time_to_string (CP_RETRY, GNUNET_NO));
    cadetp->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (CP_RETRY, &cp_reconnect, cadetp);
    return 0;
  }
  msize = ntohs (msg->size);
  GNUNET_assert (msize <= size);
  memcpy (buf, msg, msize);
  GNUNET_MQ_impl_send_continue (cadetp->mq);
  return msize;
}


/**
 * Try reconnecting to collection point and send last queued message
 */
static void
cp_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetPeer *cadetp = cls;
  const struct GNUNET_MessageHeader *msg;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Retrying connection to collection point `%s'.\n",
       GNUNET_i2s (&cadetp->peer_id));
  cadetp->reconnect_task = NULL;
  GNUNET_assert (NULL == cadetp->channel);
  cadetp->channel =
      GNUNET_CADET_channel_create (cadet, cadetp, &cadetp->peer_id,
                                   GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
                                   GNUNET_CADET_OPTION_RELIABLE);
  msg = GNUNET_MQ_impl_current (cadetp->mq);
  cadetp->th =
      GNUNET_CADET_notify_transmit_ready (cadetp->channel, GNUNET_NO,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          ntohs (msg->size), cp_mq_ntr, cadetp);
}


/**
 * Signature of functions implementing the
 * sending functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
cp_mq_send_impl (struct GNUNET_MQ_Handle *mq,
                 const struct GNUNET_MessageHeader *msg, void *impl_state)
{
  struct CadetPeer *cadetp = impl_state;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "cp_mq_send_impl()\n");
  GNUNET_assert (NULL == cadetp->th);
  if (NULL == cadetp->channel)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Sending anomaly report to collection point failed."
         " Retrying connection in %s.\n",
         GNUNET_STRINGS_relative_time_to_string (CP_RETRY, GNUNET_NO));
    cadetp->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (CP_RETRY, &cp_reconnect, cadetp);
    return;
  }
  cadetp->th =
      GNUNET_CADET_notify_transmit_ready (cadetp->channel, GNUNET_NO,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          ntohs (msg->size), cp_mq_ntr, cadetp);
}


/**
 * Signature of functions implementing the
 * destruction of a message queue.
 * Implementations must not free 'mq', but should
 * take care of 'impl_state'.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
cp_mq_destroy_impl (struct GNUNET_MQ_Handle *mq, void *impl_state)
{
  struct CadetPeer *cp = impl_state;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "cp_mq_destroy_impl()\n");
  if (NULL != cp->th)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (cp->th);
    cp->th = NULL;
  }
}


/**
 * Create the message queue used to send messages to a collection point.
 * This will be used to make sure that the message are queued even if the
 * connection to the collection point can not be established at the moment.
 *
 * @param cp CadetPeer information struct
 * @return Message queue handle
 */
static struct GNUNET_MQ_Handle *
cp_mq_create (struct CadetPeer *cp)
{
  return GNUNET_MQ_queue_for_callbacks (cp_mq_send_impl, cp_mq_destroy_impl,
                                        NULL, cp, NULL, NULL, NULL);
}


/**
 * Returns context of a connected CADET peer.
 * Creates it first if didn't exist before.
 *
 * @param pid Peer Identity
 * @return Context of connected CADET peer
 */
static struct CadetPeer *
get_cadet_peer (struct GNUNET_PeerIdentity pid)
{
  struct CadetPeer *cadetp;

  cadetp = cadetp_head;
  while (NULL != cadetp)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&pid, &cadetp->peer_id))
      return cadetp;
    cadetp = cadetp->next;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Creating a CADET connection to peer `%s'.\n",
       GNUNET_i2s (&pid));
  /* Not found, create struct and channel */
  cadetp = GNUNET_new (struct CadetPeer);
  cadetp->peer_id = pid;
  cadetp->channel =
      GNUNET_CADET_channel_create (cadet, cadetp, &pid,
                                   GNUNET_APPLICATION_TYPE_SENSORDASHBOARD,
                                   GNUNET_CADET_OPTION_RELIABLE);
  cadetp->mq = cp_mq_create (cadetp);
  cadetp->reconnect_task = NULL;
  GNUNET_CONTAINER_DLL_insert (cadetp_head, cadetp_tail, cadetp);
  return cadetp;
}


/**
 * This function is called only when we have a block ready and want to send it
 * to the given peer (represented by its message queue)
 *
 * @param mq Message queue to put the message in
 * @param ai Anomaly info to report
 * @param type Message type
 */
static void
do_send_anomaly_report (struct GNUNET_MQ_Handle *mq, struct AnomalyInfo *ai,
                        int type)
{
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *ev;
  size_t block_size;

  GNUNET_assert (NULL != ai->report_block);
  block_size =
      sizeof (struct GNUNET_SENSOR_crypto_pow_block) +
      ai->report_block->msg_size;
  ev = GNUNET_MQ_msg_header_extra (msg, block_size, type);
  memcpy (&msg[1], ai->report_block, block_size);
  GNUNET_MQ_send (mq, ev);
}


/**
 * Check if we have signed and proof-of-work block ready.
 * If yes, we send the report directly, if no, we enqueue the reporting until
 * the block is ready.
 *
 * @param mq Message queue to put the message in
 * @param ai Anomaly info to report
 * @param p2p Is the report sent to a neighboring peer
 */
static void
send_anomaly_report (struct GNUNET_MQ_Handle *mq, struct AnomalyInfo *ai,
                     int p2p)
{
  struct AnomalyReportingQueueItem *ar_item;
  int type;

  type =
      (GNUNET_YES ==
       p2p) ? GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT_P2P :
      GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT;
  if (NULL == ai->report_block)
  {
    ar_item = GNUNET_new (struct AnomalyReportingQueueItem);

    ar_item->dest_mq = mq;
    ar_item->type = type;
    GNUNET_CONTAINER_DLL_insert_tail (ai->reporting_queue_head,
                                      ai->reporting_queue_tail, ar_item);
  }
  else
  {
    do_send_anomaly_report (mq, ai, type);
  }
}


/**
 * Callback when the crypto module finished created proof-of-work and signature
 * for an anomaly report.
 *
 * @param cls Closure, a `struct AnomalyInfo *`
 * @param block The resulting block, NULL on error
 */
static void
report_creation_cb (void *cls, struct GNUNET_SENSOR_crypto_pow_block *block)
{
  struct AnomalyInfo *ai = cls;
  struct AnomalyReportingQueueItem *ar_item;

  ai->report_creation_cx = NULL;
  if (NULL != ai->report_block)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Double creation of proof-of-work, this should not happen.\n"));
    return;
  }
  if (NULL == block)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Failed to create pow and signature block.\n"));
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Anomaly report POW block ready.\n");
  ai->report_block =
      GNUNET_memdup (block,
                     sizeof (struct GNUNET_SENSOR_crypto_pow_block) +
                     block->msg_size);
  ar_item = ai->reporting_queue_head;
  while (NULL != ar_item)
  {
    GNUNET_CONTAINER_DLL_remove (ai->reporting_queue_head,
                                 ai->reporting_queue_tail, ar_item);
    do_send_anomaly_report (ar_item->dest_mq, ai, ar_item->type);
    GNUNET_free (ar_item);
    ar_item = ai->reporting_queue_head;
  }
}


/**
 * When a change to the anomaly info of a sensor is done, this function should
 * be called to create the message, its proof-of-work and signuature ready to
 * be sent to other peers or collection point.
 *
 * @param ai Anomaly Info struct
 */
static void
update_anomaly_report_pow_block (struct AnomalyInfo *ai)
{
  struct GNUNET_SENSOR_AnomalyReportMessage *arm;
  struct GNUNET_TIME_Absolute timestamp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating anomaly report POW block due to data change.\n");
  if (NULL != ai->report_block)
  {
    GNUNET_free (ai->report_block);
    ai->report_block = NULL;
  }
  if (NULL != ai->report_creation_cx)
  {
    /* If a creation is already running, cancel it because the data changed */
    GNUNET_SENSOR_crypto_pow_sign_cancel (ai->report_creation_cx);
    ai->report_creation_cx = NULL;
  }
  arm = GNUNET_new (struct GNUNET_SENSOR_AnomalyReportMessage);

  GNUNET_CRYPTO_hash (ai->sensor->name, strlen (ai->sensor->name) + 1,
                      &arm->sensorname_hash);
  arm->sensorversion_major = htons (ai->sensor->version_major);
  arm->sensorversion_minor = htons (ai->sensor->version_minor);
  arm->anomalous = htons (ai->anomalous);
  arm->anomalous_neighbors =
      (0 ==
       neighborhood) ? 0 : ((float)
                            GNUNET_CONTAINER_multipeermap_size
                            (ai->anomalous_neighbors)) / neighborhood;
  timestamp = GNUNET_TIME_absolute_get ();
  ai->report_creation_cx =
      GNUNET_SENSOR_crypto_pow_sign (arm,
                                     sizeof (struct
                                             GNUNET_SENSOR_AnomalyReportMessage),
                                     &timestamp, &mypeerid.public_key,
                                     private_key, pow_matching_bits,
                                     &report_creation_cb, ai);
  GNUNET_free (arm);
}


/**
 * Create a sensor value message from a given value info struct inside a MQ
 * envelope.
 *
 * @param vi Value info struct to use
 * @return Envelope with message
 */
static struct GNUNET_MQ_Envelope *
create_value_message (struct ValueInfo *vi)
{
  struct GNUNET_SENSOR_ValueMessage *vm;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg_extra (vm, vi->last_value_size,
                            GNUNET_MESSAGE_TYPE_SENSOR_READING);
  GNUNET_CRYPTO_hash (vi->sensor->name, strlen (vi->sensor->name) + 1,
                      &vm->sensorname_hash);
  vm->sensorversion_major = htons (vi->sensor->version_major);
  vm->sensorversion_minor = htons (vi->sensor->version_minor);
  vm->timestamp = vi->last_value_timestamp;
  vm->value_size = htons (vi->last_value_size);
  memcpy (&vm[1], vi->last_value, vi->last_value_size);
  return ev;
}


/******************************************************************************/
/***************************      CORE Handlers     ***************************/
/******************************************************************************/


/**
 * An inbound anomaly report is received from a peer through CORE.
 *
 * @param cls closure (unused)
 * @param peer the other peer involved
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close connection to the peer (signal serious error)
 */
static int
handle_anomaly_report (void *cls, const struct GNUNET_PeerIdentity *other,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SENSOR_crypto_pow_block *report_block;
  struct GNUNET_SENSOR_AnomalyReportMessage *arm;
  struct GNUNET_SENSOR_SensorInfo *sensor;
  struct AnomalyInfo *my_anomaly_info;
  struct CadetPeer *cadetp;
  int peer_anomalous;
  int peer_in_anomalous_list;

  /* Verify proof-of-work, signature and extract report message */
  report_block = (struct GNUNET_SENSOR_crypto_pow_block *) &message[1];
  if (sizeof (struct GNUNET_SENSOR_AnomalyReportMessage) !=
      GNUNET_SENSOR_crypto_verify_pow_sign (report_block, pow_matching_bits,
                                            (struct GNUNET_CRYPTO_EddsaPublicKey
                                             *) &other->public_key,
                                            (void **) &arm))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Received invalid anomaly report from peer `%s'.\n",
         GNUNET_i2s (other));
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* Now we parse the content of the message */
  sensor = GNUNET_CONTAINER_multihashmap_get (sensors, &arm->sensorname_hash);
  if (NULL == sensor ||
      sensor->version_major != ntohs (arm->sensorversion_major) ||
      sensor->version_minor != ntohs (arm->sensorversion_minor))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "I don't have the sensor reported by the peer `%s'.\n",
         GNUNET_i2s (other));
    return GNUNET_OK;
  }
  my_anomaly_info = get_anomaly_info_by_sensor (sensor);
  GNUNET_assert (NULL != my_anomaly_info);
  peer_in_anomalous_list =
      GNUNET_CONTAINER_multipeermap_contains
      (my_anomaly_info->anomalous_neighbors, other);
  peer_anomalous = ntohs (arm->anomalous);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received an anomaly update from neighbour `%s' (%d).\n",
       GNUNET_i2s (other), peer_anomalous);
  if (GNUNET_YES == peer_anomalous)
  {
    if (GNUNET_YES == peer_in_anomalous_list)   /* repeated positive report */
      GNUNET_break_op (0);
    else
      GNUNET_CONTAINER_multipeermap_put (my_anomaly_info->anomalous_neighbors,
                                         other, NULL,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    if (GNUNET_NO == peer_in_anomalous_list)    /* repeated negative report */
      GNUNET_break_op (0);
    else
      GNUNET_CONTAINER_multipeermap_remove_all
          (my_anomaly_info->anomalous_neighbors, other);
  }
  /* This is important to create an updated block since the data changed */
  update_anomaly_report_pow_block (my_anomaly_info);
  /* Send anomaly update to collection point only if I have the same anomaly */
  if (GNUNET_YES == my_anomaly_info->anomalous &&
      NULL != sensor->collection_point &&
      GNUNET_YES == sensor->report_anomalies)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Neighbor update triggered sending anomaly report to collection point `%s'.\n",
         GNUNET_i2s (sensor->collection_point));
    cadetp = get_cadet_peer (*sensor->collection_point);
    send_anomaly_report (cadetp->mq, my_anomaly_info, GNUNET_NO);
  }
  return GNUNET_OK;
}


/******************************************************************************/
/************************      PEERSTORE callbacks     ************************/
/******************************************************************************/


/**
 * Sensor value watch callback
 *
 * @param cls Closure, ValueInfo struct related to the sensor we are watching
 * @param record PEERSTORE new record, NULL if error
 * @param emsg Error message, NULL if no error
 * @return #GNUNET_YES to continue watching
 */
static int
value_watch_cb (void *cls,
                const struct GNUNET_PEERSTORE_Record *record,
                const char *emsg)
{
  struct ValueInfo *vi = cls;

  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("PEERSTORE error: %s.\n"), emsg);
    return GNUNET_YES;
  }
  if (NULL != vi->last_value)
  {
    GNUNET_free (vi->last_value);
    vi->last_value_size = 0;
  }
  vi->last_value = GNUNET_memdup (record->value, record->value_size);
  vi->last_value_size = record->value_size;
  vi->last_value_timestamp = GNUNET_TIME_absolute_get ();
  vi->last_value_reported = GNUNET_NO;
  return GNUNET_YES;
}


/******************************************************************************/
/**************************      CORE callbacks     ***************************/
/******************************************************************************/


/**
 * Method called whenever a CORE peer disconnects.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CorePeer *corep;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Core peer `%s' disconnected.\n",
       GNUNET_i2s (peer));
  neighborhood--;
  corep = corep_head;
  while (NULL != corep)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (peer, corep->peer_id))
    {
      GNUNET_CONTAINER_DLL_remove (corep_head, corep_tail, corep);
      destroy_core_peer (corep);
      return;
    }
    corep = corep->next;
  }
}


/**
 * Method called whenever a given peer connects through CORE.
 *
 * @param cls closure (unused)
 * @param peer peer identity this notification is about
 */
static void
core_connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CorePeer *corep;
  struct AnomalyInfo *ai;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, peer))
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connected to core peer `%s'.\n",
       GNUNET_i2s (peer));
  neighborhood++;
  corep = GNUNET_new (struct CorePeer);
  corep->peer_id = (struct GNUNET_PeerIdentity *) peer;
  corep->mq = GNUNET_CORE_mq_create (core, peer);
  GNUNET_CONTAINER_DLL_insert (corep_head, corep_tail, corep);
  /* Send any locally anomalous sensors to the new peer */
  ai = ai_head;
  while (NULL != ai)
  {
    if (GNUNET_YES == ai->anomalous)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Updating newly connected neighbor `%s' with anomalous sensor.\n",
           GNUNET_i2s (peer));
      send_anomaly_report (corep->mq, ai, GNUNET_YES);
    }
    ai = ai->next;
  }
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure (unused)
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_startup_cb (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CORE service.\n"));
    SENSOR_reporting_stop ();
    return;
  }
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&mypeerid, my_identity))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Peer identity received from CORE init doesn't match ours.\n"));
    SENSOR_reporting_stop ();
    return;
  }
}


/******************************************************************************/
/*************************      CADET callbacks     ***************************/
/******************************************************************************/

/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
cadet_channel_destroyed (void *cls, const struct GNUNET_CADET_Channel *channel,
                         void *channel_ctx)
{
  struct CadetPeer *cadetp = channel_ctx;

  if (GNUNET_YES == cadetp->destroying)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "CADET channel was destroyed by remote peer `%s' or failed to start.\n",
       GNUNET_i2s (&cadetp->peer_id));
  if (NULL != cadetp->th)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (cadetp->th);
    cadetp->th = NULL;
  }
  cadetp->channel = NULL;
}


/******************************************************************************/
/**********************      Local anomaly receiver     ***********************/
/******************************************************************************/


/**
 * Used by the analysis module to tell the reporting module about a change in
 * the anomaly status of a sensor.
 *
 * @param sensor Related sensor
 * @param anomalous The new sensor anomalous status
 */
void
SENSOR_reporting_anomaly_update (struct GNUNET_SENSOR_SensorInfo *sensor,
                                 int anomalous)
{
  struct AnomalyInfo *ai;
  struct CorePeer *corep;
  struct CadetPeer *cadetp;

  if (GNUNET_NO == module_running)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received an external anomaly update.\n");
  ai = get_anomaly_info_by_sensor (sensor);
  GNUNET_assert (NULL != ai);
  ai->anomalous = anomalous;
  /* This is important to create an updated block since the data changed */
  update_anomaly_report_pow_block (ai);
  /* Report change to all neighbors */
  corep = corep_head;
  while (NULL != corep)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sending an anomaly report to neighbor `%s'.\n",
         GNUNET_i2s (corep->peer_id));
    send_anomaly_report (corep->mq, ai, GNUNET_YES);
    corep = corep->next;
  }
  /* Report change to collection point if need */
  if (NULL != ai->sensor->collection_point &&
      GNUNET_YES == ai->sensor->report_anomalies)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Local anomaly update triggered sending anomaly report to collection point `%s'.\n",
         GNUNET_i2s (ai->sensor->collection_point));
    cadetp = get_cadet_peer (*ai->sensor->collection_point);
    send_anomaly_report (cadetp->mq, ai, GNUNET_NO);
  }
}


/******************************************************************************/
/*******************      Reporting values (periodic)     *********************/
/******************************************************************************/


/**
 * Task scheduled to send values to collection point
 *
 * @param cls closure, a `struct ValueReportingContext *`
 * @param tc unused
 */
static void
report_value (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ValueInfo *vi = cls;
  struct GNUNET_SENSOR_SensorInfo *sensor = vi->sensor;
  struct CadetPeer *cadetp;
  struct GNUNET_MQ_Envelope *ev;

  vi->reporting_task =
      GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                    &report_value, vi);
  if (0 == vi->last_value_size || GNUNET_YES == vi->last_value_reported)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Did not receive a fresh value from `%s' to report.\n", sensor->name);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Now trying to report last seen value of `%s' to collection point.\n",
       sensor->name);
  cadetp = get_cadet_peer (*sensor->collection_point);
  if (NULL == cadetp->channel)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Trying to send value to collection point but connection failed, discarding.\n");
    return;
  }
  ev = create_value_message (vi);
  GNUNET_MQ_send (cadetp->mq, ev);
  vi->last_value_reported = GNUNET_YES;
}


/******************************************************************************/
/********************************      INIT     *******************************/
/******************************************************************************/


/**
 * Iterator for defined sensors and creates anomaly info context
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct GNUNET_SENSOR_SensorInfo *` with sensor information
 * @return #GNUNET_YES to continue iterations
 */
static int
init_sensor_reporting (void *cls, const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_SENSOR_SensorInfo *sensor = value;
  struct AnomalyInfo *ai;
  struct ValueInfo *vi;

  /* Create sensor anomaly info context */
  ai = GNUNET_new (struct AnomalyInfo);

  ai->sensor = sensor;
  ai->anomalous = GNUNET_NO;
  ai->anomalous_neighbors =
      GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  ai->report_block = NULL;
  ai->report_creation_cx = NULL;
  GNUNET_CONTAINER_DLL_insert (ai_head, ai_tail, ai);
  /* Create sensor value info context (if needed to be reported) */
  if (NULL == sensor->collection_point || GNUNET_NO == sensor->report_values)
    return GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Reporting sensor `%s' values to collection point `%s' every %s.\n",
       sensor->name, GNUNET_i2s_full (sensor->collection_point),
       GNUNET_STRINGS_relative_time_to_string (sensor->value_reporting_interval,
                                               GNUNET_YES));
  vi = GNUNET_new (struct ValueInfo);
  vi->sensor = sensor;
  vi->last_value = NULL;
  vi->last_value_size = 0;
  vi->last_value_reported = GNUNET_NO;
  vi->wc =
      GNUNET_PEERSTORE_watch (peerstore, "sensor", &mypeerid, sensor->name,
                              &value_watch_cb, vi);
  vi->reporting_task =
      GNUNET_SCHEDULER_add_delayed (sensor->value_reporting_interval,
                                    &report_value, vi);
  GNUNET_CONTAINER_DLL_insert (vi_head, vi_tail, vi);
  return GNUNET_YES;
}


/**
 * Start the sensor anomaly reporting module
 *
 * @param c our service configuration
 * @param s multihashmap of loaded sensors
 * @return #GNUNET_OK if started successfully, #GNUNET_SYSERR otherwise
 */
int
SENSOR_reporting_start (const struct GNUNET_CONFIGURATION_Handle *c,
                        struct GNUNET_CONTAINER_MultiHashMap *s)
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_anomaly_report, GNUNET_MESSAGE_TYPE_SENSOR_ANOMALY_REPORT_P2P,
     sizeof (struct GNUNET_MessageHeader) +
     sizeof (struct GNUNET_SENSOR_crypto_pow_block) +
     sizeof (struct GNUNET_SENSOR_AnomalyReportMessage)},
    {NULL, 0, 0}
  };
  static struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    {NULL, 0, 0}
  };

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting sensor reporting module.\n");
  GNUNET_assert (NULL != s);
  sensors = s;
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "sensor-reporting",
                                             "POW_MATCHING_BITS",
                                             &pow_matching_bits))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "sensor-reporting",
                               "POW_MATCHING_BITS");
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  if (pow_matching_bits > sizeof (struct GNUNET_HashCode))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Matching bits value too large (%d > %d).\n",
         pow_matching_bits, sizeof (struct GNUNET_HashCode));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  /* Connect to PEERSTORE */
  peerstore = GNUNET_PEERSTORE_connect (cfg);
  if (NULL == peerstore)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Failed to connect to peerstore service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  /* Connect to CORE */
  core =
      GNUNET_CORE_connect (cfg, NULL, &core_startup_cb, core_connect_cb,
                           &core_disconnect_cb, NULL, GNUNET_YES, NULL,
                           GNUNET_YES, core_handlers);
  if (NULL == core)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CORE service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  /* Connect to CADET */
  cadet =
      GNUNET_CADET_connect (cfg, NULL, NULL, &cadet_channel_destroyed,
                            cadet_handlers, NULL);
  if (NULL == cadet)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to connect to CADET service.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  if (NULL == private_key)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Failed to load my private key.\n"));
    SENSOR_reporting_stop ();
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_get_peer_identity (cfg, &mypeerid);
  GNUNET_CONTAINER_multihashmap_iterate (sensors, &init_sensor_reporting, NULL);
  neighborhood = 0;
  module_running = GNUNET_YES;
  return GNUNET_OK;
}

/* end of gnunet-service-sensor_reporting.c */
