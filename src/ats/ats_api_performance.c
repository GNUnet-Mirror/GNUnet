/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api_performance.c
 * @brief automatic transport selection and outbound bandwidth determination
 * @author Christian Grothoff
 * @author Matthias Wachs
  */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"


/**
 * Message in linked list we should send to the ATS service.  The
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
   * Is this the 'ATS_START' message?
   */
  int is_init;
};


/**
 * Linked list of pending reservations.
 */
struct GNUNET_ATS_ReservationContext
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_ATS_ReservationContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_ATS_ReservationContext *prev;

  /**
   * Target peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Desired reservation
   */
  int32_t size;

  /**
   * Function to call on result.
   */
  GNUNET_ATS_ReservationCallback rcb;

  /**
   * Closure for 'rcb'
   */
  void *rcb_cls;

  /**
   * Do we need to undo this reservation if it succeeded?  Set to
   * GNUNET_YES if a reservation is cancelled.  (at that point, 'info'
   * is also set to NULL; however, info will ALSO be NULL for the
   * reservation context that is created to undo the original request,
   * so 'info' being NULL cannot be used to check if undo is
   * required).
   */
  int undo;
};


/**
 * ATS Handle to obtain and/or modify performance information.
 */
struct GNUNET_ATS_PerformanceHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback to invoke on performance changes.
   */
  GNUNET_ATS_PeerInformationCallback infocb;

  /**
   * Closure for 'infocb'.
   */
  void *infocb_cls;

  /**
   * Connection to ATS service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Head of list of messages for the ATS service.
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of list of messages for the ATS service
   */
  struct PendingMessage *pending_tail;

  /**
   * Head of linked list of pending reservation requests.
   */
  struct GNUNET_ATS_ReservationContext *reservation_head;

  /**
   * Tail of linked list of pending reservation requests.
   */
  struct GNUNET_ATS_ReservationContext *reservation_tail;

  /**
   * Current request for transmission to ATS.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task to trigger reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

};


/**
 * Re-establish the connection to the ATS service.
 *
 * @param ph handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_PerformanceHandle *ph);


/**
 * Re-establish the connection to the ATS service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;

  ph->task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (ph);
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param ph handle to use
 */
static void
do_transmit (struct GNUNET_ATS_PerformanceHandle *ph);


/**
 * We can now transmit a message to ATS. Do it.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param size number of bytes we can transmit to ATS
 * @param buf where to copy the messages
 * @return number of bytes copied into buf
 */
static size_t
transmit_message_to_ats (void *cls, size_t size, void *buf)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;
  struct PendingMessage *p;
  size_t ret;
  char *cbuf;

  ph->th = NULL;
  ret = 0;
  cbuf = buf;
  while ((NULL != (p = ph->pending_head)) && (p->size <= size))
  {
    memcpy (&cbuf[ret], &p[1], p->size);
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (ph->pending_head, ph->pending_tail, p);
    GNUNET_free (p);
  }
  do_transmit (ph);
  return ret;
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param ph handle to use
 */
static void
do_transmit (struct GNUNET_ATS_PerformanceHandle *ph)
{
  struct PendingMessage *p;

  if (NULL != ph->th)
    return;
  if (NULL == (p = ph->pending_head))
    return;
  if (NULL == ph->client)
    return;                     /* currently reconnecting */
  ph->th =
      GNUNET_CLIENT_notify_transmit_ready (ph->client, p->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &transmit_message_to_ats,
                                           ph);
}


/**
 * We received a peer information message.  Validate and process it.
 *
 * @param ph our context with the callback
 * @param msg the message
 * @return GNUNET_OK if the message was well-formed
 */
static int
process_pi_message (struct GNUNET_ATS_PerformanceHandle *ph,
                    const struct GNUNET_MessageHeader *msg)
{
  const struct PeerInformationMessage *pi;
  const struct GNUNET_ATS_Information *atsi;
  const char *plugin_address;
  const char *plugin_name;
  struct GNUNET_HELLO_Address address;
  uint16_t plugin_address_length;
  uint16_t plugin_name_length;
  uint32_t ats_count;

  if (ph->infocb == NULL)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (msg->size) < sizeof (struct PeerInformationMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  pi = (const struct PeerInformationMessage *) msg;
  ats_count = ntohl (pi->ats_count);
  plugin_address_length = ntohs (pi->address_length);
  plugin_name_length = ntohs (pi->plugin_name_length);
  atsi = (const struct GNUNET_ATS_Information *) &pi[1];
  plugin_address = (const char *) &atsi[ats_count];
  plugin_name = &plugin_address[plugin_address_length];
  if ((plugin_address_length + plugin_name_length +
       ats_count * sizeof (struct GNUNET_ATS_Information) +
       sizeof (struct PeerInformationMessage) != ntohs (msg->size)) ||
      (ats_count >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information))
      || (plugin_name[plugin_name_length - 1] != '\0'))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  address.peer = pi->peer;
  address.address = plugin_address;
  address.address_length = plugin_address_length;
  address.transport_name = plugin_name;
  ph->infocb (ph->infocb_cls, &address, pi->bandwidth_out, pi->bandwidth_in,
              atsi, ats_count);
  return GNUNET_OK;
}


/**
 * We received a reservation result message.  Validate and process it.
 *
 * @param ph our context with the callback
 * @param msg the message
 * @return GNUNET_OK if the message was well-formed
 */
static int
process_rr_message (struct GNUNET_ATS_PerformanceHandle *ph,
                    const struct GNUNET_MessageHeader *msg)
{
  const struct ReservationResultMessage *rr;
  struct GNUNET_ATS_ReservationContext *rc;
  int32_t amount;

  if (ntohs (msg->size) < sizeof (struct ReservationResultMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  rr = (const struct ReservationResultMessage *) msg;
  amount = ntohl (rr->amount);
  rc = ph->reservation_head;
  if (0 != memcmp (&rr->peer, &rc->peer, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_DLL_remove (ph->reservation_head, ph->reservation_tail, rc);
  if ((amount == 0) || (rc->rcb != NULL))
  {
    /* tell client if not cancelled */
    if (rc->rcb != NULL)
      rc->rcb (rc->rcb_cls, &rr->peer, amount,
               GNUNET_TIME_relative_ntoh (rr->res_delay));
    GNUNET_free (rc);
    return GNUNET_OK;
  }
  /* amount non-zero, but client cancelled, consider undo! */
  if (GNUNET_YES != rc->undo)
  {
    GNUNET_free (rc);
    return GNUNET_OK;           /* do not try to undo failed undos or negative amounts */
  }
  GNUNET_free (rc);
  (void) GNUNET_ATS_reserve_bandwidth (ph, &rr->peer, -amount, NULL, NULL);
  return GNUNET_OK;
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_ats_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;

  if (NULL == msg)
    goto reconnect;
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_ATS_PEER_INFORMATION:
    if (GNUNET_OK != process_pi_message (ph, msg))
      goto reconnect;
    break;
  case GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT:
    if (GNUNET_OK != process_rr_message (ph, msg))
      goto reconnect;
    break;
  default:
    GNUNET_break (0);
    goto reconnect;
  }
  GNUNET_CLIENT_receive (ph->client, &process_ats_message, ph,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return;
reconnect:
  GNUNET_CLIENT_disconnect (ph->client);
  ph->client = NULL;
  ph->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &reconnect_task,
                                    ph);
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param ph handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_PerformanceHandle *ph)
{
  struct PendingMessage *p;
  struct ClientStartMessage *init;

  GNUNET_assert (NULL == ph->client);
  ph->client = GNUNET_CLIENT_connect ("ats", ph->cfg);
  GNUNET_assert (NULL != ph->client);
  GNUNET_CLIENT_receive (ph->client, &process_ats_message, ph,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  if ((NULL == (p = ph->pending_head)) || (GNUNET_YES != p->is_init))
  {
    p = GNUNET_malloc (sizeof (struct PendingMessage) +
                       sizeof (struct ClientStartMessage));
    p->size = sizeof (struct ClientStartMessage);
    p->is_init = GNUNET_YES;
    init = (struct ClientStartMessage *) &p[1];
    init->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_START);
    init->header.size = htons (sizeof (struct ClientStartMessage));
    init->start_flag =
        htonl ((ph->infocb ==
                NULL) ? START_FLAG_PERFORMANCE_NO_PIC :
               START_FLAG_PERFORMANCE_WITH_PIC);
    GNUNET_CONTAINER_DLL_insert (ph->pending_head, ph->pending_tail, p);
  }
  do_transmit (ph);
}



/**
 * Get handle to access performance API of the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param infocb function to call on allocation changes, can be NULL
 * @param infocb_cls closure for infocb
 * @return ats performance context
 */
struct GNUNET_ATS_PerformanceHandle *
GNUNET_ATS_performance_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             GNUNET_ATS_PeerInformationCallback infocb,
                             void *infocb_cls)
{
  struct GNUNET_ATS_PerformanceHandle *ph;

  ph = GNUNET_malloc (sizeof (struct GNUNET_ATS_PerformanceHandle));
  ph->cfg = cfg;
  ph->infocb = infocb;
  ph->infocb_cls = infocb_cls;
  reconnect (ph);
  return ph;
}


/**
 * Client is done using the ATS performance subsystem, release resources.
 *
 * @param ph handle
 */
void
GNUNET_ATS_performance_done (struct GNUNET_ATS_PerformanceHandle *ph)
{
  struct PendingMessage *p;
  struct GNUNET_ATS_ReservationContext *rc;

  while (NULL != (p = ph->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->pending_head, ph->pending_tail, p);
    GNUNET_free (p);
  }
  while (NULL != (rc = ph->reservation_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->reservation_head, ph->reservation_tail,
                                 rc);
    GNUNET_break (NULL == rc->rcb);
    GNUNET_free (rc);
  }
  if (GNUNET_SCHEDULER_NO_TASK != ph->task)
  {
    GNUNET_SCHEDULER_cancel (ph->task);
    ph->task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != ph->client)
  {
    GNUNET_CLIENT_disconnect (ph->client);
    ph->client = NULL;
  }
  GNUNET_free (ph);
}


/**
 * Reserve inbound bandwidth from the given peer.  ATS will look at
 * the current amount of traffic we receive from the peer and ensure
 * that the peer could add 'amount' of data to its stream.
 *
 * @param ph performance handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param rcb function to call with the resulting reservation information
 * @param rcb_cls closure for info
 * @return NULL on error
 * @deprecated will be replaced soon
 */
struct GNUNET_ATS_ReservationContext *
GNUNET_ATS_reserve_bandwidth (struct GNUNET_ATS_PerformanceHandle *ph,
                              const struct GNUNET_PeerIdentity *peer,
                              int32_t amount,
                              GNUNET_ATS_ReservationCallback rcb, void *rcb_cls)
{
  struct GNUNET_ATS_ReservationContext *rc;
  struct PendingMessage *p;
  struct ReservationRequestMessage *m;

  rc = GNUNET_malloc (sizeof (struct GNUNET_ATS_ReservationContext));
  rc->size = amount;
  rc->peer = *peer;
  rc->rcb = rcb;
  rc->rcb_cls = rcb_cls;
  if ((rcb != NULL) && (amount > 0))
    rc->undo = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert_tail (ph->reservation_head, ph->reservation_tail,
                                    rc);

  p = GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct ReservationRequestMessage));
  p->size = sizeof (struct ReservationRequestMessage);
  p->is_init = GNUNET_NO;
  m = (struct ReservationRequestMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST);
  m->header.size = htons (sizeof (struct ReservationRequestMessage));
  m->amount = htonl (amount);
  m->peer = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (ph->pending_head, ph->pending_tail, p);
  do_transmit (ph);
  return rc;
}


/**
 * Cancel request for reserving bandwidth.
 *
 * @param rc context returned by the original GNUNET_ATS_reserve_bandwidth call
 */
void
GNUNET_ATS_reserve_bandwidth_cancel (struct GNUNET_ATS_ReservationContext *rc)
{
  rc->rcb = NULL;
}


/**
 * Change preferences for the given peer. Preference changes are forgotten if peers
 * disconnect.
 *
 * @param ph performance handle
 * @param peer identifies the peer
 * @param ... 0-terminated specification of the desired changes
 */
void
GNUNET_ATS_change_preference (struct GNUNET_ATS_PerformanceHandle *ph,
                              const struct GNUNET_PeerIdentity *peer, ...)
{
  struct PendingMessage *p;
  struct ChangePreferenceMessage *m;
  size_t msize;
  uint32_t count;
  struct PreferenceInformation *pi;
  va_list ap;
  enum GNUNET_ATS_PreferenceKind kind;

  count = 0;
  va_start (ap, peer);
  while (GNUNET_ATS_PREFERENCE_END !=
         (kind = va_arg (ap, enum GNUNET_ATS_PreferenceKind)))
  {
    switch (kind)
    {
    case GNUNET_ATS_PREFERENCE_BANDWIDTH:
      count++;
      (void) va_arg (ap, double);

      break;
    case GNUNET_ATS_PREFERENCE_LATENCY:
      count++;
      (void) va_arg (ap, double);

      break;
    default:
      GNUNET_assert (0);
    }
  }
  va_end (ap);
  msize =
      count * sizeof (struct PreferenceInformation) +
      sizeof (struct ChangePreferenceMessage);
  p = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct ChangePreferenceMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE);
  m->header.size = htons (msize);
  m->num_preferences = htonl (count);
  m->peer = *peer;
  pi = (struct PreferenceInformation *) &m[1];
  count = 0;
  va_start (ap, peer);
  while (GNUNET_ATS_PREFERENCE_END !=
         (kind = va_arg (ap, enum GNUNET_ATS_PreferenceKind)))
  {
    pi[count].preference_kind = htonl (kind);
    switch (kind)
    {
    case GNUNET_ATS_PREFERENCE_BANDWIDTH:
      pi[count].preference_value = (float) va_arg (ap, double);

      count++;
      break;
    case GNUNET_ATS_PREFERENCE_LATENCY:
      pi[count].preference_value = (float) va_arg (ap, double);

      count++;
      break;
    default:
      GNUNET_assert (0);
    }
  }
  va_end (ap);
  GNUNET_CONTAINER_DLL_insert_tail (ph->pending_head, ph->pending_tail, p);
  do_transmit (ph);
}

/* end of ats_api_performance.c */
