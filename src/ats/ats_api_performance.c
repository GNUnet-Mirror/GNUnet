/*
  This file is part of GNUnet.
  Copyright (C) 2010, 2011, 2016 GNUnet e.V.

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
 * @file ats/ats_api_performance.c
 * @brief automatic transport selection and outbound bandwidth determination
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"


#define LOG(kind,...) GNUNET_log_from(kind, "ats-performance-api", __VA_ARGS__)


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
   * Closure for @e rcb
   */
  void *rcb_cls;

  /**
   * Do we need to undo this reservation if it succeeded?  Set to
   * #GNUNET_YES if a reservation is cancelled.  (at that point, 'info'
   * is also set to NULL; however, info will ALSO be NULL for the
   * reservation context that is created to undo the original request,
   * so 'info' being NULL cannot be used to check if undo is
   * required).
   */
  int undo;
};


/**
 * Linked list of pending reservations.
 */
struct GNUNET_ATS_AddressListHandle
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_ATS_AddressListHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_ATS_AddressListHandle *prev;

  /**
   * Performance handle
   */
  struct GNUNET_ATS_PerformanceHandle *ph;

  /**
   * Callback
   */
  GNUNET_ATS_AddressInformationCallback cb;

  /**
   * Callback closure for @e cb
   */
  void *cb_cls;

  /**
   * Target peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Return all or specific peer only
   */
  int all_peers;

  /**
   * Return all or used address only
   */
  int all_addresses;

  /**
   * Request multiplexing
   */
  uint32_t id;
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
   * Callback to invoke when an address has performance changes.
   */
  GNUNET_ATS_AddressInformationCallback addr_info_cb;

  /**
   * Closure for @e addr_info_cb.
   */
  void *addr_info_cb_cls;

  /**
   * Connection to ATS service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of linked list of pending reservation requests.
   */
  struct GNUNET_ATS_ReservationContext *reservation_head;

  /**
   * Tail of linked list of pending reservation requests.
   */
  struct GNUNET_ATS_ReservationContext *reservation_tail;

  /**
   * Head of linked list of pending address list requests.
   */
  struct GNUNET_ATS_AddressListHandle *addresslist_head;

  /**
   * Tail of linked list of pending address list requests.
   */
  struct GNUNET_ATS_AddressListHandle *addresslist_tail;

  /**
   * Current request for transmission to ATS.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task to trigger reconnect.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Reconnect backoff delay.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Monitor request multiplexing
   */
  uint32_t monitor_id;

  /**
   * Request multiplexing
   */
  uint32_t id;

  /**
   * Is the receive loop active?
   */
  int in_receive;
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
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;

  ph->task = NULL;
  reconnect (ph);
}


/**
 * Reconnect to the ATS service, something went wrong.
 *
 * @param ph handle to reconnect
 */
static void
do_reconnect (struct GNUNET_ATS_PerformanceHandle *ph)
{
  struct GNUNET_ATS_ReservationContext *rc;
  struct GNUNET_ATS_AddressListHandle *alh;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_zero;

  if (NULL != ph->mq)
  {
    GNUNET_MQ_destroy (ph->mq);
    ph->mq = NULL;
  }
  while (NULL != (rc = ph->reservation_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->reservation_head,
                                 ph->reservation_tail,
                                 rc);
    if (NULL != rc->rcb)
      rc->rcb (rc->rcb_cls,
               NULL,
               0,
               GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (rc);
  }
  bandwidth_zero.value__ = htonl (0);
  while (NULL != (alh = ph->addresslist_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->addresslist_head,
                                 ph->addresslist_tail,
                                 alh);
    if (NULL != alh->cb)
      alh->cb (alh->cb_cls,
               NULL,
               GNUNET_NO,
               bandwidth_zero,
               bandwidth_zero,
               NULL);
    GNUNET_free (alh);
  }
  if (NULL != ph->addr_info_cb)
  {
    /* Indicate reconnect */
    ph->addr_info_cb (ph->addr_info_cb_cls,
                      NULL,
                      GNUNET_NO,
                      bandwidth_zero,
                      bandwidth_zero,
                      NULL);
  }
  ph->backoff = GNUNET_TIME_STD_BACKOFF (ph->backoff);
  ph->task = GNUNET_SCHEDULER_add_delayed (ph->backoff,
                                           &reconnect_task,
                                           ph);
}


/**
 * We received a peer information message.  Validate and process it.
 *
 * @param cls our context with the callback
 * @param pi the message
 * @return #GNUNET_OK if the message was well-formed
 */
static int
check_peer_information (void *cls,
                        const struct PeerInformationMessage *pi)
{
  const char *plugin_address;
  const char *plugin_name;
  uint16_t plugin_address_length;
  uint16_t plugin_name_length;

  plugin_address_length = ntohs (pi->address_length);
  plugin_name_length = ntohs (pi->plugin_name_length);
  plugin_address = (const char *) &pi[1];
  plugin_name = &plugin_address[plugin_address_length];
  if ( (plugin_address_length + plugin_name_length
        + sizeof(struct PeerInformationMessage) != ntohs (pi->header.size)) ||
       (plugin_name[plugin_name_length - 1] != '\0'))
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We received a peer information message.  Validate and process it.
 *
 * @param cls our context with the callback
 * @param pi the message
 * @return #GNUNET_OK if the message was well-formed
 */
static void
handle_peer_information (void *cls,
                         const struct PeerInformationMessage *pi)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;
  const char *plugin_address;
  const char *plugin_name;
  struct GNUNET_HELLO_Address address;
  uint16_t plugin_address_length;
  int addr_active;
  struct GNUNET_ATS_Properties prop;

  if (NULL == ph->addr_info_cb)
    return;
  plugin_address_length = ntohs (pi->address_length);
  addr_active = (int) ntohl (pi->address_active);
  plugin_address = (const char *) &pi[1];
  plugin_name = &plugin_address[plugin_address_length];

  GNUNET_ATS_properties_ntoh (&prop,
                              &pi->properties);
  address.peer = pi->peer;
  address.local_info = (enum GNUNET_HELLO_AddressInfo) ntohl (pi->address_local_info);
  address.address = plugin_address;
  address.address_length = plugin_address_length;
  address.transport_name = plugin_name;
  ph->addr_info_cb (ph->addr_info_cb_cls,
                    &address,
                    addr_active,
                    pi->bandwidth_out,
                    pi->bandwidth_in,
                    &prop);
}


/**
 * We received a reservation result message.  Validate and process it.
 *
 * @param cls our context with the callback
 * @param rr the message
 */
static void
handle_reservation_result (void *cls,
                           const struct ReservationResultMessage *rr)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;
  struct GNUNET_ATS_ReservationContext *rc;
  int32_t amount;

  amount = ntohl (rr->amount);
  rc = ph->reservation_head;
  if (0 != memcmp (&rr->peer,
                   &rc->peer,
                   sizeof(struct GNUNET_PeerIdentity)))
  {
    GNUNET_break(0);
    reconnect (ph);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (ph->reservation_head,
                               ph->reservation_tail,
                               rc);
  if ( (0 == amount) ||
       (NULL != rc->rcb) )
  {
    /* tell client if not cancelled */
    if (NULL != rc->rcb)
      rc->rcb (rc->rcb_cls,
               &rr->peer,
               amount,
               GNUNET_TIME_relative_ntoh (rr->res_delay));
    GNUNET_free (rc);
    return;
  }
  /* amount non-zero, but client cancelled, consider undo! */
  if (GNUNET_YES != rc->undo)
  {
    GNUNET_free (rc);
    return; /* do not try to undo failed undos or negative amounts */
  }
  GNUNET_free (rc);
  (void) GNUNET_ATS_reserve_bandwidth (ph,
                                       &rr->peer,
                                       -amount,
                                       NULL, NULL);
}


/**
 * We received a PeerInformationMessage.  Validate it.
 *
 * @param cls our context with the callback
 * @param pi the message
 * @return #GNUNET_OK if the message was well-formed
 */
static int
check_address_list (void *cls,
                    const struct PeerInformationMessage *pi)
{
  const char *plugin_address;
  const char *plugin_name;
  uint16_t plugin_address_length;
  uint16_t plugin_name_length;

  plugin_address_length = ntohs (pi->address_length);
  plugin_name_length = ntohs (pi->plugin_name_length);
  plugin_address = (const char *) &pi[1];
  plugin_name = &plugin_address[plugin_address_length];
  if ( (plugin_address_length + plugin_name_length
        + sizeof (struct PeerInformationMessage) != ntohs (pi->header.size)) ||
       (plugin_name[plugin_name_length - 1] != '\0') )
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We received a #GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE.
 * Process it.
 *
 * @param cls our context with the callback
 * @param pi the message
 */
static void
handle_address_list (void *cls,
                     const struct PeerInformationMessage *pi)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;
  struct GNUNET_ATS_AddressListHandle *alh;
  struct GNUNET_ATS_AddressListHandle *next;
  const char *plugin_address;
  const char *plugin_name;
  struct GNUNET_HELLO_Address address;
  struct GNUNET_PeerIdentity allzeros;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_zero;
  struct GNUNET_ATS_Properties prop;
  uint16_t plugin_address_length;
  uint16_t plugin_name_length;
  uint32_t active;
  uint32_t id;

  id = ntohl (pi->id);
  active = ntohl (pi->address_active);
  plugin_address_length = ntohs (pi->address_length);
  plugin_name_length = ntohs (pi->plugin_name_length);
  plugin_address = (const char *) &pi[1];
  plugin_name = &plugin_address[plugin_address_length];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received ATS_ADDRESSLIST_RESPONSE message for peer %s and plugin %s\n",
       GNUNET_i2s (&pi->peer),
       plugin_name);

  next = ph->addresslist_head;
  while (NULL != (alh = next))
  {
    next = alh->next;
    if (alh->id == id)
      break;
  }
  if (NULL == alh)
    return; /* was canceled */

  memset (&allzeros, '\0', sizeof (allzeros));
  if ( (0 == memcmp (&allzeros, &pi->peer, sizeof(allzeros))) &&
       (0 == plugin_name_length) &&
       (0 == plugin_address_length) )
  {
    /* Done */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received last message for ATS_ADDRESSLIST_RESPONSE\n");
    bandwidth_zero.value__ = htonl (0);
    GNUNET_CONTAINER_DLL_remove (ph->addresslist_head,
                                 ph->addresslist_tail,
                                 alh);
    if (NULL != alh->cb)
      alh->cb (alh->cb_cls,
               NULL,
               GNUNET_NO,
               bandwidth_zero,
               bandwidth_zero,
               NULL);
    GNUNET_free (alh);
    return;
  }

  address.peer = pi->peer;
  address.address = plugin_address;
  address.address_length = plugin_address_length;
  address.transport_name = plugin_name;
  if ( ( (GNUNET_YES == alh->all_addresses) ||
         (GNUNET_YES == active) ) &&
       (NULL != alh->cb) )
  {
    GNUNET_ATS_properties_ntoh (&prop,
                                &pi->properties);
    alh->cb (alh->cb_cls,
             &address,
             active,
             pi->bandwidth_out,
             pi->bandwidth_in,
             &prop);
  }
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_ATS_PerformanceHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_ATS_PerformanceHandle *ph = cls;

  do_reconnect (ph);
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param ph handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_PerformanceHandle *ph)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (peer_information,
                           GNUNET_MESSAGE_TYPE_ATS_PEER_INFORMATION,
                           struct PeerInformationMessage,
                           ph),
    GNUNET_MQ_hd_fixed_size (reservation_result,
                             GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT,
                             struct ReservationResultMessage,
                             ph),
    GNUNET_MQ_hd_var_size (address_list,
                           GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE,
                           struct PeerInformationMessage,
                           ph),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct ClientStartMessage *init;

  GNUNET_assert (NULL == ph->mq);
  ph->mq = GNUNET_CLIENT_connect (ph->cfg,
                                  "ats",
                                  handlers,
                                  &mq_error_handler,
                                  ph);
  if (NULL == ph->mq)
    return;
  env = GNUNET_MQ_msg (init,
                       GNUNET_MESSAGE_TYPE_ATS_START);
  init->start_flag = htonl ( (NULL == ph->addr_info_cb)
                             ? START_FLAG_PERFORMANCE_NO_PIC
                             : START_FLAG_PERFORMANCE_WITH_PIC);
  GNUNET_MQ_send (ph->mq,
                  env);
}


/**
 * Get handle to access performance API of the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param addr_info_cb callback called when performance characteristics for
 * 	an address change
 * @param addr_info_cb_cls closure for @a addr_info_cb
 * @return ats performance context
 */
struct GNUNET_ATS_PerformanceHandle *
GNUNET_ATS_performance_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             GNUNET_ATS_AddressInformationCallback addr_info_cb,
                             void *addr_info_cb_cls)
{
  struct GNUNET_ATS_PerformanceHandle *ph;

  ph = GNUNET_new (struct GNUNET_ATS_PerformanceHandle);
  ph->cfg = cfg;
  ph->addr_info_cb = addr_info_cb;
  ph->addr_info_cb_cls = addr_info_cb_cls;
  reconnect (ph);
  if (NULL == ph->mq)
  {
    GNUNET_free (ph);
    return NULL;
  }
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
  struct GNUNET_ATS_ReservationContext *rc;
  struct GNUNET_ATS_AddressListHandle *alh;

  while (NULL != (alh = ph->addresslist_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->addresslist_head,
                                 ph->addresslist_tail,
                                 alh);
    GNUNET_free (alh);
  }
  while (NULL != (rc = ph->reservation_head))
  {
    GNUNET_CONTAINER_DLL_remove (ph->reservation_head,
                                 ph->reservation_tail,
                                 rc);
    GNUNET_break (NULL == rc->rcb);
    GNUNET_free (rc);
  }
  if (NULL != ph->task)
  {
    GNUNET_SCHEDULER_cancel (ph->task);
    ph->task = NULL;
  }
  if (NULL != ph->mq)
  {
    GNUNET_MQ_destroy (ph->mq);
    ph->mq = NULL;
  }
  GNUNET_free (ph);
}


/**
 * Reserve inbound bandwidth from the given peer.  ATS will look at
 * the current amount of traffic we receive from the peer and ensure
 * that the peer could add @a amount of data to its stream.
 *
 * @param ph performance handle
 * @param peer identifies the peer
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param rcb function to call with the resulting reservation information
 * @param rcb_cls closure for @a rcb
 * @return NULL on error
 * @deprecated will be replaced soon
 */
struct GNUNET_ATS_ReservationContext *
GNUNET_ATS_reserve_bandwidth (struct GNUNET_ATS_PerformanceHandle *ph,
                              const struct GNUNET_PeerIdentity *peer,
                              int32_t amount,
                              GNUNET_ATS_ReservationCallback rcb,
                              void *rcb_cls)
{
  struct GNUNET_ATS_ReservationContext *rc;
  struct GNUNET_MQ_Envelope *env;
  struct ReservationRequestMessage *m;

  if (NULL == ph->mq)
    return NULL;
  rc = GNUNET_new (struct GNUNET_ATS_ReservationContext);
  rc->size = amount;
  rc->peer = *peer;
  rc->rcb = rcb;
  rc->rcb_cls = rcb_cls;
  if ( (NULL != rcb) &&
       (amount > 0) )
    rc->undo = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert_tail (ph->reservation_head,
                                    ph->reservation_tail,
                                    rc);
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST);
  m->amount = htonl (amount);
  m->peer = *peer;
  GNUNET_MQ_send (ph->mq,
                  env);
  return rc;
}


/**
 * Cancel request for reserving bandwidth.
 *
 * @param rc context returned by the original #GNUNET_ATS_reserve_bandwidth() call
 */
void
GNUNET_ATS_reserve_bandwidth_cancel (struct GNUNET_ATS_ReservationContext *rc)
{
  rc->rcb = NULL;
}


/**
 * Get information about addresses known to the ATS subsystem.
 *
 * @param ph the performance handle to use
 * @param peer peer idm can be NULL for all peers
 * @param all #GNUNET_YES to get information about all addresses or #GNUNET_NO to
 *        get only address currently used
 * @param infocb callback to call with the addresses,
 *        will callback with address == NULL when done
 * @param infocb_cls closure for @a infocb
 * @return ats performance context
 */
struct GNUNET_ATS_AddressListHandle*
GNUNET_ATS_performance_list_addresses (struct GNUNET_ATS_PerformanceHandle *ph,
                                       const struct GNUNET_PeerIdentity *peer,
                                       int all,
                                       GNUNET_ATS_AddressInformationCallback infocb,
                                       void *infocb_cls)
{
  struct GNUNET_ATS_AddressListHandle *alh;
  struct GNUNET_MQ_Envelope *env;
  struct AddressListRequestMessage *m;

  if (NULL == ph->mq)
    return NULL;
  if (NULL == infocb)
  {
    GNUNET_break (0);
    return NULL;
  }
  alh = GNUNET_new (struct GNUNET_ATS_AddressListHandle);
  alh->id = ph->id++;
  alh->cb = infocb;
  alh->cb_cls = infocb_cls;
  alh->ph = ph;
  alh->all_addresses = all;
  if (NULL == peer)
  {
    alh->all_peers = GNUNET_YES;
  }
  else
  {
    alh->all_peers = GNUNET_NO;
    alh->peer = *peer;
  }
  GNUNET_CONTAINER_DLL_insert (ph->addresslist_head,
                               ph->addresslist_tail,
                               alh);
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_REQUEST);
  m->all = htonl (all);
  m->id = htonl (alh->id);
  if (NULL != peer)
    m->peer = *peer;
  GNUNET_MQ_send (ph->mq,
                  env);
  return alh;
}


/**
 * Cancel a pending address listing operation
 *
 * @param alh the handle of the request to cancel
 */
void
GNUNET_ATS_performance_list_addresses_cancel (struct GNUNET_ATS_AddressListHandle *alh)
{
  struct GNUNET_ATS_PerformanceHandle *ph = alh->ph;

  GNUNET_CONTAINER_DLL_remove (ph->addresslist_head,
                               ph->addresslist_tail,
                               alh);
  GNUNET_free (alh);
}


/**
 * Convert a `enum GNUNET_ATS_PreferenceType` to a string
 *
 * @param type the preference type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_ATS_print_preference_type (uint32_t type)
{
  const char *prefs[] = GNUNET_ATS_PreferenceTypeString;

  if (type < GNUNET_ATS_PREFERENCE_END)
    return prefs[type];
  return NULL;
}


/**
 * Change preferences for the given peer. Preference changes are forgotten if peers
 * disconnect.
 *
 * @param ph performance handle
 * @param peer identifies the peer
 * @param ... #GNUNET_ATS_PREFERENCE_END-terminated specification of the desired changes
 */
void
GNUNET_ATS_performance_change_preference (struct GNUNET_ATS_PerformanceHandle *ph,
                                          const struct GNUNET_PeerIdentity *peer,
                                          ...)
{
  struct GNUNET_MQ_Envelope *env;
  struct ChangePreferenceMessage *m;
  uint32_t count;
  struct PreferenceInformation *pi;
  va_list ap;
  enum GNUNET_ATS_PreferenceKind kind;

  if (NULL == ph->mq)
    return;
  count = 0;
  va_start(ap, peer);
  while (GNUNET_ATS_PREFERENCE_END !=
         (kind = va_arg (ap, enum GNUNET_ATS_PreferenceKind) ))
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
      GNUNET_assert(0);
    }
  }
  va_end(ap);
  env = GNUNET_MQ_msg_extra (m,
                             count * sizeof(struct PreferenceInformation),
                             GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE);
  m->num_preferences = htonl (count);
  m->peer = *peer;
  pi = (struct PreferenceInformation *) &m[1];
  count = 0;
  va_start(ap, peer);
  while (GNUNET_ATS_PREFERENCE_END != (kind =
      va_arg (ap, enum GNUNET_ATS_PreferenceKind) ))
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
      GNUNET_assert(0);
    }
  }
  va_end(ap);
  GNUNET_MQ_send (ph->mq,
                  env);
}


/**
 * Send feedback to ATS on how good a the requirements for a peer and a
 * preference is satisfied by ATS
 *
 * @param ph performance handle
 * @param scope the time interval this valid for: [now - scope .. now]
 * @param peer identifies the peer
 * @param ... #GNUNET_ATS_PREFERENCE_END-terminated specification of the desired changes
 */
void
GNUNET_ATS_performance_give_feedback (struct GNUNET_ATS_PerformanceHandle *ph,
                                      const struct GNUNET_PeerIdentity *peer,
                                      const struct GNUNET_TIME_Relative scope,
                                      ...)
{
  struct GNUNET_MQ_Envelope *env;
  struct FeedbackPreferenceMessage *m;
  uint32_t count;
  struct PreferenceInformation *pi;
  va_list ap;
  enum GNUNET_ATS_PreferenceKind kind;

  if (NULL == ph->mq)
    return;
  count = 0;
  va_start(ap, scope);
  while (GNUNET_ATS_PREFERENCE_END !=
         (kind = va_arg (ap, enum GNUNET_ATS_PreferenceKind) ))
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
      GNUNET_assert(0);
    }
  }
  va_end(ap);
  env = GNUNET_MQ_msg_extra (m,
                             count * sizeof(struct PreferenceInformation),
                             GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_FEEDBACK);
  m->scope = GNUNET_TIME_relative_hton (scope);
  m->num_feedback = htonl (count);
  m->peer = *peer;
  pi = (struct PreferenceInformation *) &m[1];
  count = 0;
  va_start(ap, scope);
  while (GNUNET_ATS_PREFERENCE_END != (kind =
      va_arg (ap, enum GNUNET_ATS_PreferenceKind) ))
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
      GNUNET_assert(0);
    }
  }
  va_end(ap);
  GNUNET_MQ_send (ph->mq,
                  env);
}

/* end of ats_api_performance.c */
