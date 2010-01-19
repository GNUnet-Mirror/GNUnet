/*
     This file is part of GNUnet
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/plugin_transport.h
 * @brief API for the transport services.  This header
 *        specifies the struct that is given to the plugin's entry
 *        method and the other struct that must be returned.
 *        Note that the destructors of transport plugins will
 *        be given the value returned by the constructor
 *        and is expected to return a NULL pointer.
 *
 * TODO:
 * - consider moving DATA message (latency measurement)
 *   to service; avoids encapsulation overheads and
 *   would enable latency measurements for non-bidi
 *   transports.
 * -
 *
 * @author Christian Grothoff
 */
#ifndef PLUGIN_TRANSPORT_H
#define PLUGIN_TRANSPORT_H

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_transport_service.h"

/**
 * Function called by the transport for each received message.
 * This function should also be called with "NULL" for the
 * message to signal that the other peer disconnected.
 *
 * @param cls closure
 * @param latency estimated latency for communicating with the
 *        given peer; should be set to GNUNET_TIME_UNIT_FOREVER_REL
 *        until the transport has seen messages transmitted in
 *        BOTH directions (and hence been able to do an actual
 *        round-trip observation); a non-FOREVER latency is also used
 *        by the transport to know that communication in both directions
 *        using this one plugin actually works
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if peer was disconnected
 */
typedef void (*GNUNET_TRANSPORT_PluginReceiveCallback) (void *cls,
                                                        struct
                                                        GNUNET_TIME_Relative
                                                        latency,
                                                        const struct
                                                        GNUNET_PeerIdentity *
                                                        peer,
                                                        const struct
                                                        GNUNET_MessageHeader *
                                                        message);


/**
 * Function that will be called if we receive a validation
 * of an address challenge that we transmitted to another
 * peer.  Note that the validation should only be considered
 * acceptable if the challenge matches AND if the sender
 * address is at least a plausible address for this peer
 * (otherwise we may be seeing a MiM attack).
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param peer who responded to our challenge
 * @param challenge the challenge number we presumably used
 * @param sender_addr string describing our sender address (as observed
 *         by the other peer in human-readable format)
 */
typedef void (*GNUNET_TRANSPORT_ValidationNotification) (void *cls,
                                                         const char *name,
                                                         const struct
                                                         GNUNET_PeerIdentity *
                                                         peer,
                                                         uint32_t challenge,
                                                         const char
                                                         *sender_addr);



/**
 * Function that will be called for each address the transport
 * is aware that it might be reachable under.
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param expires when should this address automatically expire?
 */
typedef void (*GNUNET_TRANSPORT_AddressNotification) (void *cls,
                                                      const char *name,
                                                      const void *addr,
                                                      size_t addrlen,
                                                      struct
                                                      GNUNET_TIME_Relative
                                                      expires);


/**
 * Function that will be called for each address obtained from the HELLO.
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 */
typedef void (*GNUNET_TRANSPORT_AddressCallback) (void *cls,
                                                  const char *name,
                                                  const void *addr,
                                                  size_t addrlen);


/**
 * The transport service will pass a pointer to a struct
 * of this type as the first and only argument to the
 * entry point of each transport plugin.
 */
struct GNUNET_TRANSPORT_PluginEnvironment
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Scheduler to use.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Our public key.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *my_public_key;

  /**
   * Our private key.
   */
  struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

  /**
   * Identity of this peer.
   */
  const struct GNUNET_PeerIdentity *my_identity;

  /**
   * Closure for the various callbacks.
   */
  void *cls;

  /**
   * Function that should be called by the transport plugin
   * whenever a message is received.
   */
  GNUNET_TRANSPORT_PluginReceiveCallback receive;

  /**
   * Function that must be called by each plugin to notify the
   * transport service about the addresses under which the transport
   * provided by the plugin can be reached.
   */
  GNUNET_TRANSPORT_AddressNotification notify_address;

  /**
   * Function that must be called by each plugin to notify the
   * transport service about a successful validation of an
   * address of another peer (or at least likely successful
   * validation).
   */
  GNUNET_TRANSPORT_ValidationNotification notify_validation;

  /**
   * What is the default quota (in terms of incoming bytes per
   * ms) for new connections?
   */
  uint32_t default_quota_in;

  /**
   * What is the maximum number of connections that this transport
   * should allow?  Transports that do not have sessions (such as
   * UDP) can ignore this value.
   */
  uint32_t max_connections;

};


/**
 * Function that can be used by the transport service to validate
 * the address of another peer.  Even if
 * we already have a connection to this peer, this function is
 * required to establish a new one.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param challenge challenge code to use
 * @param timeout how long should we try to transmit these?
 * @param addrlen length of the address
 * @param addr the address
 * @return GNUNET_OK on success, GNUNET_SYSERR if the address
 *         format is invalid
 */
typedef int
  (*GNUNET_TRANSPORT_ValidationFunction) (void *cls,
                                          const struct
                                          GNUNET_PeerIdentity * target,
                                          uint32_t challenge,
                                          struct GNUNET_TIME_Relative
                                          timeout, const void *addr,
                                          size_t addrlen);

/**
 * Function called by the GNUNET_TRANSPORT_TransmitFunction
 * upon "completion".
 *
 * @param cls closure
 * @param target who was the recipient of the message?
 * @param result GNUNET_OK on success
 *               GNUNET_SYSERR if the target disconnected;
 *               disconnect will ALSO be signalled using
 *               the ReceiveCallback.
 */
typedef void
  (*GNUNET_TRANSPORT_TransmitContinuation) (void *cls,
                                            const struct GNUNET_PeerIdentity *
                                            target, int result);


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param priority how important is the message?
 * @param msg the message to transmit
 * @param timeout how long to wait at most for the transmission
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 */
typedef void
  (*GNUNET_TRANSPORT_TransmitFunction) (void *cls,
                                        const struct GNUNET_PeerIdentity *
                                        target,
                                        unsigned int priority,
                                        const struct GNUNET_MessageHeader *
                                        msg,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_TRANSPORT_TransmitContinuation
                                        cont, void *cont_cls);


/**
 * Function that can be called to force a disconnect from the
 * specified neighbour.  This should also cancel all previously
 * scheduled transmissions.  Obviously the transmission may have been
 * partially completed already, which is OK.  The plugin is supposed
 * to close the connection (if applicable) and no longer call the
 * transmit continuation(s).
 *
 * Finally, plugin MUST NOT call the services's receive function to
 * notify the service that the connection to the specified target was
 * closed after a getting this call.
 *
 * @param cls closure
 * @param target peer for which the last transmission is
 *        to be cancelled
 */
typedef void
  (*GNUNET_TRANSPORT_DisconnectFunction) (void *cls,
                                          const struct GNUNET_PeerIdentity *
                                          target);


/**
 * Function called by the pretty printer for the resolved address for
 * each human-readable address obtained.
 *
 * @param cls closure
 * @param hostname one of the names for the host, NULL
 *        on the last call to the callback
 */
typedef void (*GNUNET_TRANSPORT_AddressStringCallback) (void *cls,
                                                        const char *address);


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param name name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
typedef void
  (*GNUNET_TRANSPORT_AddressPrettyPrinter) (void *cls,
                                            const char *type,
                                            const void *addr,
                                            size_t addrlen,
                                            int numeric,
                                            struct GNUNET_TIME_Relative
                                            timeout,
                                            GNUNET_TRANSPORT_AddressStringCallback
                                            asc, void *asc_cls);


/**
 * Set a quota for receiving data from the given peer; this is a
 * per-transport limit.  The transport should limit its read/select
 * calls to stay below the quota (in terms of incoming data).
 *
 * @param cls closure
 * @param peer the peer for whom the quota is given
 * @param quota_in quota for receiving/sending data in bytes per ms
 */
typedef void
  (*GNUNET_TRANSPORT_SetQuota) (void *cls,
                                const struct GNUNET_PeerIdentity * target,
                                uint32_t quota_in);


/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
typedef int
  (*GNUNET_TRANSPORT_SuggestAddress) (void *cls,
                                      const void *addr, size_t addrlen);

/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_TRANSPORT_PluginFunctions
{

  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Function used to send a single message to a particular
   * peer using the specified address.  Used to validate
   * HELLOs.
   */
  GNUNET_TRANSPORT_ValidationFunction validate;

  /**
   * Function that the transport service will use to transmit data to
   * another peer.  May be null for plugins that only support
   * receiving data.  After this call, the plugin call the specified
   * continuation with success or error before notifying us about the
   * target having disconnected.
   */
  GNUNET_TRANSPORT_TransmitFunction send;

  /**
   * Function that can be used to force the plugin to disconnect from
   * the given peer and cancel all previous transmissions (and their
   * continuations).  Note that if the transport does not have
   * sessions / persistent connections (for example, UDP), this
   * function may very well do nothing.
   */
  GNUNET_TRANSPORT_DisconnectFunction disconnect;

  /**
   * Function to pretty-print addresses.  NOTE: this function is not
   * yet used by transport-service, but will be used in the future
   * once the transport-API has been completed.
   */
  GNUNET_TRANSPORT_AddressPrettyPrinter address_pretty_printer;

  /**
   * Function that the transport service can use to try to enforce a
   * quota for the number of bytes received via this transport.
   * Transports that can not refuse incoming data (such as UDP)
   * are free to ignore these calls.
   */
  GNUNET_TRANSPORT_SetQuota set_receive_quota;

  /**
   * Function that will be called if another peer suggested that
   * we should use a particular address (since he is reaching
   * us at that address) for this transport.
   */
  GNUNET_TRANSPORT_SuggestAddress address_suggested;

  /**
   * Relative cost of this transport compared to others.  This
   * is supposed to be a static cost estimate which determines
   * which plugins should not even be attempted if other,
   * cheaper transports are already working.  The idea is that
   * the costs have roughly this relationship:
   * <pre>
   * TCP < UDP < HTTP == HTTPS < SMTP
   * </pre>
   */
  unsigned int cost_estimate;
};


#endif
