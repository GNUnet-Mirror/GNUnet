/*
     This file is part of GNUnet
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
 * @file include/gnunet_transport_plugin.h
 * @brief API for the transport services.  This header
 *        specifies the struct that is given to the plugin's entry
 *        method and the other struct that must be returned.
 *        Note that the destructors of transport plugins will
 *        be given the value returned by the constructor
 *        and is expected to return a NULL pointer.
 * @author Christian Grothoff
 */
#ifndef PLUGIN_TRANSPORT_H
#define PLUGIN_TRANSPORT_H

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"

/**
 * Opaque pointer that plugins can use to distinguish specific
 * connections to a given peer.  Typically used by stateful plugins to
 * allow the service to refer to specific streams instead of a more
 * general notion of "some connection" to the given peer.  This is
 * useful since sometimes (i.e. for inbound TCP connections) a
 * connection may not have an address that can be used for meaningful
 * distinction between sessions to the same peer.
 */
struct Session;

/**
 * Every 'struct Session' must begin with this header.
 */
struct SessionHeader
{

  /**
   * Cached signature for PONG generation for the session.  Do not use
   * in the plugin!
   */
  struct GNUNET_CRYPTO_RsaSignature pong_signature;

  /**
   * Expiration time for signature.  Do not use in the plugin!
   */
  struct GNUNET_TIME_Absolute pong_sig_expires;

};

/**
 * Function that will be called whenever the plugin internally
 * cleans up a session pointer and hence the service needs to
 * discard all of those sessions as well.  Plugins that do not
 * use sessions can simply omit calling this function and always
 * use NULL wherever a session pointer is needed.  This function
 * should be called BEFORE a potential "TransmitContinuation"
 * from the "TransmitFunction".
 *
 * @param cls closure
 * @param peer which peer was the session for
 * @param session which session is being destoyed
 */
typedef void (*GNUNET_TRANSPORT_SessionEnd) (void *cls,
                                             const struct GNUNET_PeerIdentity *
                                             peer, struct Session * session);


/**
 * Function called by the transport for each received message.
 * This function should also be called with "NULL" for the
 * message to signal that the other peer disconnected.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message, NULL if we only care about
 *                learning about the delay until we should receive again
 * @param session identifier used for this session (NULL for plugins
 *                that do not offer bi-directional communication to the sender
 *                using the same "connection")
 * @param sender_address binary address of the sender (if we established the
 *                connection or are otherwise sure of it; should be NULL
 *                for inbound TCP/UDP connections since it it not clear
 *                that we could establish ourselves a connection to that
 *                IP address and get the same system)
 * @param sender_address_len number of bytes in sender_address
 * @return how long the plugin should wait until receiving more data
 *         (plugins that do not support this, can ignore the return value)
 */
typedef struct
    GNUNET_TIME_Relative (*GNUNET_TRANSPORT_PluginReceiveCallback) (void *cls,
                                                                    const struct
                                                                    GNUNET_PeerIdentity
                                                                    * peer,
                                                                    const struct
                                                                    GNUNET_MessageHeader
                                                                    * message,
                                                                    const struct
                                                                    GNUNET_ATS_Information
                                                                    * ats,
                                                                    uint32_t
                                                                    ats_count,
                                                                    struct
                                                                    Session *
                                                                    session,
                                                                    const char
                                                                    *sender_address,
                                                                    uint16_t
                                                                    sender_address_len);


/**
 * Function that will be called to figure if an address is an loopback,
 * LAN, WAN etc. address
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return ATS Information containing the network type
 */
typedef const struct GNUNET_ATS_Information
(*GNUNET_TRANSPORT_AddressToType) (void *cls,
                                   const struct sockaddr *addr,
                                   size_t addrlen);

/**
 * Function that will be called for each address the transport
 * is aware that it might be reachable under.
 *
 * @param cls closure
 * @param add_remove should the address added (YES) or removed (NO) from the
 *                   set of valid addresses?
 * @param addr one of the addresses of the host
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 */
typedef void (*GNUNET_TRANSPORT_AddressNotification) (void *cls, int add_remove,
                                                      const void *addr,
                                                      size_t addrlen);


/**
 * Function that will be called whenever the plugin receives data over
 * the network and wants to determine how long it should wait until
 * the next time it reads from the given peer.  Note that some plugins
 * (such as UDP) may not be able to wait (for a particular peer), so
 * the waiting part is optional.  Plugins that can wait should call
 * this function, sleep the given amount of time, and call it again
 * (with zero bytes read) UNTIL it returns zero and only then read.
 *
 * @param cls closure
 * @param peer which peer did we read data from
 * @param amount_recved number of bytes read (can be zero)
 * @return how long to wait until reading more from this peer
 *         (to enforce inbound quotas)
 */
typedef struct GNUNET_TIME_Relative (*GNUNET_TRANSPORT_TrafficReport) (void
                                                                       *cls,
                                                                       const
                                                                       struct
                                                                       GNUNET_PeerIdentity
                                                                       * peer,
                                                                       size_t
                                                                       amount_recved);


/**
 * Function that returns a HELLO message.
 */
typedef const struct GNUNET_MessageHeader
    *(*GNUNET_TRANSPORT_GetHelloCallback) (void);


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
   * Identity of this peer.
   */
  const struct GNUNET_PeerIdentity *my_identity;

  /**
   * Closure for the various callbacks.
   */
  void *cls;

  /**
   * Handle for reporting statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Function that should be called by the transport plugin
   * whenever a message is received.
   */
  GNUNET_TRANSPORT_PluginReceiveCallback receive;


  /**
   * Function that returns our HELLO.
   */
  GNUNET_TRANSPORT_GetHelloCallback get_our_hello;

  /**
   * Function that must be called by each plugin to notify the
   * transport service about the addresses under which the transport
   * provided by the plugin can be reached.
   */
  GNUNET_TRANSPORT_AddressNotification notify_address;

  /**
   * Function that must be called by the plugin when a non-NULL
   * session handle stops being valid (is destroyed).
   */
  GNUNET_TRANSPORT_SessionEnd session_end;

  /**
   * Function that will be called to figure if an address is an loopback,
   * LAN, WAN etc. address
   */
  GNUNET_TRANSPORT_AddressToType get_address_type;


  /**
   * What is the maximum number of connections that this transport
   * should allow?  Transports that do not have sessions (such as
   * UDP) can ignore this value.
   */
  uint32_t max_connections;

};


/**
 * Function called by the GNUNET_TRANSPORT_TransmitFunction
 * upon "completion".  In the case that a peer disconnects,
 * this function must be called for each pending request
 * (with a 'failure' indication) AFTER notifying the service
 * about the disconnect event (so that the service won't try
 * to transmit more messages, believing the connection still
 * exists...).
 *
 * @param cls closure
 * @param target who was the recipient of the message?
 * @param result GNUNET_OK on success
 *               GNUNET_SYSERR if the target disconnected;
 *               disconnect will ALSO be signalled using
 *               the ReceiveCallback.
 */
typedef void (*GNUNET_TRANSPORT_TransmitContinuation) (void *cls,
                                                       const struct
                                                       GNUNET_PeerIdentity *
                                                       target, int result);

/**
 * The new send function with just the session and no address
 *
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param session which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param timeout how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
typedef ssize_t (*GNUNET_TRANSPORT_TransmitFunction) (void *cls,
    struct Session *session,
    const char *msgbuf, size_t msgbuf_size,
    unsigned int priority,
    struct GNUNET_TIME_Relative to,
    GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls);


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
typedef void (*GNUNET_TRANSPORT_DisconnectFunction) (void *cls,
                                                     const struct
                                                     GNUNET_PeerIdentity *
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
typedef void (*GNUNET_TRANSPORT_AddressPrettyPrinter) (void *cls,
                                                       const char *type,
                                                       const void *addr,
                                                       size_t addrlen,
                                                       int numeric,
                                                       struct
                                                       GNUNET_TIME_Relative
                                                       timeout,
                                                       GNUNET_TRANSPORT_AddressStringCallback
                                                       asc, void *asc_cls);


/**
 * Another peer has suggested an address for this peer and transport
 * plugin.  Check that this could be a valid address.  This function
 * is not expected to 'validate' the address in the sense of trying to
 * connect to it but simply to see if the binary format is technically
 * legal for establishing a connection to this peer (and make sure that
 * the address really corresponds to our network connection/settings
 * and not some potential man-in-the-middle).
 *
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 */
typedef int (*GNUNET_TRANSPORT_CheckAddress) (void *cls, const void *addr,
                                              size_t addrlen);

/**
 * Create a new session to transmit data to the target
 * This session will used to send data to this peer and the plugin will
 * notify us by calling the env->session_end function
 *
 * @param cls the plugin
 * @param target the neighbour id
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return the session if the address is valid, NULL otherwise
 */
typedef struct Session * (*GNUNET_TRANSPORT_CreateSession) (void *cls,
                      const struct GNUNET_HELLO_Address *address);


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addr_len length of the address
 * @return string representing the same address
 */
typedef const char *(*GNUNET_TRANSPORT_AddressToString) (void *cls,
                                                         const void *addr,
                                                         size_t addrlen);


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
   * Function that the transport service will use to transmit data to
   * another peer.  May be NULL for plugins that only support
   * receiving data.  After this call, the plugin call the specified
   * continuation with success or error before notifying us about the
   * target having disconnected.
   */
  GNUNET_TRANSPORT_TransmitFunction send;

  /**
   * Function that can be used to force the plugin to disconnect from
   * the given peer and cancel all previous transmissions (and their
   * continuations).
   */
  GNUNET_TRANSPORT_DisconnectFunction disconnect;

  /**
   * Function to pretty-print addresses.  NOTE: this function is not
   * yet used by transport-service, but will be used in the future
   * once the transport-API has been completed.
   */
  GNUNET_TRANSPORT_AddressPrettyPrinter address_pretty_printer;

  /**
   * Function that will be called to check if a binary address
   * for this plugin is well-formed and corresponds to an
   * address for THIS peer (as per our configuration).  Naturally,
   * if absolutely necessary, plugins can be a bit conservative in
   * their answer, but in general plugins should make sure that the
   * address does not redirect traffic to a 3rd party that might
   * try to man-in-the-middle our traffic.
   */
  GNUNET_TRANSPORT_CheckAddress check_address;

  /**
   * Function that will be called to convert a binary address
   * to a string (numeric conversion only).
   */
  GNUNET_TRANSPORT_AddressToString address_to_string;

  /**
   * Function that will be called tell the plugin to create a session
   * object
   */
  GNUNET_TRANSPORT_CreateSession get_session;
};


#endif
