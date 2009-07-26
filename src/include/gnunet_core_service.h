/*
     This file is part of GNUnet.
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
 * @file include/gnunet_core_service.h
 * @brief core service; this is the main API for encrypted P2P
 *        communications
 * @author Christian Grothoff
 */

#ifndef GNUNET_CORE_SERVICE_H
#define GNUNET_CORE_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Version number of GNUnet-core API.
 */
#define GNUNET_CORE_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_CORE_Handle;


/**
 * Method called whenever a given peer either connects or
 * disconnects (or list of connections was requested).
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
typedef void (*GNUNET_CORE_ClientEventHandler) (void *cls,
                                                const struct
                                                GNUNET_PeerIdentity * peer);


/**
 * Type of a send callback to fill up buffers.
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
typedef unsigned int
  (*GNUNET_CORE_BufferFillCallback) (void *cls,
                                     const struct GNUNET_PeerIdentity *
                                     receiver,
                                     void *position, unsigned int padding);


/**
 * Functions with this signature are called whenever a message is
 * received or transmitted.
 *
 * @param cls closure
 * @param peer the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
typedef int
  (*GNUNET_CORE_MessageCallback) (void *cls,
                                  const struct GNUNET_PeerIdentity * other,
                                  const struct GNUNET_MessageHeader *
                                  message);


/**
 * Message handler.  Each struct specifies how to handle on particular
 * type of message received.
 */
struct GNUNET_CORE_MessageHandler
{
  /**
   * Function to call for messages of "type".
   */
  GNUNET_CORE_MessageCallback callback;

  /**
   * Type of the message this handler covers.
   */
  uint16_t type;

  /**
   * Expected size of messages of this type.  Use 0 for variable-size.
   * If non-zero, messages of the given type will be discarded if they
   * do not have the right size.
   */
  uint16_t expected_size;

};


/**
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).  Note that the private key of the
 * peer is intentionally not exposed here; if you need it,
 * your process should try to read the private key file
 * directly (which should work if you are authorized...).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_identity ID of this peer, NULL if we failed
 * @param publicKey public key of this peer, NULL if we failed
 */
typedef void
  (*GNUNET_CORE_StartupCallback) (void *cls,
                                  struct GNUNET_CORE_Handle * server,
                                  const struct GNUNET_PeerIdentity *
                                  my_identity,
                                  const struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *
                                  publicKey);


/**
 * Connect to the core service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param timeout after how long should we give up trying to connect to the core service?
 * @param cls closure for the various callbacks that follow (including handlers in the handlers array)
 * @param init callback to call on timeout or once we have successfully
 *        connected to the core service
 * @param connects function to call on peer connect, can be NULL
 * @param disconnects function to call on peer disconnect / timeout, can be NULL
 * @param bfc function to call to fill up spare bandwidth, can be NULL
 * @param inbound_notify function to call for all inbound messages, can be NULL
 * @param inbound_hdr_only set to GNUNET_YES if inbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message;
 *                can be used to improve efficiency, ignored if inbound_notify is NULLL
 * @param outbound_notify function to call for all outbound messages, can be NULL
 * @param outbound_hdr_only set to GNUNET_YES if outbound_notify will only read the
 *                GNUNET_MessageHeader and hence we do not need to give it the full message
 *                can be used to improve efficiency, ignored if outbound_notify is NULLL
 * @param handlers callbacks for messages we care about, NULL-terminated
 */
void
GNUNET_CORE_connect (struct GNUNET_SCHEDULER_Handle *sched,
                     const struct GNUNET_CONFIGURATION_Handle *cfg,
                     struct GNUNET_TIME_Relative timeout,
                     void *cls,
                     GNUNET_CORE_StartupCallback init,
                     GNUNET_CORE_ClientEventHandler connects,
                     GNUNET_CORE_ClientEventHandler disconnects,
                     GNUNET_CORE_BufferFillCallback bfc,
                     GNUNET_CORE_MessageCallback inbound_notify,
                     int inbound_hdr_only,
                     GNUNET_CORE_MessageCallback outbound_notify,
                     int outbound_hdr_only,
                     const struct GNUNET_CORE_MessageHandler *handlers);


/**
 * Disconnect from the core service.
 *
 * @param handle connection to core to disconnect
 */
void GNUNET_CORE_disconnect (struct GNUNET_CORE_Handle *handle);


/**
 * Function called with statistics about the given peer.
 *
 * @param peer identifies the peer
 * @param latency current latency estimate, "FOREVER" if we have been
 *                disconnected
 * @param bpm_in set to the current bandwidth limit (receiving) for this peer
 * @param bpm_out set to the current bandwidth limit (sending) for this peer
 * @param amount set to the amount that was actually reserved or unreserved
 * @param preference current traffic preference for the given peer
 */
typedef void
  (*GNUNET_CORE_PeerConfigurationInfoCallback) (void *cls,
                                                const struct
                                                GNUNET_PeerIdentity * peer,
                                                unsigned int bpm_in,
                                                unsigned int bpm_out,
                                                struct GNUNET_TIME_Relative
                                                latency, int amount,
                                                unsigned long long preference);


/**
 * Obtain statistics and/or change preferences for the given peer.
 *
 * @param handle connection to core to use
 * @param peer identifies the peer
 * @param timeout after how long should we give up (and call "info" with NULL
 *                for "peer" to signal an error)?
 * @param bpm_out set to the current bandwidth limit (sending) for this peer,
 *                caller should set "bpm_out" to "-1" to avoid changing
 *                the current value; otherwise "bpm_out" will be lowered to
 *                the specified value; passing a pointer to "0" can be used to force
 *                us to disconnect from the peer; "bpm_out" might not increase
 *                as specified since the upper bound is generally
 *                determined by the other peer!
 * @param amount reserve N bytes for receiving, negative
 *                amounts can be used to undo a (recent) reservation;
 * @param preference increase incoming traffic share preference by this amount;
 *                in the absence of "amount" reservations, we use this
 *                preference value to assign proportional bandwidth shares
 *                to all connected peers
 * @param info function to call with the resulting configuration information
 * @param info_cls closure for info
 */
void
GNUNET_CORE_peer_configure (struct GNUNET_CORE_Handle *handle,
                            const struct GNUNET_PeerIdentity *peer,
                            struct GNUNET_TIME_Relative timeout,
                            unsigned int bpm_out,
                            int amount,
                            unsigned long long preference,
                            GNUNET_CORE_PeerConfigurationInfoCallback info,
                            void *info_cls);


/**
 * Handle for a transmission request.
 */
struct GNUNET_CORE_TransmitHandle;


/**
 * Ask the core to call "notify" once it is ready to transmit the
 * given number of bytes to the specified "target".  If we are not yet
 * connected to the specified peer, a call to this function will cause
 * us to try to establish a connection.
 *
 * @param handle connection to core service
 * @param priority how important is the message?
 * @param maxdelay how long can the message wait?
 * @param target who should receive the message,
 *        use NULL for this peer (loopback)
 * @param notify_size how many bytes of buffer space does notify want?
 * @param notify function to call when buffer space is available
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we can not even queue the request (insufficient
 *         memory); if NULL is returned, "notify" will NOT be called.
 */
struct GNUNET_CORE_TransmitHandle *GNUNET_CORE_notify_transmit_ready (struct
                                                                      GNUNET_CORE_Handle
                                                                      *handle,
                                                                      unsigned
                                                                      int
                                                                      priority,
                                                                      struct
                                                                      GNUNET_TIME_Relative
                                                                      maxdelay,
                                                                      const
                                                                      struct
                                                                      GNUNET_PeerIdentity
                                                                      *target,
                                                                      size_t
                                                                      notify_size,
                                                                      GNUNET_NETWORK_TransmitReadyNotify
                                                                      notify,
                                                                      void
                                                                      *notify_cls);


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param h handle that was returned by "notify_transmit_ready".
 */
void
GNUNET_CORE_notify_transmit_ready_cancel (struct GNUNET_CORE_TransmitHandle
                                          *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CORE_SERVICE_H */
#endif
/* end of gnunet_core_service.h */
