/*
     This file is part of GNUnet
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_peerinfo_service.h
 * @brief Code to maintain the list of currently known hosts
 *   (in memory structure of data/hosts) and their trust ratings
 *   (in memory structure of data/trust)
 * @author Christian Grothoff
 */

#ifndef GNUNET_PEERINFO_SERVICE_H
#define GNUNET_PEERINFO_SERVICE_H

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_hello_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Handle to the peerinfo service.
 */
struct GNUNET_PEERINFO_Handle;


/**
 * Connect to the peerinfo service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return NULL on error (configuration related, actual connection
 *         etablishment may happen asynchronously).
 */
struct GNUNET_PEERINFO_Handle *
GNUNET_PEERINFO_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 struct GNUNET_SCHEDULER_Handle *sched);


/**
 * Disconnect from the peerinfo service.  Note that all iterators must
 * have completed or have been cancelled by the time this function is
 * called (otherwise, calling this function is a serious error).
 * Furthermore, if 'GNUNET_PEERINFO_add_peer' operations are still
 * pending, they will be cancelled silently on disconnect.
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERINFO_disconnect (struct GNUNET_PEERINFO_Handle *h);


/**
 * Add a host to the persistent list.  This method operates in 
 * semi-reliable mode: if the transmission is not completed by
 * the time 'GNUNET_PEERINFO_disconnect' is called, it will be
 * aborted.  Furthermore, if a second HELLO is added for the
 * same peer before the first one was transmitted, PEERINFO may
 * merge the two HELLOs prior to transmission to the service.
 *
 * @param h handle to the peerinfo service
 * @param peer identity of the peer
 * @param hello the verified (!) HELLO message
 */
void
GNUNET_PEERINFO_add_peer_new (struct GNUNET_PEERINFO_Handle *h,
			      const struct GNUNET_PeerIdentity *peer,
			      const struct GNUNET_HELLO_Message *hello);



/**
 * Add a host to the persistent list.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param peer identity of the peer
 * @param hello the verified (!) HELLO message
 */
void
GNUNET_PEERINFO_add_peer (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_SCHEDULER_Handle *sched,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_HELLO_Message *hello);

/**
 * Type of an iterator over the hosts.  Note that each
 * host will be called with each available protocol.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param trust amount of trust we have in the peer
 */
typedef void
  (*GNUNET_PEERINFO_Processor) (void *cls,
                                const struct GNUNET_PeerIdentity * peer,
                                const struct GNUNET_HELLO_Message * hello,
                                uint32_t trust);


/**
 * Handle for cancellation of iteration over peers.
 */
struct GNUNET_PEERINFO_IteratorContext;


/**
 * Call a method for each known matching host and change
 * its trust value.  The method will be invoked once for
 * each host and then finally once with a NULL pointer.  After
 * that final invocation, the iterator context must no longer
 * be used.
 *
 * Note that the last call can be triggered by timeout or by simply
 * being done; however, the trust argument will be set to zero if we
 * are done, 1 if we timed out and 2 for fatal error.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param trust_delta how much to change the trust in all matching peers
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error (in this case, 'callback' is never called!), 
 *         otherwise an iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         struct GNUNET_SCHEDULER_Handle *sched,
                         const struct GNUNET_PeerIdentity *peer,
                         int trust_delta,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_PEERINFO_Processor callback,
                         void *callback_cls);



/**
 * Call a method for each known matching host and change its trust
 * value.  The callback method will be invoked once for each matching
 * host and then finally once with a NULL pointer.  After that final
 * invocation, the iterator context must no longer be used.
 *
 * Note that the last call can be triggered by timeout or by simply
 * being done; however, the trust argument will be set to zero if we
 * are done, 1 if we timed out and 2 for fatal error.
 *
 * Instead of calling this function with 'peer == NULL' and 'trust ==
 * 0', it is often better to use 'GNUNET_PEERINFO_notify'.
 * 
 * @param h handle to the peerinfo service
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param trust_delta how much to change the trust in all matching peers
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error (in this case, 'callback' is never called!), 
 *         otherwise an iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate_new (struct GNUNET_PEERINFO_Handle *h,
			     const struct GNUNET_PeerIdentity *peer,
			     int trust_delta,
			     struct GNUNET_TIME_Relative timeout,
			     GNUNET_PEERINFO_Processor callback,
			     void *callback_cls);



/**
 * Cancel an iteration over peer information.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_PEERINFO_iterate_cancel (struct GNUNET_PEERINFO_IteratorContext *ic);


/**
 * Handle for notifications about changes to the set of known peers.
 */
struct GNUNET_PEERINFO_NotifyContext;


/**
 * Call a method whenever our known information about peers
 * changes.  Initially calls the given function for all known
 * peers and then only signals changes.  Note that it is
 * possible (i.e. on disconnects) that the callback is called
 * twice with the same peer information.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error
 */
struct GNUNET_PEERINFO_NotifyContext *
GNUNET_PEERINFO_notify (const struct GNUNET_CONFIGURATION_Handle *cfg,
			struct GNUNET_SCHEDULER_Handle *sched,
			GNUNET_PEERINFO_Processor callback,
			void *callback_cls);


/**
 * Stop notifying about changes.
 *
 * @param nc context to stop notifying
 */
void
GNUNET_PEERINFO_notify_cancel (struct GNUNET_PEERINFO_NotifyContext *nc);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* end of gnunet_peerinfo_service.h */
#endif
