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
 * @file include/gnunet_peerinfo_service.h
 * @brief Code to maintain the list of currently known hosts
 *   (in memory structure of data/hosts).
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
 * @return NULL on error (configuration related, actual connection
 *         etablishment may happen asynchronously).
 */
struct GNUNET_PEERINFO_Handle *
GNUNET_PEERINFO_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


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
 * Continuation called with a status result.
 * 
 * @param cls closure
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_PEERINFO_Continuation)(void *cls,
					     const char *emsg);


/**
 * Opaque handle to cancel 'add' operation.
 */
struct GNUNET_PEERINFO_AddContext;


/**
 * Add a host to the persistent list.  This method operates in
 * semi-reliable mode: if the transmission is not completed by
 * the time 'GNUNET_PEERINFO_disconnect' is called, it will be
 * aborted.  Furthermore, if a second HELLO is added for the
 * same peer before the first one was transmitted, PEERINFO may
 * merge the two HELLOs prior to transmission to the service.
 *
 * @param h handle to the peerinfo service
 * @param hello the verified (!) HELLO message
 * @param cont continuation to call when done, NULL is allowed
 * @param cont_cls closure for 'cont'
 * @return handle to cancel add operation; all pending
 *         'add' operations will be cancelled automatically
 *        on disconnect, so it is not necessary to keep this
 *        handle (unless 'cont' is NULL and at some point
 *        calling 'cont' must be prevented)
 */
struct GNUNET_PEERINFO_AddContext *
GNUNET_PEERINFO_add_peer (struct GNUNET_PEERINFO_Handle *h,
                          const struct GNUNET_HELLO_Message *hello,
			  GNUNET_PEERINFO_Continuation cont,
			  void *cont_cls);


/**
 * Cancel pending 'add' operation.  Must only be called before
 * either 'cont' or 'GNUNET_PEERINFO_disconnect' are invoked.
 *
 * @param ac handle for the add operation to cancel
 */
void
GNUNET_PEERINFO_add_peer_cancel (struct GNUNET_PEERINFO_AddContext *ac);


/**
 * Type of an iterator over the hosts.  Note that each
 * host will be called with each available protocol.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param error message
 */
typedef void (*GNUNET_PEERINFO_Processor) (void *cls,
                                           const struct GNUNET_PeerIdentity *
                                           peer,
                                           const struct GNUNET_HELLO_Message *
                                           hello, const char *err_msg);


/**
 * Handle for cancellation of iteration over peers.
 */
struct GNUNET_PEERINFO_IteratorContext;


/**
 * Call a method for each known matching host to get its HELLO.
 * The callback method will be invoked once for each matching
 * host and then finally once with a NULL pointer.  After that final
 * invocation, the iterator context must no longer be used.
 *
 * Instead of calling this function with 'peer == NULL'
 * it is often better to use 'GNUNET_PEERINFO_notify'.
 *
 * @param h handle to the peerinfo service
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error (in this case, 'callback' is never called!),
 *         otherwise an iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate (struct GNUNET_PEERINFO_Handle *h,
                         const struct GNUNET_PeerIdentity *peer,
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
 * @param callback the method to call for each peer
 * @param callback_cls closure for callback
 * @return NULL on error
 */
struct GNUNET_PEERINFO_NotifyContext *
GNUNET_PEERINFO_notify (const struct GNUNET_CONFIGURATION_Handle *cfg,
                        GNUNET_PEERINFO_Processor callback, void *callback_cls);


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
