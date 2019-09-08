/*
     This file is part of GNUnet
     Copyright (C) 2009, 2010 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @author Christian Grothoff
 *
 * @file
 * Maintain the list of currently known hosts
 *
 * @defgroup peerinfo  Peer Info service
 * Maintain the list of currently known hosts.
 *
 * Holds an in-memory structure of data/hosts.
 *
 * @see [Documentation](https://gnunet.org/gnunets-peerinfo-subsystem)
 *
 * @{
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
GNUNET_PEERINFO_connect(const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the peerinfo service.  Note that all iterators must
 * have completed or have been cancelled by the time this function is
 * called (otherwise, calling this function is a serious error).
 * Furthermore, if #GNUNET_PEERINFO_add_peer() operations are still
 * pending, they will be cancelled silently on disconnect.
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERINFO_disconnect(struct GNUNET_PEERINFO_Handle *h);


/**
 * Add a host to the persistent list.  This method operates in
 * semi-reliable mode: if the transmission is not completed by
 * the time #GNUNET_PEERINFO_disconnect() is called, it will be
 * aborted.  Furthermore, if a second HELLO is added for the
 * same peer before the first one was transmitted, PEERINFO may
 * merge the two HELLOs prior to transmission to the service.
 *
 * @param h handle to the peerinfo service
 * @param hello the verified (!) HELLO message
 * @param cont continuation to call when done, NULL is allowed
 * @param cont_cls closure for @a cont
 * @return handle to cancel add operation; all pending
 *         'add' operations will be cancelled automatically
 *        on disconnect, so it is not necessary to keep this
 *        handle (unless @a cont is non-NULL and at some point
 *        calling @a cont must be prevented)
 */
struct GNUNET_MQ_Envelope *
GNUNET_PEERINFO_add_peer(struct GNUNET_PEERINFO_Handle *h,
                         const struct GNUNET_HELLO_Message *hello,
                         GNUNET_SCHEDULER_TaskCallback cont,
                         void *cont_cls);


/**
 * Type of an iterator over the hosts.  Note that each
 * host will be called with each available protocol.
 *
 * @param cls closure
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param error message
 */
typedef void
(*GNUNET_PEERINFO_Processor) (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_HELLO_Message *hello,
                              const char *err_msg);


/**
 * Handle for cancellation of iteration over peers.
 */
struct GNUNET_PEERINFO_IteratorContext;


/**
 * Call a method for each known matching host.  The callback method
 * will be invoked once for each matching host and then finally once
 * with a NULL pointer.  After that final invocation, the iterator
 * context must no longer be used.
 *
 * Instead of calling this function with `peer == NULL` it is often
 * better to use #GNUNET_PEERINFO_notify().
 *
 * @param h handle to the peerinfo service
 * @param include_friend_only include HELLO messages for friends only
 * @param peer restrict iteration to this peer only (can be NULL)
 * @param timeout how long to wait until timing out
 * @param callback the method to call for each peer
 * @param callback_cls closure for @a callback
 * @return iterator context
 */
struct GNUNET_PEERINFO_IteratorContext *
GNUNET_PEERINFO_iterate(struct GNUNET_PEERINFO_Handle *h,
                        int include_friend_only,
                        const struct GNUNET_PeerIdentity *peer,
                        GNUNET_PEERINFO_Processor callback,
                        void *callback_cls);


/**
 * Cancel an iteration over peer information.
 *
 * @param ic context of the iterator to cancel
 */
void
GNUNET_PEERINFO_iterate_cancel(struct GNUNET_PEERINFO_IteratorContext *ic);


/**
 * Handle for notifications about changes to the set of known peers.
 */
struct GNUNET_PEERINFO_NotifyContext;


/**
 * Call a method whenever our known information about peers
 * changes.  Initially calls the given function for all known
 * peers and then only signals changes.
 *
 * If @a include_friend_only is set to #GNUNET_YES peerinfo will include HELLO
 * messages which are intended for friend to friend mode and which do not
 * have to be gossiped. Otherwise these messages are skipped.
 *
 * @param cfg configuration to use
 * @param include_friend_only include HELLO messages for friends only
 * @param callback the method to call for each peer
 * @param callback_cls closure for @a callback
 * @return NULL on error
 */
struct GNUNET_PEERINFO_NotifyContext *
GNUNET_PEERINFO_notify(const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int include_friend_only,
                       GNUNET_PEERINFO_Processor callback,
                       void *callback_cls);


/**
 * Stop notifying about changes.
 *
 * @param nc context to stop notifying
 */
void
GNUNET_PEERINFO_notify_cancel(struct GNUNET_PEERINFO_NotifyContext *nc);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
