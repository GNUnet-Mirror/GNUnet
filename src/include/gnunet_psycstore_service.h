/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_psycstore_service.h
 * @brief PSYCstore service; implements persistent storage for the PSYC service
 * @author Gabor X Toth
 * @author Christian Grothoff
 */
#ifndef GNUNET_PSYCSTORE_SERVICE_H
#define GNUNET_PSYCSTORE_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/** 
 * Version number of GNUnet PSYCstore API.
 */
#define GNUNET_PSYCSTORE_VERSION 0x00000000

/** 
 * Handle for a PSYCstore
 */
struct GNUNET_PSYCSTORE_Handle;


/** 
 * Connect to the PSYCstore service.
 *
 * @param cfg Configuration to use.
 *
 * @return Handle for the connecton.
 */
struct GNUNET_PSYCSTORE_Handle *
GNUNET_PSYCSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/** 
 * Disconnect from the PSYCstore service.
 *
 * @param h Handle for the connection.
 */
void
GNUNET_PSYCSTORE_disconnect (struct GNUNET_PSYCSTORE_Handle *h);


/** 
 * Handle for an operation on the PSYCSTORE (useful to cancel the operation).
 */
struct GNUNET_PSYCSTORE_OperationHandle;


/** 
 * Function called with the result of an asynchronous operation.
; * 
 * @param result #GNUNET_SYSERR on error,
 *        #GNUNET_YES on success or if the peer was a member,
 *        #GNUNET_NO if the peer was not a member
 */
typedef void (*GNUNET_PSYCSTORE_ContinuationCallback)(void *cls,
						      int result);

/** 
 * Store join/leave events for a PSYC channel in order to be able to answer
 * membership test queries later.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id ID of the channel where the event happened.
 * @param message_id ID of the message in which this event was announced.
 * @param group_generation Generation of the group when this event was announced.
 * @param peer Identity of joining/leaving peer.
 * @param did_join #GNUNET_YES on join, #GNUNET_NO on leave.
 * @param ccb Callback to call with the result of the storage operation.
 * @param ccb_cls Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_store (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_HashCode *channel_id,
                                   uint64_t message_id,
                                   uint64_t group_generation,
                                   const struct GNUNET_PeerIdentity *peer,
                                   int did_join,
                                   GNUNET_PSYCSTORE_ContinuationCallback ccb,
                                   void *ccb_cls);


/** 
 * Test if a peer was a member of the channel when the message fragment with the
 * specified ID was sent to the channel.
 *
 * This is useful in case of retransmissions to check if the peer was authorized
 * to see the requested message.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel we are interested in.
 * @param fragment_id Message fragment ID to check.
 * @param peer Peer whose membership to check.
 * @param ccb Callback to call with the test result.
 * @param ccb_cls Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_test (struct GNUNET_PSYCSTORE_Handle *h,
				  const struct GNUNET_HashCode *channel_id,
				  uint64_t fragment_id,
				  const struct GNUNET_PeerIdentity *peer,
				  GNUNET_PSYCSTORE_ContinuationCallback ccb,
				  void *ccb_cls);


/** 
 * Store a message fragment sent to a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel the message belongs to.
 * @param message Message to store.
 * @param ccb Callback to call with the result of the operation.
 * @param ccb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_store (struct GNUNET_PSYCSTORE_Handle *h,
                                 const struct GNUNET_HashCode *channel_id,
                                 const struct GNUNET_MULTICAST_MessageHeader *message,
                                 GNUNET_PSYCSTORE_ContinuationCallback ccb,
                                 void *ccb_cls);


/** 
 * Function called with one message fragment, as the result of a
 * GNUNET_PSYCSTORE_fragment_get() or GNUNET_PSYCSTORE_message_get() call.
 *
 * @param cls Closure.
 * @param message The retrieved message fragment.
 * @param flags Message flags indicating fragmentation status.
 */
typedef void (*GNUNET_PSYCSTORE_FragmentResultCallback)(void *cls,	
						       const struct GNUNET_MULTICAST_MessageHeader *message,
                                                       enum GNUNET_PSYC_MessageFlags flags);


/** 
 * Retrieve a message fragment by fragment ID.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel we are interested in.
 * @param fragment_id Fragment ID to check.  Use 0 to get the latest message fragment.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_get (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_HashCode *channel_id,
                               uint64_t message_id,
                               GNUNET_PSYCSTORE_FragmentResultCallback rcb,
                               void *rcb_cls);


/** 
 * Retrieve a message by ID.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel we are interested in.
 * @param message_id Message ID to check.  Use 0 to get the latest message.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get (struct GNUNET_PSYCSTORE_Handle *h,
			      const struct GNUNET_HashCode *channel_id,
			      uint64_t message_id,
			      GNUNET_PSYCSTORE_FragmentResultCallback rcb,
			      void *rcb_cls);


/** 
 * Store a state variable.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel we are interested in.
 * @param name Name of variable.
 * @param value_size Size of @a value.
 * @param value Value of variable.
 * @param ccb Callback to call with the result of the operation.
 * @param ccb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_set (struct GNUNET_PSYCSTORE_Handle *h,
			    const struct GNUNET_HashCode *channel_id,
			    const char *name,
			    size_t value_size,
			    const void *value,
			    GNUNET_PSYCSTORE_ContinuationCallback ccb,
			    void *ccb_cls);


/** 
 * Function called with the value of a state variable.
 *
 * @param cls Closure.
 * @param name Name of variable.
 * @param size Size of @a value.
 * @param value Value of variable.
t * 
 */
typedef void (*GNUNET_PSYCSTORE_StateResultCallback)(void *cls,
						     const char *name,
						     size_t size,
						     const void *value);


/** 
 * Retrieve the given state variable for a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel we are interested in.
 * @param name Name of variable to get.
 * @param rcb Callback to call with the result.
 * @param rcb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get (struct GNUNET_PSYCSTORE_Handle *h,
			    const struct GNUNET_HashCode *channel_id,
			    const char *name,
			    GNUNET_PSYCSTORE_StateResultCallback rcb,
			    void *rcb_cls);


/** 
 * Retrieve all state variables for a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_id The channel we are interested in.
 * @param rcb Callback to call with the result.
 * @param rcb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get_all (struct GNUNET_PSYCSTORE_Handle *h,
				const struct GNUNET_HashCode *channel_id,
				GNUNET_PSYCSTORE_StateResultCallback rcb,
				void *rcb_cls);


/** 
 * Cancel an operation.
 *
 * @param oh Handle for the operation to cancel.
 */
void
GNUNET_PSYCSTORE_operation_cancel (struct GNUNET_PSYCSTORE_OperationHandle *oh);




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYCSTORE_SERVICE_H */
#endif
/* end of gnunet_psycstore_service.h */
