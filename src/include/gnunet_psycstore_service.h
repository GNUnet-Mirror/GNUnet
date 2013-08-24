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
#include "gnunet_env_lib.h"

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
 * Callback used to return the latest value of counters of a channel.
 *
 * @see GNUNET_PSYCSTORE_counters_get()
 *
 * @param *cls Closure.
 * @param fragment_id Latest message fragment ID, used by multicast.
 * @param message_id Latest message ID, used by PSYC.
 * @param group_generation Latest group generation, used by PSYC.
 */
typedef void
(*GNUNET_PSYCSTORE_CountersCallback) (void *cls,
                                      uint64_t fragment_id,
                                      uint64_t message_id,
                                      uint64_t group_generation);


/** 
 * Retrieve latest values of counters for a channel.
 *
 * The current value of counters are needed when a channel master is restarted,
 * so that it can continue incrementing the counters from their last value.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key Public key that identifies the channel.
 * @param cb Callback to call with the result.
 * @param cb_cls Closure for the callback.
 * 
 * @return 
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_counters_get (struct GNUNET_PSYCSTORE_Handle *h,
                               GNUNET_CRYPTO_EccPublicKey *channel_key,
                               GNUNET_PSYCSTORE_CountersCallback *cb,
                               void *cb_cls);


/** 
 * Function called with the result of an asynchronous operation.
 * 
 * @param result #GNUNET_SYSERR on error,
 *        #GNUNET_YES on success or if the peer was a member,
 *        #GNUNET_NO if the peer was not a member
 */
typedef void
(*GNUNET_PSYCSTORE_ResultCallback) (void *cls,
                                    int result);


/** 
 * Store join/leave events for a PSYC channel in order to be able to answer
 * membership test queries later.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel where the event happened.
 * @param slave_key Public key of joining/leaving slave.
 * @param did_join #GNUNET_YES on join, #GNUNET_NO on part.
 * @param announced_at ID of the message that announced the membership change.
 * @param effective_since Message ID this membership change is in effect since.
 *        For joins it is <= announced_at, for parts it is always 0.
 * @param group_generation In case of a part, the last group generation the
 *        slave has access to.  It has relevance when a larger message have
 *        fragments with different group generations.
 * @param rcb Callback to call with the result of the storage operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_store (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                                   const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                                   int did_join,
                                   uint64_t announced_at,
                                   uint64_t effective_since,
                                   uint64_t group_generation,
                                   GNUNET_PSYCSTORE_ResultCallback rcb,
                                   void *rcb_cls);


/** 
 * Test if a peer was a member of the channel during the given period specified by the group generation.
 *
 * This is useful when relaying and replaying messages to check if a particular slave has access to the message fragment with a given group generation.  It is also used when handling join requests to determine whether the slave is currently admitted to the channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param slave_key Public key of slave whose membership to check.
 * @param message_id Message ID for which to do the membership test.
 * @param group_generation Group generation of the fragment of the message to
 *        test.  It has relevance if the message consists of multiple fragments
 *        with different group generations.
 * @param rcb Callback to call with the test result.
 * @param rcb_cls Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_test (struct GNUNET_PSYCSTORE_Handle *h,
                                  const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                                  const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                                  uint64_t message_id,
                                  uint64_t group_generation,
                                  GNUNET_PSYCSTORE_ResultCallback rcb,
                                  void *rcb_cls);


/** 
 * Store a message fragment sent to a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel the message belongs to.
 * @param message Message to store.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_store (struct GNUNET_PSYCSTORE_Handle *h,
                                 const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                                 const struct GNUNET_MULTICAST_MessageHeader *message,
                                 GNUNET_PSYCSTORE_ResultCallback rcb,
                                 void *rcb_cls);


/** 
 * Function called with one message fragment, as the result of a
 * GNUNET_PSYCSTORE_fragment_get() or GNUNET_PSYCSTORE_message_get() call.
 *
 * @param cls Closure.
 * @param message The retrieved message fragment.  A NULL value indicates that
 *        there are no more results to be returned.
 * @param flags Message flags indicating fragmentation status.
 */
typedef void
(*GNUNET_PSYCSTORE_FragmentCallback) (void *cls,
                                      const struct GNUNET_MULTICAST_MessageHeader *message,
                                      enum GNUNET_PSYC_MessageFlags flags);


/** 
 * Retrieve a message fragment by fragment ID.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param fragment_id Fragment ID to check.  Use 0 to get the latest message fragment.
 * @param cb Callback to call with the retrieved fragment.
 * @param cb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_get (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                               uint64_t fragment_id,
                               GNUNET_PSYCSTORE_FragmentCallback cb,
                               void *cb_cls);


/** 
 * Retrieve a message by ID.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id Message ID to check.  Use 0 to get the latest message.
 * @param cb Callback to call with the retrieved fragments.
 * @param cb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get (struct GNUNET_PSYCSTORE_Handle *h,
                              const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                              uint64_t message_id,
                              GNUNET_PSYCSTORE_FragmentCallback cb,
                              void *cb_cls);


/** 
 * Apply modifiers of a message to the current channel state.
 *
 * An error is returned if there are missing messages containing state
 * operations before the current one.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id ID of the message that contains the @a modifiers.
 * @param state_delta Value of the _state_delta PSYC header variable of the message.
 * @param modifier_count Number of elements in the @a modifiers array.
 * @param modifiers List of modifiers to apply.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_modify (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                               uint64_t message_id,
                               uint64_t state_delta,
                               size_t modifier_count,
                               const struct GNUNET_ENV_Modifier *modifiers,
                               GNUNET_PSYCSTORE_ResultCallback rcb,
                               void *rcb_cls);


/** 
 * Update signed values of state variables in the state store.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id Message ID that contained the state @a hash.
 * @param hash Hash of the serialized full state.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_hash_update (struct GNUNET_PSYCSTORE_Handle *h,
                                    const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                                    uint64_t message_id,
                                    const struct GNUNET_HashCode *hash,
                                    GNUNET_PSYCSTORE_ResultCallback rcb,
                                    void *rcb_cls);


/** 
 * Function called with the value of a state variable.
 *
 * @param cls Closure.
 * @param name Name of the state variable.  A NULL value indicates that there are no more
 *        state variables to be returned.
 * @param value_size Number of bytes in @a value.
 * @param value Value of the state variable.
t * 
 */
typedef void
(*GNUNET_PSYCSTORE_StateCallback) (void *cls,
                                   const char *name,
                                   size_t value_size,
                                   const void *value);


/** 
 * Retrieve the best matching state variable.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param name Name of variable to match, the returned variable might be less specific.
 * @param cb Callback to return matching state variables.
 * @param cb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get (struct GNUNET_PSYCSTORE_Handle *h,
                            const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                            const char *name,
                            GNUNET_PSYCSTORE_StateCallback cb,
                            void *cb_cls);


/** 
 * Retrieve all state variables for a channel with the given prefix.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param name_prefix Prefix of state variable names to match.
 * @param cb Callback to return matching state variables.
 * @param cb_cls Closure for the callback.
 * 
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get_all (struct GNUNET_PSYCSTORE_Handle *h,
                                const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                                const char *name_prefix,
                                GNUNET_PSYCSTORE_StateCallback cb,
                                void *cb_cls);


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
