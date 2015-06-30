/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
#include "gnunet_multicast_service.h"
#include "gnunet_psyc_service.h"

/**
 * Version number of GNUnet PSYCstore API.
 */
#define GNUNET_PSYCSTORE_VERSION 0x00000000

/**
 * Membership test failed.
 */
#define GNUNET_PSYCSTORE_MEMBERSHIP_TEST_FAILED -2

/**
 * Flags for stored messages.
 */
enum GNUNET_PSYCSTORE_MessageFlags
{
  /**
   * The message contains state modifiers.
   */
  GNUNET_PSYCSTORE_MESSAGE_STATE = 1 << 0,

  /**
   * The state modifiers have been applied to the state store.
   */
  GNUNET_PSYCSTORE_MESSAGE_STATE_APPLIED = 1 << 1,

  /**
   * The message contains a state hash.
   */
  GNUNET_PSYCSTORE_MESSAGE_STATE_HASH = 1 << 2
};


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
 *
 * @param cls
 *        Closure.
 * @param result
 *        Result of the operation.
 * @param err_msg
 *        Error message, or NULL if there's no error.
 * @param err_msg_size
 *        Size of @a err_msg
 */
typedef void
(*GNUNET_PSYCSTORE_ResultCallback) (void *cls,
                                    int64_t result,
                                    const char *err_msg,
                                    uint16_t err_msg_size);


/**
 * Store join/leave events for a PSYC channel in order to be able to answer
 * membership test queries later.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel where the event happened.
 * @param slave_key
 *        Public key of joining/leaving slave.
 * @param did_join
 *        #GNUNET_YES on join, #GNUNET_NO on part.
 * @param announced_at
 *        ID of the message that announced the membership change.
 * @param effective_since
 *        Message ID this membership change is in effect since.
 *        For joins it is <= announced_at, for parts it is always 0.
 * @param group_generation
 *        In case of a part, the last group generation the slave has access to.
 *        It has relevance when a larger message have fragments with different
 *        group generations.
 * @param rcb
 *        Callback to call with the result of the storage operation.
 * @param rcb_cls
 *        Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_store (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                   const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                   int did_join,
                                   uint64_t announced_at,
                                   uint64_t effective_since,
                                   uint64_t group_generation,
                                   GNUNET_PSYCSTORE_ResultCallback rcb,
                                   void *rcb_cls);


/**
 * Test if a member was admitted to the channel at the given message ID.
 *
 * This is useful when relaying and replaying messages to check if a particular
 * slave has access to the message fragment with a given group generation.  It
 * is also used when handling join requests to determine whether the slave is
 * currently admitted to the channel.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        Public key of slave whose membership to check.
 * @param message_id
 *        Message ID for which to do the membership test.
 * @param group_generation
 *        Group generation of the fragment of the message to test.
 *        It has relevance if the message consists of multiple fragments with
 *        different group generations.
 * @param rcb
 *        Callback to call with the test result.
 * @param rcb_cls
 *        Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_test (struct GNUNET_PSYCSTORE_Handle *h,
                                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                  const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                  uint64_t message_id,
                                  uint64_t group_generation,
                                  GNUNET_PSYCSTORE_ResultCallback rcb,
                                  void *rcb_cls);


/**
 * Store a message fragment sent to a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel the message belongs to.
 * @param msg Message to store.
 * @param psycstore_flags Flags indicating whether the PSYC message contains
 *        state modifiers.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_store (struct GNUNET_PSYCSTORE_Handle *h,
                                 const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                 const struct GNUNET_MULTICAST_MessageHeader *msg,
                                 enum GNUNET_PSYCSTORE_MessageFlags psycstore_flags,
                                 GNUNET_PSYCSTORE_ResultCallback rcb,
                                 void *rcb_cls);


/**
 * Function called with one message fragment, as the result of a
 * GNUNET_PSYCSTORE_fragment_get() or GNUNET_PSYCSTORE_message_get() call.
 *
 * @param cls Closure.
 * @param message The retrieved message fragment.  A NULL value indicates that
 *        there are no more results to be returned.
 * @param psycstore_flags Flags stored with the message.
 *
 * @return #GNUNET_NO to stop calling this callback with further fragments,
 *         #GNUNET_YES to continue.
 */
typedef int
(*GNUNET_PSYCSTORE_FragmentCallback) (void *cls,
                                      struct GNUNET_MULTICAST_MessageHeader *message,
                                      enum GNUNET_PSYCSTORE_MessageFlags psycstore_flags);


/**
 * Retrieve message fragments by fragment ID range.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the fragment.  If not NULL, a membership test is
 *        performed first and the fragment is only returned if the slave has
 *        access to it.
 * @param first_fragment_id
 *        First fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param last_fragment_id
 *        Last consecutive fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_get (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                               uint64_t first_message_id,
                               uint64_t last_message_id,
                               GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                               GNUNET_PSYCSTORE_ResultCallback result_cb,
                               void *cls);


/**
 * Retrieve latest message fragments.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the fragment.  If not NULL, a membership test is
 *        performed first and the fragment is only returned if the slave has
 *        access to it.
 * @param first_fragment_id
 *        First fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param last_fragment_id
 *        Last consecutive fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param fragment_limit
 *        Maximum number of fragments to retrieve.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param rcb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_get_latest (struct GNUNET_PSYCSTORE_Handle *h,
                                      const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                      const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                      uint64_t fragment_limit,
                                      GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                                      GNUNET_PSYCSTORE_ResultCallback rcb,
                                      void *cls);


/**
 * Retrieve all fragments of messages in a message ID range.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the message.
 *        If not NULL, a membership test is performed first
 *        and the message is only returned if the slave has access to it.
 * @param first_message_id
 *        First message ID to retrieve.
 * @param last_message_id
 *        Last consecutive message ID to retrieve.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get (struct GNUNET_PSYCSTORE_Handle *h,
                              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                              const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                              uint64_t first_message_id,
                              uint64_t last_message_id,
                              const char *method_prefix,
                              GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                              GNUNET_PSYCSTORE_ResultCallback result_cb,
                              void *cls);


/**
 * Retrieve all fragments of the latest messages.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the message.
 *        If not NULL, a membership test is performed first
 *        and the message is only returned if the slave has access to it.
 * @param message_limit
 *        Maximum number of messages to retrieve.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get_latest (struct GNUNET_PSYCSTORE_Handle *h,
                                     const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                     const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                     uint64_t message_limit,
                                     const char *method_prefix,
                                     GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                                     GNUNET_PSYCSTORE_ResultCallback rcb,
                                     void *cls);


/**
 * Retrieve a fragment of message specified by its message ID and fragment
 * offset.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the message fragment.  If not NULL, a membership
 *        test is performed first and the message fragment is only returned
 *        if the slave has access to it.
 * @param message_id
 *        Message ID to retrieve.  Use 0 to get the latest message.
 * @param fragment_offset
 *        Offset of the fragment to retrieve.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get_fragment (struct GNUNET_PSYCSTORE_Handle *h,
                                       const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                       const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                       uint64_t message_id,
                                       uint64_t fragment_offset,
                                       GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                                       GNUNET_PSYCSTORE_ResultCallback result_cb,
                                       void *cls);


/**
 * Callback used to return the latest value of counters for the channel master.
 *
 * @see GNUNET_PSYCSTORE_counters_get()
 *
 * @param cls Closure.
 * @param result_code Status code for the operation:
 *        #GNUNET_OK: success, counter values are returned.
 *        #GNUNET_NO: no message has been sent to the channel yet.
 *        #GNUNET_SYSERR: an error occurred.
 * @param max_fragment_id Latest message fragment ID, used by multicast.
 * @param max_message_id Latest message ID, used by PSYC.
 * @param max_group_generation Latest group generation, used by PSYC.
 * @param max_state_message_id Latest message ID containing state modifiers that
 *        was applied to the state store.  Used for the state sync process.
 */
typedef void
(*GNUNET_PSYCSTORE_CountersCallback) (void *cls,
                                      int result_code,
                                      uint64_t max_fragment_id,
                                      uint64_t max_message_id,
                                      uint64_t max_group_generation,
                                      uint64_t max_state_message_id);


/**
 * Retrieve latest values of counters for a channel.
 *
 * The current value of counters are needed
 * - when a channel master is restarted, so that it can continue incrementing
 *   the counters from their last value.
 * - when a channel slave rejoins and starts the state synchronization process.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key Public key that identifies the channel.
 * @param ccb Callback to call with the result.
 * @param ccb_cls Closure for the @a ccb callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_counters_get (struct GNUNET_PSYCSTORE_Handle *h,
                               struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               GNUNET_PSYCSTORE_CountersCallback ccb,
                               void *ccb_cls);


/**
 * Apply modifiers of a message to the current channel state.
 *
 * An error is returned if there are missing messages containing state
 * operations before the current one.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id ID of the message that contains the @a modifiers.
 * @param state_delta Value of the @e state_delta PSYC header variable of the message.
 * @param modifier_count Number of elements in the @a modifiers array.
 * @param modifiers List of modifiers to apply.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the @a rcb callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_modify (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               uint64_t message_id,
                               uint64_t state_delta,
                               size_t modifier_count,
                               const struct GNUNET_ENV_Modifier *modifiers,
                               GNUNET_PSYCSTORE_ResultCallback rcb,
                               void *rcb_cls);


/**
 * Store synchronized state.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id ID of the message that contains the state_hash PSYC header variable.
 * @param modifier_count Number of elements in the @a modifiers array.
 * @param modifiers Full state to store.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_sync (struct GNUNET_PSYCSTORE_Handle *h,
                             const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                             uint64_t message_id,
                             size_t modifier_count,
                             const struct GNUNET_ENV_Modifier *modifiers,
                             GNUNET_PSYCSTORE_ResultCallback rcb,
                             void *rcb_cls);



/**
 * Reset the state of a channel.
 *
 * Delete all state variables stored for the given channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_reset (struct GNUNET_PSYCSTORE_Handle *h,
                              const struct GNUNET_CRYPTO_EddsaPublicKey
                              *channel_key,
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
                                    const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
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
 * @param value Value of the state variable.
 * @param value_size Number of bytes in @a value.
 *
 * @return #GNUNET_NO to stop calling this callback with further variables,
 *         #GNUNET_YES to continue.
 */;
typedef int
(*GNUNET_PSYCSTORE_StateCallback) (void *cls, const char *name,
                                   const void *value, size_t value_size);


/**
 * Retrieve the best matching state variable.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param name Name of variable to match, the returned variable might be less specific.
 * @param scb Callback to return the matching state variable.
 * @param rcb Callback to call with the result of the operation.
 * @param cls Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get (struct GNUNET_PSYCSTORE_Handle *h,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                            const char *name,
                            GNUNET_PSYCSTORE_StateCallback scb,
                            GNUNET_PSYCSTORE_ResultCallback rcb,
                            void *cls);


/**
 * Retrieve all state variables for a channel with the given prefix.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param name_prefix Prefix of state variable names to match.
 * @param scb Callback to return matching state variables.
 * @param rcb Callback to call with the result of the operation.
 * @param cls Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get_prefix (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                   const char *name_prefix,
                                   GNUNET_PSYCSTORE_StateCallback scb,
                                   GNUNET_PSYCSTORE_ResultCallback rcb,
                                   void *cls);


/**
 * Cancel an operation.
 *
 * @param op Handle for the operation to cancel.
 */
void
GNUNET_PSYCSTORE_operation_cancel (struct GNUNET_PSYCSTORE_OperationHandle *op);




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYCSTORE_SERVICE_H */
#endif
/* end of gnunet_psycstore_service.h */
