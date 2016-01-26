/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @author Gabor X Toth
 * @author Christian Grothoff
 *
 * @file
 * PSYC Slicer library
 *
 * @defgroup psyc-util-slicer  PSYC Utilities library: Slicer
 * Try-and-slice processing of PSYC method names and environment.
 * @{
 */

#ifndef GNUNET_PSYC_SLICER_H
#define GNUNET_PSYC_SLICER_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * Handle to an implementation of try-and-slice.
 */
struct GNUNET_PSYC_Slicer;


/**
 * Function called upon receiving a message indicating a call to a @e method.
 *
 * This function is called one or more times for each message until all data
 * fragments arrive from the network.
 *
 * @param cls
 *        Closure.
 * @param msg
 *        Message part, as it arrived from the network.
 * @param message_id
 *        Message counter, monotonically increasing from 1.
 * @param flags
 *        OR'ed GNUNET_PSYC_MessageFlags
 * @param fragment_offset
 *        Multicast message fragment offset.
 * @param tmit_flags
 *        OR'ed GNUNET_PSYC_MasterTransmitFlags
 * @param nym
 *        The sender of the message.
 *        Can be NULL if the message is not connected to a pseudonym.
 * @param method_name
 *        Original method name from PSYC.
 *        May be more specific than the registered method name due to
 *        try-and-slice matching.
 */
typedef void
(*GNUNET_PSYC_MethodCallback) (void *cls,
                               const struct GNUNET_PSYC_MessageMethod *msg,
                               uint64_t message_id,
                               uint32_t flags,
                               uint64_t fragment_offset,
                               uint32_t tmit_flags,
                               const struct GNUNET_CRYPTO_EcdsaPublicKey *nym_pub_key,
                               const char *method_name);


/**
 * Function called upon receiving a modifier of a message.
 *
 * @param cls
 *        Closure.
 * @param message_id
 *        Message ID this data fragment belongs to.
 * @param flags
 *        OR'ed GNUNET_PSYC_MessageFlags
 * @param fragment_offset
 *        Multicast message fragment offset.
 * @param msg
 *        Message part, as it arrived from the network.
 * @param oper
 *        Operation to perform.
 *        0 in case of a modifier continuation.
 * @param name
 *        Name of the modifier.
 *        NULL in case of a modifier continuation.
 * @param value
 *        Value of the modifier.
 * @param value_size
 *        Size of @value.
 */
typedef void
(*GNUNET_PSYC_ModifierCallback) (void *cls,
                                 const struct GNUNET_MessageHeader *msg,
                                 uint64_t message_id,
                                 uint32_t flags,
                                 uint64_t fragment_offset,
                                 enum GNUNET_PSYC_Operator oper,
                                 const char *name,
                                 const void *value,
                                 uint16_t value_size,
                                 uint16_t full_value_size);


/**
 * Function called upon receiving a data fragment of a message.
 *
 * @param cls
 *        Closure.
 * @param msg
 *        Message part, as it arrived from the network.
 * @param message_id
 *        Message ID this data fragment belongs to.
 * @param flags
 *        OR'ed GNUNET_PSYC_MessageFlags
 * @param fragment_offset
 *        Multicast message fragment offset.
 * @param data
 *        Data stream given to the method.
 * @param data_size
 *        Number of bytes in @a data.
 * @param end
 *        End of message?
 *        #GNUNET_NO     if there are further fragments,
 *        #GNUNET_YES    if this is the last fragment,
 *        #GNUNET_SYSERR indicates the message was cancelled by the sender.
 */
typedef void
(*GNUNET_PSYC_DataCallback) (void *cls,
                             const struct GNUNET_MessageHeader *msg,
                             uint64_t message_id,
                             uint32_t flags,
                             uint64_t fragment_offset,
                             const void *data,
                             uint16_t data_size);


/**
 * End of message.
 *
 * @param cls
 *        Closure.
 * @param msg
 *        Message part, as it arrived from the network.
 * @param message_id
 *        Message ID this data fragment belongs to.
 * @param flags
 *        OR'ed GNUNET_PSYC_MessageFlags
 * @param fragment_offset
 *        Multicast message fragment offset.
 * @param cancelled
 *        #GNUNET_YES if the message was cancelled,
 *        #GNUNET_NO  if the message is complete.
 */
typedef void
(*GNUNET_PSYC_EndOfMessageCallback) (void *cls,
                                     const struct GNUNET_MessageHeader *msg,
                                     uint64_t message_id,
                                     uint32_t flags,
                                     uint64_t fragment_offset,
                                     uint8_t cancelled);


/**
 * Create a try-and-slice instance.
 *
 * A slicer processes incoming messages and notifies callbacks about matching
 * methods or modifiers encountered.
 *
 * @return A new try-and-slice construct.
 */
struct GNUNET_PSYC_Slicer *
GNUNET_PSYC_slicer_create (void);


/**
 * Add a method to the try-and-slice instance.
 *
 * The callbacks are called for messages with a matching @a method_name prefix.
 *
 * @param slicer
 *        The try-and-slice instance to extend.
 * @param method_name
 *        Name of the given method, use empty string to match all.
 * @param method_cb
 *        Method handler invoked upon a matching message.
 * @param modifier_cb
 *        Modifier handler, invoked after @a method_cb
 *        for each modifier in the message.
 * @param data_cb
 *        Data handler, invoked after @a modifier_cb for each data fragment.
 * @param eom_cb
 *        Invoked upon reaching the end of a matching message.
 * @param cls
 *        Closure for the callbacks.
 */
void
GNUNET_PSYC_slicer_method_add (struct GNUNET_PSYC_Slicer *slicer,
                               const char *method_name,
                               GNUNET_PSYC_MethodCallback method_cb,
                               GNUNET_PSYC_ModifierCallback modifier_cb,
                               GNUNET_PSYC_DataCallback data_cb,
                               GNUNET_PSYC_EndOfMessageCallback eom_cb,
                               void *cls);

/**
 * Remove a registered method from the try-and-slice instance.
 *
 * Removes one matching handler registered with the given
 * @a method_name and callbacks.
 *
 * @param slicer
 *        The try-and-slice instance.
 * @param method_name
 *        Name of the method to remove.
 * @param method_cb
 *        Method handler.
 * @param modifier_cb
 *        Modifier handler.
 * @param data_cb
 *        Data handler.
 * @param eom_cb
 *        End of message handler.
 *
 * @return #GNUNET_OK if a method handler was removed,
 *         #GNUNET_NO if no handler matched the given method name and callbacks.
 */
int
GNUNET_PSYC_slicer_method_remove (struct GNUNET_PSYC_Slicer *slicer,
                                  const char *method_name,
                                  GNUNET_PSYC_MethodCallback method_cb,
                                  GNUNET_PSYC_ModifierCallback modifier_cb,
                                  GNUNET_PSYC_DataCallback data_cb,
                                  GNUNET_PSYC_EndOfMessageCallback eom_cb);


/**
 * Watch a place for changed objects.
 *
 * @param slicer
 *        The try-and-slice instance.
 * @param object_filter
 *        Object prefix to match.
 * @param modifier_cb
 *        Function to call when encountering a state modifier.
 * @param cls
 *        Closure for callback.
 */
void
GNUNET_PSYC_slicer_modifier_add (struct GNUNET_PSYC_Slicer *slicer,
                                 const char *object_filter,
                                 GNUNET_PSYC_ModifierCallback modifier_cb,
                                 void *cls);


/**
 * Remove a registered modifier from the try-and-slice instance.
 *
 * Removes one matching handler registered with the given
 * @a object_filter and callback.
 *
 * @param slicer
 *        The try-and-slice instance.
 * @param object_filter
 *        Object prefix to match.
 * @param modifier_cb
 *        Function to call when encountering a state modifier changes.
 */
int
GNUNET_PSYC_slicer_modifier_remove (struct GNUNET_PSYC_Slicer *slicer,
                                    const char *object_filter,
                                    GNUNET_PSYC_ModifierCallback modifier_cb);


/**
 * Process an incoming message and call matching handlers.
 *
 * @param slicer
 *        The slicer to use.
 * @param msg
 *        The message as it arrived from the network.
 */
void
GNUNET_PSYC_slicer_message (struct GNUNET_PSYC_Slicer *slicer,
                            const struct GNUNET_PSYC_MessageHeader *msg);


/**
 * Process an incoming message part and call matching handlers.
 *
 * @param slicer
 *        The slicer to use.
 * @param message_id
 *        ID of the message.
 * @param flags
 *        Flags for the message.
 *        @see enum GNUNET_PSYC_MessageFlags
 * @param fragment offset
 *        Fragment offset of the message.
 * @param msg
 *        The message part as it arrived from the network.
 */
void
GNUNET_PSYC_slicer_message_part (struct GNUNET_PSYC_Slicer *slicer,
                                 const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                                 uint64_t message_id,
                                 uint32_t flags,
                                 uint64_t fragment_offset,
                                 const struct GNUNET_MessageHeader *msg);


/**
 * Remove all registered method handlers.
 *
 * @param slicer
 *        Slicer to clear.
 */
void
GNUNET_PSYC_slicer_method_clear (struct GNUNET_PSYC_Slicer *slicer);


/**
 * Remove all registered modifier handlers.
 *
 * @param slicer
 *        Slicer to clear.
 */
void
GNUNET_PSYC_slicer_modifier_clear (struct GNUNET_PSYC_Slicer *slicer);


/**
 * Remove all registered method & modifier handlers.
 *
 * @param slicer
 *        Slicer to clear.
 */
void
GNUNET_PSYC_slicer_clear (struct GNUNET_PSYC_Slicer *slicer);


/**
 * Destroy a given try-and-slice instance.
 *
 * @param slicer
 *        Slicer to destroy
 */
void
GNUNET_PSYC_slicer_destroy (struct GNUNET_PSYC_Slicer *slicer);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYC_SLICER_H */
#endif

/** @} */  /* end of group */
