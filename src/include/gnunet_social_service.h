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
 * @file include/gnunet_social_service.h
 * @brief Social service; implements social interactions using the PSYC service.
 * @author Gabor X Toth
 * @author Christian Grothoff
 */
#ifndef GNUNET_SOCIAL_SERVICE_H
#define GNUNET_SOCIAL_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include <stdint.h>
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_psyc_service.h"


/**
 * Version number of GNUnet Social API.
 */
#define GNUNET_SOCIAL_VERSION 0x00000000


/**
 * Handle for a pseudonym of another user in the network.
 */
struct GNUNET_SOCIAL_Nym;

/**
 * Handle for a place where social interactions happen.
 */
struct GNUNET_SOCIAL_Place;

/**
 * Host handle for a place that we entered.
 */
struct GNUNET_SOCIAL_Host;

/**
 * Guest handle for place that we entered.
 */
struct GNUNET_SOCIAL_Guest;

/**
 * Handle to an implementation of try-and-slice.
 */
struct GNUNET_SOCIAL_Slicer;

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
 * @param nym
 *        The sender of the message.
 *        Can be NULL if the message is not connected to a pseudonym.
 * @param flags
 *        OR'ed GNUNET_PSYC_MessageFlags
 * @param method_name
 *        Original method name from PSYC.
 *        May be more specific than the registered method name due to
 *        try-and-slice matching.
 */
typedef void
(*GNUNET_SOCIAL_MethodCallback) (void *cls,
                                 const struct GNUNET_PSYC_MessageMethod *msg,
                                 uint64_t message_id,
                                 uint32_t flags,
                                 const struct GNUNET_SOCIAL_Nym *nym,
                                 const char *method_name);


/**
 * Function called upon receiving a modifier of a message.
 *
 * @param cls
 *        Closure.
 * @param message_id
 *        Message ID this data fragment belongs to.
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
(*GNUNET_SOCIAL_ModifierCallback) (void *cls,
                                   const struct GNUNET_MessageHeader *msg,
                                   uint64_t message_id,
                                   enum GNUNET_ENV_Operator oper,
                                   const char *name,
                                   const void *value,
                                   uint16_t value_size,
                                   uint16_t full_value_size);


/**
 * Function called upon receiving a data fragment of a message.
 *
 * @param cls
 *        Closure.
 * @param message_id
 *        Message ID this data fragment belongs to.
 * @param msg
 *        Message part, as it arrived from the network.
 * @param data_offset
 *        Byte offset of @a data in the overall data of the method.
 * @param data_size
 *        Number of bytes in @a data.
 * @param data
 *        Data stream given to the method.
 * @param end
 *        End of message?
 *        #GNUNET_NO     if there are further fragments,
 *        #GNUNET_YES    if this is the last fragment,
 *        #GNUNET_SYSERR indicates the message was cancelled by the sender.
 */
typedef void
(*GNUNET_SOCIAL_DataCallback) (void *cls,
                               const struct GNUNET_MessageHeader *msg,
                               uint64_t message_id,
                               uint64_t data_offset,
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
 * @param cancelled.
 *        #GNUNET_YES if the message was cancelled,
 *        #GNUNET_NO  if the message is complete.
 */
typedef void
(*GNUNET_SOCIAL_EndOfMessageCallback) (void *cls,
                                       const struct GNUNET_MessageHeader *msg,
                                       uint64_t message_id,
                                       uint8_t cancelled);


/**
 * Create a try-and-slice instance.
 *
 * A slicer processes incoming messages and notifies callbacks about matching
 * methods or modifiers encountered.
 *
 * @return A new try-and-slice construct.
 */
struct GNUNET_SOCIAL_Slicer *
GNUNET_SOCIAL_slicer_create (void);


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
GNUNET_SOCIAL_slicer_method_add (struct GNUNET_SOCIAL_Slicer *slicer,
                                 const char *method_name,
                                 GNUNET_SOCIAL_MethodCallback method_cb,
                                 GNUNET_SOCIAL_ModifierCallback modifier_cb,
                                 GNUNET_SOCIAL_DataCallback data_cb,
                                 GNUNET_SOCIAL_EndOfMessageCallback eom_cb,
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
GNUNET_SOCIAL_slicer_method_remove (struct GNUNET_SOCIAL_Slicer *slicer,
                                    const char *method_name,
                                    GNUNET_SOCIAL_MethodCallback method_cb,
                                    GNUNET_SOCIAL_ModifierCallback modifier_cb,
                                    GNUNET_SOCIAL_DataCallback data_cb,
                                    GNUNET_SOCIAL_EndOfMessageCallback eom_cb);


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
GNUNET_SOCIAL_slicer_modifier_add (struct GNUNET_SOCIAL_Slicer *slicer,
                                   const char *object_filter,
                                   GNUNET_SOCIAL_ModifierCallback modifier_cb,
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
GNUNET_SOCIAL_slicer_modifier_remove (struct GNUNET_SOCIAL_Slicer *slicer,
                                      const char *object_filter,
                                      GNUNET_SOCIAL_ModifierCallback modifier_cb);


/**
 * Destroy a given try-and-slice instance.
 *
 * @param slicer
 *        Slicer to destroy
 */
void
GNUNET_SOCIAL_slicer_destroy (struct GNUNET_SOCIAL_Slicer *slicer);


/**
 * Function called asking for nym to be admitted to the place.
 *
 * Should call either GNUNET_SOCIAL_host_admit() or
 * GNUNET_SOCIAL_host_reject_entry() (possibly asynchronously).  If this host
 * cannot decide, it is fine to call neither function, in which case hopefully
 * some other host of the place exists that will make the decision.  The @a nym
 * reference remains valid until the #GNUNET_SOCIAL_FarewellCallback is invoked
 * for it.
 *
 * @param cls Closure.
 * @param nym Handle for the user who wants to enter.
 * @param method_name Method name in the entry request.
 * @param variable_count Number of elements in the @a variables array.
 * @param variables Variables present in the message.
 * @param data_size Number of bytes in @a data.
 * @param data Payload given on enter (e.g. a password).
 */
typedef void
(*GNUNET_SOCIAL_AnswerDoorCallback) (void *cls,
                                     struct GNUNET_SOCIAL_Nym *nym,
                                     const char *method_name,
                                     struct GNUNET_ENV_Environment *env,
                                     size_t data_size,
                                     const void *data);


/**
 * Function called when a @a nym leaves the place.
 *
 * This is also called if the @a nym was never given permission to enter
 * (i.e. the @a nym stopped asking to get in).
 *
 * @param cls
 *        Closure.
 * @param nym
 *        Handle for the user who left.
 */
typedef void
(*GNUNET_SOCIAL_FarewellCallback) (void *cls,
                                   const struct GNUNET_SOCIAL_Nym *nym,
                                   struct GNUNET_ENV_Environment *env);


/**
 * Function called after the host entered the place.
 *
 * @param cls
 *        Closure.
 * @param result
 *        #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error.
 * @param max_message_id
 *        Last message ID sent to the channel.
 *        Or 0 if no messages have been sent to the place yet.
 */
typedef void
(*GNUNET_SOCIAL_HostEnterCallback) (void *cls, int result,
                                    uint64_t max_message_id);


/**
 * Enter a place as host.
 *
 * A place is created upon first entering, and it is active until permanently
 * left using GNUNET_SOCIAL_host_leave().
 *
 * @param cfg
 *        Configuration to contact the social service.
 * @param ego
 *        Identity of the host.
 * @param place_key
 *        Private-public key pair of the place.
 *        NULL for ephemeral places.
 * @param policy
 *        Policy specifying entry and history restrictions for the place.
 * @param slicer
 *        Slicer to handle incoming messages.
 * @param answer_door_cb
 *        Function to handle new nyms that want to enter.
 * @param farewell_cb
 *        Function to handle departing nyms.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle for the host.
 */
struct GNUNET_SOCIAL_Host *
GNUNET_SOCIAL_host_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_IDENTITY_Ego *ego,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *place_key,
                          enum GNUNET_PSYC_Policy policy,
                          struct GNUNET_SOCIAL_Slicer *slicer,
                          GNUNET_SOCIAL_HostEnterCallback enter_cb,
                          GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                          GNUNET_SOCIAL_FarewellCallback farewell_cb,
                          void *cls);


/**
 * Decision whether to admit @a nym into the place or refuse entry.
 *
 * @param hst
 *        Host of the place.
 * @param nym
 *        Handle for the entity that wanted to enter.
 * @param is_admitted
 *        #GNUNET_YES    if @a nym is admitted,
 *        #GNUNET_NO     if @a nym is refused entry,
 *        #GNUNET_SYSERR if we cannot answer the request.
 * @param method_name
 *        Method name for the rejection message.
 * @param env
 *        Environment containing variables for the message, or NULL.
 * @param data
 *        Data for the rejection message to send back.
 * @param data_size
 *        Number of bytes in @a data for method.
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if the message is too large.
 */
int
GNUNET_SOCIAL_host_entry_decision (struct GNUNET_SOCIAL_Host *hst,
                                   struct GNUNET_SOCIAL_Nym *nym,
                                   int is_admitted,
                                   const struct GNUNET_PSYC_Message *entry_resp);


/**
 * Throw @a nym out of the place.
 *
 * The @a nym reference will remain valid until the
 * #GNUNET_SOCIAL_FarewellCallback is invoked,
 * which should be very soon after this call.
 *
 * @param host
 *        Host of the place.
 * @param nym
 *        Handle for the entity to be ejected.
 */
void
GNUNET_SOCIAL_host_eject (struct GNUNET_SOCIAL_Host *host,
                          const struct GNUNET_SOCIAL_Nym *nym);


/**
 * Get the public key of a @a nym.
 *
 * Suitable, for example, to be used with GNUNET_NAMESTORE_zone_to_name().
 *
 * @param nym
 *        Pseudonym to map to a cryptographic identifier.
 *
 * @return Public key of nym.
 */
const struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_nym_get_key (const struct GNUNET_SOCIAL_Nym *nym);


/**
 * Get the hash of the public key of a @a nym.
 *
 * @param nym
 *        Pseudonym to map to a cryptographic identifier.
 *
 * @return Hash of the public key of nym.
 */
const struct GNUNET_HashCode *
GNUNET_SOCIAL_nym_get_key_hash (const struct GNUNET_SOCIAL_Nym *nym);


/**
 * Advertise the place in the GNS zone of the @e ego of the @a host.
 *
 * @param hst
 *        Host of the place.
 * @param name
 *        The name for the PLACE record to put in the zone.
 * @param peer_count
 *        Number of elements in the @a peers array.
 * @param peers
 *        List of peers to put in the PLACE record to advertise
 *        as entry points to the place in addition to the origin.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param password
 *        Password used to encrypt the record.
 *        FIXME: not implemented yet.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 */
void
GNUNET_SOCIAL_host_advertise (struct GNUNET_SOCIAL_Host *host,
                              const char *name,
                              uint32_t peer_count,
                              const struct GNUNET_PeerIdentity *peers,
                              struct GNUNET_TIME_Absolute expiration_time,
                              const char *password,
                              GNUNET_NAMESTORE_ContinuationWithStatus result_cb,
                              void *result_cls);


/**
 * Flags for announcements by a host.
 */
enum GNUNET_SOCIAL_AnnounceFlags
{
  GNUNET_SOCIAL_ANNOUNCE_NONE = 0,

  /**
   * Whether this announcement removes all objects from the place.
   *
   * New objects can be still added to the now empty place using the @e env
   * parameter of the same announcement.
   */
  GNUNET_SOCIAL_ANNOUNCE_CLEAR_OBJECTS = 1 << 0
};


/**
 * Handle for an announcement request.
 */
struct GNUNET_SOCIAL_Announcement;


/**
 * Send a message to all nyms that are present in the place.
 *
 * This function is restricted to the host.  Nyms can only send requests
 * to the host who can decide to relay it to everyone in the place.
 *
 * @param host
 *        Host of the place.
 * @param method_name
 *        Method to use for the announcement.
 * @param env
 *        Environment containing variables for the message and operations
 *        on objects of the place.
 *        Has to remain available until the first call to @a notify_data.
 *        Can be NULL.
 * @param notify_data
 *        Function to call to get the payload of the announcement.
 * @param notify_data_cls
 *        Closure for @a notify.
 * @param flags
 *        Flags for this announcement.
 *
 * @return NULL on error (another announcement already in progress?).
 */
struct GNUNET_SOCIAL_Announcement *
GNUNET_SOCIAL_host_announce (struct GNUNET_SOCIAL_Host *host,
                             const char *method_name,
                             const struct GNUNET_ENV_Environment *env,
                             GNUNET_PSYC_TransmitNotifyData notify_data,
                             void *notify_data_cls,
                             enum GNUNET_SOCIAL_AnnounceFlags flags);


/**
 * Resume transmitting announcement.
 *
 * @param a
 *        The announcement to resume.
 */
void
GNUNET_SOCIAL_host_announce_resume (struct GNUNET_SOCIAL_Announcement *a);


/**
 * Cancel announcement.
 *
 * @param a
 *        The announcement to cancel.
 */
void
GNUNET_SOCIAL_host_announce_cancel (struct GNUNET_SOCIAL_Announcement *a);


/**
 * Obtain handle for a hosted place.
 *
 * The returned handle can be used to access the place API.
 *
 * @param host
 *        Handle for the host.
 *
 * @return Handle for the hosted place, valid as long as @a host is valid.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_host_get_place (struct GNUNET_SOCIAL_Host *host);


/**
 * Stop hosting a place.
 *
 * Invalidates host handle.
 *
 * @param host
 *        Host leaving the place.
 * @param keep_active
 *        Keep the place active after last host disconnected.
 * @param leave_cb
 *        Function called after the host left the place
 *        and disconnected from the social service.
 * @param leave_cls
 *        Closure for @a leave_cb.
 */
void
GNUNET_SOCIAL_host_leave (struct GNUNET_SOCIAL_Host *host,
                          int keep_active,
                          GNUNET_ContinuationCallback leave_cb,
                          void *leave_cls);


/**
 * Function called after the guest entered the local copy of the place.
 *
 * History and object query functions can be used after this call,
 * but new messages can't be sent or received.
 *
 * @param cls
 *        Closure.
 * @param result
 *        #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error, e.g. could not connect to the service, or
 *        could not resolve GNS name.
 * @param max_message_id
 *        Last message ID sent to the place.
 *        Or 0 if no messages have been sent to the place yet.
 */
typedef void
(*GNUNET_SOCIAL_GuestEnterCallback) (void *cls, int result,
                                     uint64_t max_message_id);


/**
 * Function called upon a guest receives a decision about entry to the place.
 *
 * @param is_admitted
 *   Is the guest admitted to the place?
 *   #GNUNET_YES    if admitted,
 *   #GNUNET_NO     if refused entry
 *   #GNUNET_SYSERR if the request could not be answered.
 * @param method_name
 *   Method for the message sent along with the decision.
 *   NULL if no message was sent.
 * @param env
 *   Environment with variables for the message.
 *   NULL if there are no variables.
 *   It has to be freed using GNUNET_ENV_environment_destroy()
 *   when it is not needed anymore.
 * @param data_size
 *   Size of @data.
 * @param data
 *   Payload of the message.
 */
typedef void
(*GNUNET_SOCIAL_EntryDecisionCallback) (void *cls,
                                        int is_admitted,
                                        const struct GNUNET_PSYC_Message *entry_resp);


/**
 * Request entry to a place as a guest.
 *
 * @param cfg Configuration to contact the social service.
 * @param ego  Identity of the guest.
 * @param crypto_address Public key of the place to enter.
 * @param origin Peer identity of the origin of the underlying multicast group.
 * @param relay_count Number of elements in the @a relays array.
 * @param relays Relays for the underlying multicast group.
 * @param method_name Method name for the message.
 * @param env Environment containing variables for the message, or NULL.
 * @param data Payload for the message to give to the enter callback.
 * @param data_size Number of bytes in @a data.
 * @param slicer Slicer to use for processing incoming requests from guests.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           const struct GNUNET_IDENTITY_Ego *ego,
                           const struct GNUNET_CRYPTO_EddsaPublicKey *place_key,
                           const struct GNUNET_PeerIdentity *origin,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_PSYC_Message *entry_msg,
                           struct GNUNET_SOCIAL_Slicer *slicer,
                           GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                           GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                           void *cls);


/**
 * Request entry to a place by name as a guest.
 *
 * @param cfg
 *        Configuration to contact the social service.
 * @param ego
 *        Identity of the guest.
 * @param gns_name
 *        GNS name of the place to enter.  Either in the form of
 *        'room.friend.gnu', or 'NYMPUBKEY.zkey'.  This latter case refers to
 *        the 'PLACE' record of the empty label ("+") in the GNS zone with the
 *        nym's public key 'NYMPUBKEY', and can be used to request entry to a
 *        pseudonym's place directly.
 * @param password
 *        Password to decrypt the record, or NULL for cleartext records.
 * @param join_msg
 *        Entry request message.
 * @param slicer
 *        Slicer to use for processing incoming requests from guests.
 * @param local_enter_cb
 *        Called upon connection established to the social service.
 * @param entry_decision_cb
 *        Called upon receiving entry decision.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter_by_name (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                   const struct GNUNET_IDENTITY_Ego *ego,
                                   const char *gns_name, const char *password,
                                   const struct GNUNET_PSYC_Message *join_msg,
                                   struct GNUNET_SOCIAL_Slicer *slicer,
                                   GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                                   GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                                   void *cls);


/**
 * Flags for talking to the host of a place.
 */
enum GNUNET_SOCIAL_TalkFlags
{
  GNUNET_SOCIAL_TALK_NONE = 0
};


/**
 * A talk request.
 */
struct GNUNET_SOCIAL_TalkRequest;


/**
 * Talk to the host of the place.
 *
 * @param place
 *        Place where we want to talk to the host.
 * @param method_name
 *        Method to invoke on the host.
 * @param env
 *        Environment containing variables for the message, or NULL.
 * @param notify_data
 *        Function to use to get the payload for the method.
 * @param notify_data_cls
 *        Closure for @a notify_data.
 * @param flags
 *        Flags for the message being sent.
 *
 * @return NULL if we are already trying to talk to the host,
 *         otherwise handle to cancel the request.
 */
struct GNUNET_SOCIAL_TalkRequest *
GNUNET_SOCIAL_guest_talk (struct GNUNET_SOCIAL_Guest *guest,
                          const char *method_name,
                          const struct GNUNET_ENV_Environment *env,
                          GNUNET_PSYC_TransmitNotifyData notify_data,
                          void *notify_data_cls,
                          enum GNUNET_SOCIAL_TalkFlags flags);


/**
 * Resume talking to the host of the place.
 *
 * @param tr
 *        Talk request to resume.
 */
void
GNUNET_SOCIAL_guest_talk_resume (struct GNUNET_SOCIAL_TalkRequest *tr);


/**
 * Cancel talking to the host of the place.
 *
 * @param tr
 *        Talk request to cancel.
 */
void
GNUNET_SOCIAL_guest_talk_cancel (struct GNUNET_SOCIAL_TalkRequest *tr);


/**
 * Leave a place temporarily or permanently.
 *
 * Notifies the owner of the place about leaving, and destroys the place handle.
 *
 * @param place
 *        Place to leave.
 * @param keep_active
 *        Keep place active after last application disconnected.
 *        #GNUNET_YES or #GNUNET_NO
 * @param env
 *        Optional environment for the leave message if @a keep_active
 *        is #GNUNET_NO.  NULL if not needed.
 * @param leave_cb
 *        Called upon disconnecting from the social service.
 */
void
GNUNET_SOCIAL_guest_leave (struct GNUNET_SOCIAL_Guest *gst,
                           int keep_active,
                           struct GNUNET_ENV_Environment *env,
                           GNUNET_ContinuationCallback leave_cb,
                           void *leave_cls);


/**
 * Obtain handle for a place entered as guest.
 *
 * The returned handle can be used to access the place API.
 *
 * @param guest  Handle for the guest.
 *
 * @return Handle for the place, valid as long as @a guest is valid.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_guest_get_place (struct GNUNET_SOCIAL_Guest *guest);


/**
 * A history request.
 */
struct GNUNET_SOCIAL_HistoryRequest;


/**
 * Learn about the history of a place.
 *
 * Messages are returned through the @a slicer function
 * and have the #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * @param place
 *        Place we want to learn more about.
 * @param start_message_id
 *        First historic message we are interested in.
 * @param end_message_id
 *        Last historic message we are interested in (inclusive).
 * @param method_prefix
 *        Only retrieve messages with this method prefix.
 * @param flags
 *        OR'ed GNUNET_PSYC_HistoryReplayFlags
 * @param slicer
 *        Slicer to use for retrieved messages.
 *        Can be the same as the slicer of the place.
 * @param result_cb
 *        Function called after all messages retrieved.
 *        NULL if not needed.
 * @param cls Closure for @a result_cb.
 */
struct GNUNET_SOCIAL_HistoryRequest *
GNUNET_SOCIAL_place_history_replay (struct GNUNET_SOCIAL_Place *plc,
                                    uint64_t start_message_id,
                                    uint64_t end_message_id,
                                    const char *method_prefix,
                                    uint32_t flags,
                                    struct GNUNET_SOCIAL_Slicer *slicer,
                                    GNUNET_ResultCallback result_cb,
                                    void *cls);


/**
 * Learn about the history of a place.
 *
 * Sends messages through the slicer function of the place where
 * start_message_id <= message_id <= end_message_id.
 * The messages will have the #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param place
 *        Place we want to learn more about.
 * @param message_limit
 *        Maximum number of historic messages we are interested in.
 * @param result_cb
 *        Function called after all messages retrieved.
 *        NULL if not needed.
 * @param cls Closure for @a result_cb.
 */
struct GNUNET_SOCIAL_HistoryRequest *
GNUNET_SOCIAL_place_history_replay_latest (struct GNUNET_SOCIAL_Place *plc,
                                           uint64_t message_limit,
                                           const char *method_prefix,
                                           uint32_t flags,
                                           struct GNUNET_SOCIAL_Slicer *slicer,
                                           GNUNET_ResultCallback result_cb,
                                           void *cls);

/**
 * Cancel learning about the history of a place.
 *
 * @param hist
 *        History lesson to cancel.
 */
void
GNUNET_SOCIAL_place_history_replay_cancel (struct GNUNET_SOCIAL_HistoryRequest *hist);


struct GNUNET_SOCIAL_LookHandle;


/**
 * Look at a particular object in the place.
 *
 * The best matching object is returned (its name might be less specific than
 * what was requested).
 *
 * @param place
 *        The place to look the object at.
 * @param full_name
 *        Full name of the object.
 * @param value_size
 *        Set to the size of the returned value.
 *
 * @return NULL if there is no such object at this place.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look_at (struct GNUNET_SOCIAL_Place *plc,
                             const char *full_name,
                             GNUNET_PSYC_StateVarCallback var_cb,
                             GNUNET_ResultCallback result_cb,
                             void *cls);

/**
 * Look for objects in the place with a matching name prefix.
 *
 * @param place
 *        The place to look its objects at.
 * @param name_prefix
 *        Look at objects with names beginning with this value.
 * @param var_cb
 *        Function to call for each object found.
 * @param cls
 *        Closure for callback function.
 *
 * @return Handle that can be used to stop looking at objects.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look_for (struct GNUNET_SOCIAL_Place *plc,
                              const char *name_prefix,
                              GNUNET_PSYC_StateVarCallback var_cb,
                              GNUNET_ResultCallback result_cb,
                              void *cls);


/**
 * Stop looking at objects.
 *
 * @param lh Look handle to stop.
 */
void
GNUNET_SOCIAL_place_look_cancel (struct GNUNET_SOCIAL_LookHandle *lh);


/**
 * Add public key to the GNS zone of the @e ego.
 *
 * @param cfg
 *        Configuration.
 * @param ego
 *        Ego.
 * @param name
 *        The name for the PKEY record to put in the zone.
 * @param nym_pub_key
 *        Public key of nym to add.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 */
void
GNUNET_SOCIAL_zone_add_pkey (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const struct GNUNET_IDENTITY_Ego *ego,
                             const char *name,
                             const struct GNUNET_CRYPTO_EcdsaPublicKey *nym_pub_key,
                             struct GNUNET_TIME_Absolute expiration_time,
                             GNUNET_NAMESTORE_ContinuationWithStatus result_cb,
                             void *result_cls);


/**
 * Handle for place notifications.
 */
struct GNUNET_SOCIAL_PlaceListenHandle;


/**
 * Notification about a place entered as host.
 */
typedef void
(*GNUNET_SOCIAL_PlaceNotifyHostCallback) (void *cls,
                                          const struct GNUNET_CRYPTO_EddsaPrivateKey *place_key,
                                          enum GNUNET_PSYC_Policy policy);


/**
 * Notification about a place entered as guest.
 */
typedef void
(*GNUNET_SOCIAL_PlaceNotifyGuestCallback) (void *cls,
                                           const struct GNUNET_CRYPTO_EddsaPublicKey *place_key,
                                           const struct GNUNET_PeerIdentity *origin,
                                           uint32_t relay_count,
                                           const struct GNUNET_PeerIdentity *relays,
                                           const struct GNUNET_PSYC_Message *entry_msg);


/**
 * Start listening for entered places as host or guest.
 *
 * The @notify_host and @notify_guest functions are
 * initially called with the full list of entered places,
 * then later each time a new place is entered.
 *
 * @param cfg
 *        Configuration.
 * @param ego
 *        Listen for places of this ego.
 * @param notify_host
 *        Function to notify about a place entered as host.
 * @param notify_guest
 *        Function to notify about a place entered as guest..
 * @param notify_cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to stop listening.
 */
struct GNUNET_SOCIAL_PlaceListenHandle *
GNUNET_SOCIAL_place_listen_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                  const struct GNUNET_IDENTITY_Ego *ego,
                                  GNUNET_SOCIAL_PlaceNotifyHostCallback notify_host,
                                  GNUNET_SOCIAL_PlaceNotifyGuestCallback notify_guest,
                                  void *notify_cls);


/**
 * Stop listening for entered places.
 *
 * @param h
 *        Listen handle.
 */
void
GNUNET_SOCIAL_place_listen_stop (struct GNUNET_SOCIAL_PlaceListenHandle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SOCIAL_SERVICE_H */
#endif
/* end of gnunet_social_service.h */
