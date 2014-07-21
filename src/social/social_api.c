/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file social/social_api.c
 * @brief Social service; implements social interactions using the PSYC service.
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_service.h"
#include "gnunet_social_service.h"
#include "social.h"


/**
 * Handle for a pseudonym of another user in the network.
 */
struct GNUNET_SOCIAL_Nym
{

};


/**
 * Handle for a place where social interactions happen.
 */
struct GNUNET_SOCIAL_Place
{

};


/**
 * Host handle for a place that we entered.
 */
struct GNUNET_SOCIAL_Host
{

};


/**
 * Guest handle for place that we entered.
 */
struct GNUNET_SOCIAL_Guest
{

};


/**
 * Handle to an implementation of try-and-slice.
 */
struct GNUNET_SOCIAL_Slicer
{

};


/**
 * Handle for an announcement request.
 */
struct GNUNET_SOCIAL_Announcement
{

};


struct GNUNET_SOCIAL_WatchHandle
{

};


struct GNUNET_SOCIAL_LookHandle
{

};


/**
 * A talk request.
 */
struct GNUNET_SOCIAL_TalkRequest
{

};


/**
 * A history lesson.
 */
struct GNUNET_SOCIAL_HistoryLesson
{

};




/**
 * Create a try-and-slice instance.
 *
 * @return A new try-and-slice construct.
 */
struct GNUNET_SOCIAL_Slicer *
GNUNET_SOCIAL_slicer_create (void)
{
  return NULL;
}


/**
 * Add a method to the try-and-slice instance.
 *
 * A slicer processes messages and calls methods that match a message. A match
 * happens whenever the method name of a message starts with the method_name
 * parameter given here.
 *
 * @param slicer The try-and-slice instance to extend.
 * @param method_name Name of the given method, use empty string for default.
 * @param method Method to invoke.
 * @param method_cls Closure for method.
 */
void
GNUNET_SOCIAL_slicer_add (struct GNUNET_SOCIAL_Slicer *slicer,
                          const char *method_name,
                          GNUNET_SOCIAL_MethodCallback method_cb,
                          void *cls)
{

}


/**
 * Remove a registered method from the try-and-slice instance.
 *
 * @param slicer The try-and-slice instance.
 * @param method_name Name of the method to remove.
 * @param method Method handler.
 */
void
GNUNET_SOCIAL_slicer_remove (struct GNUNET_SOCIAL_Slicer *slicer,
                             const char *method_name,
                             GNUNET_SOCIAL_MethodCallback method_cb)
{

}

/**
 * Destroy a given try-and-slice instance.
 *
 * @param slicer slicer to destroy
 */
void
GNUNET_SOCIAL_slicer_destroy (struct GNUNET_SOCIAL_Slicer *slicer)
{

}


/**
 * Enter a place as host.
 *
 * A place is created upon first entering, and it is active until permanently
 * left using GNUNET_SOCIAL_host_leave().
 *
 * @param cfg  Configuration to contact the social service.
 * @param place_keyfile  File with the private-public key pair of the place,
 *        created if the file does not exist; pass NULL for ephemeral places.
 * @param policy  Policy specifying entry and history restrictions of the place.
 * @param ego  Identity of the host.
 * @param slicer  Slicer to handle incoming messages.
 * @param listener_cb  Function to handle new nyms that want to enter.
 * @param farewell_cb  Function to handle departing nyms.
 * @param cls  Closure for @a listener_cb and @a farewell_cb.
 *
 * @return Handle for the host.
 */
struct GNUNET_SOCIAL_Host *
GNUNET_SOCIAL_host_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_IDENTITY_Ego *ego,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *place_key,
                          enum GNUNET_PSYC_Policy policy,
                          struct GNUNET_SOCIAL_Slicer *slicer,
                          GNUNET_SOCIAL_HostEnterCallback enter_cb,
                          GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                          GNUNET_SOCIAL_FarewellCallback farewell_cb,
                          void *cls)
// struct GNUNET_SOCIAL_Host *
// GNUNET_SOCIAL_host_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
//                           const char *place_keyfile,
//                           enum GNUNET_PSYC_Policy policy,
//                           struct GNUNET_IDENTITY_Ego *ego,
//                           struct GNUNET_SOCIAL_Slicer *slicer,
//                           GNUNET_SOCIAL_AnswerDoorCallback listener_cb,
//                           GNUNET_SOCIAL_FarewellCallback farewell_cb,
//                           void *cls)
{
  return NULL;
}


/**
 * Admit @a nym to the place.
 *
 * The @a nym reference will remain valid until either the @a host or @a nym
 * leaves the place.
 *
 * @param host  Host of the place.
 * @param nym  Handle for the entity that wants to enter.
 */
void
GNUNET_SOCIAL_host_admit (struct GNUNET_SOCIAL_Host *host,
                          struct GNUNET_SOCIAL_Nym *nym)
{

}


/**
 * Throw @a nym out of the place.
 *
 * The @a nym reference will remain valid until the
 * #GNUNET_SOCIAL_FarewellCallback is invoked,
 * which should be very soon after this call.
 *
 * @param host  Host of the place.
 * @param nym  Handle for the entity to be ejected.
 */
void
GNUNET_SOCIAL_host_eject (struct GNUNET_SOCIAL_Host *host,
                          struct GNUNET_SOCIAL_Nym *nym)
{

}


/**
 * Refuse @a nym entry into the place.
 *
 * @param host  Host of the place.
 * @param nym Handle for the entity that wanted to enter.
 * @param method_name Method name for the rejection message.
 * @param env Environment containing variables for the message, or NULL.
 * @param data Data for the rejection message to send back.
 * @param data_size Number of bytes in @a data for method.
 */
void
GNUNET_SOCIAL_host_refuse_entry (struct GNUNET_SOCIAL_Host *host,
                                 struct GNUNET_SOCIAL_Nym *nym,
                                 const char *method_name,
                                 const struct GNUNET_ENV_Environment *env,
                                 const void *data,
                                 size_t data_size)
{

}


/**
 * Get the public key of a @a nym.
 *
 * Suitable, for example, to be used with GNUNET_NAMESTORE_zone_to_name().
 *
 * @param nym Pseudonym to map to a cryptographic identifier.
 * @param[out] nym_key Set to the public key of the nym.
 */
void
GNUNET_SOCIAL_nym_get_key (struct GNUNET_SOCIAL_Nym *nym,
                           struct GNUNET_CRYPTO_EddsaPublicKey *nym_key)
{

}


/**
 * Obtain the private-public key pair of the host.
 *
 * @param host  Host to get the key of.
 * @param[out] host_key  Set to the private-public key pair of the host.  The
 *                 public part is suitable for storing in GNS within a "PLACE"
 *                 record, along with peer IDs to join at.
 */
void
GNUNET_SOCIAL_host_get_key (struct GNUNET_SOCIAL_Host *host,
                            struct GNUNET_CRYPTO_EddsaPrivateKey *host_key)
{

}


/**
 * Advertise the place in the GNS zone of the @e ego of the @a host.
 *
 * @param host  Host of the place.
 * @param name The name for the PLACE record to put in the zone.
 * @param peer_count Number of elements in the @a peers array.
 * @param peers List of peers in the PLACE record that can be used to send join
 *        requests to.
 * @param expiration_time Expiration time of the record, use 0 to remove the record.
 * @param password Password used to encrypt the record.
 */
void
GNUNET_SOCIAL_host_advertise (struct GNUNET_SOCIAL_Host *host,
                              const char *name,
                              size_t peer_count,
                              const struct GNUNET_PeerIdentity *peers,
                              struct GNUNET_TIME_Relative expiration_time,
                              const char *password)
{

}


/**
 * Send a message to all nyms that are present in the place.
 *
 * This function is restricted to the host.  Nyms can only send requests
 * to the host who can decide to relay it to everyone in the place.
 *
 * @param host  Host of the place.
 * @param method_name Method to use for the announcement.
 * @param env  Environment containing variables for the message and operations
 *          on objects of the place.  Can be NULL.
 * @param notify Function to call to get the payload of the announcement.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for this announcement.
 *
 * @return NULL on error (announcement already in progress?).
 */
// struct GNUNET_SOCIAL_Announcement *
// GNUNET_SOCIAL_host_announce (struct GNUNET_SOCIAL_Host *host,
//                              const char *method_name,
//                              const struct GNUNET_ENV_Environment *env,
//                              GNUNET_CONNECTION_TransmitReadyNotify notify,
//                              void *notify_cls,
//                              enum GNUNET_SOCIAL_AnnounceFlags flags)
struct GNUNET_SOCIAL_Announcement *
GNUNET_SOCIAL_host_announce (struct GNUNET_SOCIAL_Host *host,
                             const char *method_name,
                             const struct GNUNET_ENV_Environment *env,
                             GNUNET_PSYC_TransmitNotifyData notify_data,
                             void *notify_data_cls,
                             enum GNUNET_SOCIAL_AnnounceFlags flags)
{
  return NULL;
}


/**
 * Cancel announcement.
 *
 * @param a The announcement to cancel.
 */
void
GNUNET_SOCIAL_host_announce_cancel (struct GNUNET_SOCIAL_Announcement *a)
{

}


/**
 * Obtain handle for a hosted place.
 *
 * The returned handle can be used to access the place API.
 *
 * @param host  Handle for the host.
 *
 * @return Handle for the hosted place, valid as long as @a host is valid.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_host_get_place (struct GNUNET_SOCIAL_Host *host)
{
  return NULL;
}


/**
 * Stop hosting a place.
 *
 * Invalidates host handle.
 *
 * @param host  Host leaving the place.
 * @param keep_active  Keep the place active after last host disconnected.
 */
void
GNUNET_SOCIAL_host_leave (struct GNUNET_SOCIAL_Host *host, int keep_active)
{

}


/**
 * Request entry to a place as a guest.
 *
 * @param cfg  Configuration to contact the social service.
 * @param ego  Identity of the guest.
 * @param address GNS name of the place to enter.  Either in the form of
 *        'room.friend.gnu', or 'NYMPUBKEY.zkey'.  This latter case refers to
 *        the 'PLACE' record of the empty label ("+") in the GNS zone with the
 *        nym's public key 'NYMPUBKEY', and can be used to request entry to a
 *        pseudonym's place directly.
 * @param method_name Method name for the message.
 * @param env Environment containing variables for the message, or NULL.
 * @param data Payload for the message to give to the enter callback.
 * @param data_size Number of bytes in @a data.
 * @param slicer Slicer to use for processing incoming requests from guests.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
// struct GNUNET_SOCIAL_Guest *
// GNUNET_SOCIAL_guest_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
//                            struct GNUNET_IDENTITY_Ego *ego,
//                            char *address,
//                            const char *method_name,
//                            const struct GNUNET_ENV_Environment *env,
//                            const void *data,
//                            size_t data_size,
//                            struct GNUNET_SOCIAL_Slicer *slicer)
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           struct GNUNET_IDENTITY_Ego *ego,
                           struct GNUNET_CRYPTO_EddsaPublicKey *place_key,
                           struct GNUNET_PeerIdentity *origin,
                           uint32_t relay_count,
                           struct GNUNET_PeerIdentity *relays,
                           const char *method_name,
                           const struct GNUNET_ENV_Environment *env,
                           const void *data,
                           size_t data_size,
                           struct GNUNET_SOCIAL_Slicer *slicer,
                           GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                           GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                           void *cls)
{
  return NULL;
}

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
GNUNET_SOCIAL_guest_enter2 (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            struct GNUNET_IDENTITY_Ego *ego,
                            struct GNUNET_CRYPTO_EddsaPublicKey *crypto_address,
                            struct GNUNET_PeerIdentity *origin,
                            size_t relay_count,
                            struct GNUNET_PeerIdentity *relays,
                            const char *method_name,
                            const struct GNUNET_ENV_Environment *env,
                            const void *data,
                            size_t data_size,
                            struct GNUNET_SOCIAL_Slicer *slicer)
{
  return NULL;
}


/**
 * Talk to the host of the place.
 *
 * @param place Place where we want to talk to the host.
 * @param method_name Method to invoke on the host.
 * @param env Environment containing variables for the message, or NULL.
 * @param notify Function to use to get the payload for the method.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being sent.
 *
 * @return NULL if we are already trying to talk to the host,
 *         otherwise handle to cancel the request.
 */
// struct GNUNET_SOCIAL_TalkRequest *
// GNUNET_SOCIAL_guest_talk (struct GNUNET_SOCIAL_Place *place,
//                           const char *method_name,
//                           const struct GNUNET_ENV_Environment *env,
//                           GNUNET_CONNECTION_TransmitReadyNotify notify,
//                           void *notify_cls,
//                           enum GNUNET_SOCIAL_TalkFlags flags)
struct GNUNET_SOCIAL_TalkRequest *
GNUNET_SOCIAL_guest_talk (struct GNUNET_SOCIAL_Guest *guest,
                          const char *method_name,
                          const struct GNUNET_ENV_Environment *env,
                          GNUNET_PSYC_TransmitNotifyData notify_data,
                          void *notify_data_cls,
                          enum GNUNET_SOCIAL_TalkFlags flags)
{
  return NULL;
}


/**
 * Cancel talking to the host of the place.
 *
 * @param tr Talk request to cancel.
 */
void
GNUNET_SOCIAL_guest_talk_cancel (struct GNUNET_SOCIAL_TalkRequest *tr)
{

}


/**
 * Leave a place permanently.
 *
 * Notifies the owner of the place about leaving, and destroys the place handle.
 *
 * @param place Place to leave permanently.
 * @param keep_active Keep place active after last application disconnected.
 */
void
// GNUNET_SOCIAL_guest_leave (struct GNUNET_SOCIAL_Place *place, int keep_active)
GNUNET_SOCIAL_guest_leave (struct GNUNET_SOCIAL_Guest *guest, int keep_active)
{

}


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
// GNUNET_SOCIAL_guest_get_place (struct GNUNET_SOCIAL_Host *guest)
GNUNET_SOCIAL_guest_get_place (struct GNUNET_SOCIAL_Guest *guest)
{
  return NULL;
}


/**
 * A history lesson.
 */
struct GNUNET_SOCIAL_HistoryLesson;

/**
 * Learn about the history of a place.
 *
 * Sends messages through the slicer function of the place where
 * start_message_id <= message_id <= end_message_id.
 * The messages will have the #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param place Place we want to learn more about.
 * @param start_message_id First historic message we are interested in.
 * @param end_message_id Last historic message we are interested in (inclusive).
 * @param slicer Slicer to use to process history.  Can be the same as the
 *               slicer of the place, as the HISTORIC flag allows distinguishing
 *               old messages from fresh ones.
 * @param finish_cb Function called after the last message in the history lesson
 *              is passed through the @a slicer. NULL if not needed.
 * @param finish_cb_cls Closure for @a finish_cb.
 * @return Handle to abort history lesson, never NULL (multiple lessons
 *         at the same time are allowed).
 */
struct GNUNET_SOCIAL_HistoryLesson *
GNUNET_SOCIAL_place_get_history (struct GNUNET_SOCIAL_Place *place,
                                 uint64_t start_message_id,
                                 uint64_t end_message_id,
                                 const struct GNUNET_SOCIAL_Slicer *slicer,
                                 void (*finish_cb)(void *),
                                 void *finish_cb_cls)
{
  return NULL;
}


/**
 * Stop processing messages from the history lesson.
 *
 * Must not be called after the finish callback of the history lesson is called.
 *
 * @param hist History lesson to cancel.
 */
void
GNUNET_SOCIAL_place_get_history_cancel (struct GNUNET_SOCIAL_HistoryLesson *hist)
{

}


struct GNUNET_SOCIAL_WatchHandle;

/**
 * Watch a place for changed objects.
 *
 * @param place Place to watch.
 * @param object_filter Object prefix to match.
 * @param state_cb Function to call when an object/state changes.
 * @param state_cb_cls Closure for callback.
 *
 * @return Handle that can be used to cancel watching.
 */
struct GNUNET_SOCIAL_WatchHandle *
GNUNET_SOCIAL_place_watch (struct GNUNET_SOCIAL_Place *place,
                           const char *object_filter,
                           GNUNET_PSYC_StateCallback state_cb,
                           void *state_cb_cls)
{
  return NULL;
}


/**
 * Cancel watching a place for changed objects.
 *
 * @param wh Watch handle to cancel.
 */
void
GNUNET_SOCIAL_place_watch_cancel (struct GNUNET_SOCIAL_WatchHandle *wh)
{

}


struct GNUNET_SOCIAL_LookHandle;


/**
 * Look at objects in the place with a matching name prefix.
 *
 * @param place The place to look its objects at.
 * @param name_prefix Look at objects with names beginning with this value.
 * @param state_cb Function to call for each object found.
 * @param state_cb_cls Closure for callback function.
 *
 * @return Handle that can be used to stop looking at objects.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look (struct GNUNET_SOCIAL_Place *place,
                          const char *name_prefix,
                          GNUNET_PSYC_StateCallback state_cb,
                          void *state_cb_cls)
{
  return NULL;
}


/**
 * Stop looking at objects.
 *
 * @param lh Look handle to stop.
 */
void
GNUNET_SOCIAL_place_look_cancel (struct GNUNET_SOCIAL_LookHandle *lh)
{

}



/**
 * Look at a particular object in the place.
 *
 * The best matching object is returned (its name might be less specific than
 * what was requested).
 *
 * @param place The place to look the object at.
 * @param full_name Full name of the object.
 * @param value_size Set to the size of the returned value.
 * @return NULL if there is no such object at this place.
 */
const void *
GNUNET_SOCIAL_place_look_at (struct GNUNET_SOCIAL_Place *place,
                             const char *full_name,
                             size_t *value_size)
{
  return NULL;
}




/* end of social_api.c */
