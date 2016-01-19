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
 * Social service; implements social interactions through the PSYC service.
 */

/** @defgroup social Social service
Social interactions through the PSYC service.

# Overview

The social service provides an API for social interactions based on a one-to-many messaging model.
It manages subscriptions of applications to places, provides messaging functionality in places,
allows access to the local message history and manages the GNS zone of _egos_ (user identities).

The service stores private and public keys of subscribed places, as well as files received in subscribed places.

# Concepts and terminology

## Ego, Nym

An _ego_ is an identity of a user, a private-public key pair.
A _nym_ is an identity of another user in the network, identified by its public key.
Each user can have multiple identities.

struct GNUNET_SOCIAL_Ego and struct GNUNET_SOCIAL_Nym represents one of these identities.

## Place, Host, Guest

A _place_ is where social interactions happen.  It is owned and created by an _ego_.
Creating a new place happens by an _ego_ entering a new place as a _host_,
where _guests_ can enter later to receive messages sent to the place.

A place is identified by its public key.

- struct GNUNET_SOCIAL_Host represents a place entered as host,
- struct GNUNET_SOCIAL_Guest is used for a place entered as guest.
- A struct GNUNET_SOCIAL_Place can be obtained for both a host and guest place
  using GNUNET_SOCIAL_host_get_place() and GNUNET_SOCIAL_guest_get_place()
  and can be used with API functions common to hosts and guests.

## History

Messages sent to places are stored locally by the PSYCstore service, and can be queried any time.
GNUNET_SOCIAL_history_replay_latest() retrieves the latest N messages sent to the place,
while GNUNET_SOCIAL_history_replay() is used to query a given message ID range.

## GNU Name System

The GNU Name System is used for assigning human-readable names to nyms and places.
There's a _GNS zone_ corresponding to each _nym_.
An _ego_ can publish PKEY and PLACE records in its own zone, pointing to nyms and places, respectively.

## Announcement, talk request

The host can _announce_ messages to the place, using GNUNET_SOCIAL_host_announce().
Guests can send _talk_ requests to the host, using GNUNET_SOCIAL_guest_talk().
The host receives talk requests of guests and can _relay_ them to the place,
or process it using a message handler function.

# Using the API

## Connecting to the service

A client first establishes an _application connection_ to the service using
GNUNET_SOCIAL_app_connect() providing its _application ID_, then receives the
public keys of subscribed places and available egos and in response.

## Reconnecting to places

Then the application can reconnect to its subscribed places by establishing
_place connections_ with GNUNET_SOCIAL_host_enter_reconnect() and
GNUNET_SOCIAL_guest_enter_reconnect().

## Subscribing to a place

Entering and subscribing a new host or guest place is done using
GNUNET_SOCIAL_host_enter() and GNUNET_SOCIAL_guest_enter().

## Disconnecting from a place

An application can disconnect from a place while the social service keeps its
network connection active, using GNUNET_SOCIAL_host_disconnect() and
GNUNET_SOCIAL_guest_disconnect().

## Leaving a place

To permanently leave a place, see GNUNET_SOCIAL_host_leave() and GNUNET_SOCIAL_guest_leave().
When leaving a place its network connections are closed and all applications are unsubscribed from the place.

# Methods

## _message

A message sent to the place.

### Environment

#### _id_reply_to
Message ID this message is in reply to.

#### _id_thread
Thread ID, the first message ID in the thread.

#### _nym_author__
Nym of the author.

#### _sig_author
Signature of the message body and its variables by the author.

## Data

Message body.

## _notice_place

Notification about a place.

TODO: Applications can decide to auto-subscribe to certain places,
e.g. files under a given size.

### Environment

#### Using GNS

##### _gns_place
GNS name of the place in a globally unique .zkey zone

#### Without GNS

##### _key_pub_place
Public key of place

##### _peer_origin
Peer ID of origin

##### _list_peer_relays
List of peer IDs of relays

## _notice_place_file

Notification about a place hosting a file.

### Environment

The environment of _notice_place above, plus the following:

#### _size_file
Size of file

#### _mime_file
MIME type of file

#### _name_file
Name of file

#### _description_file
Description of file

## _file

Messages with a _file method contain a file,
which is saved to disk upon receipt at the following location:
$GNUNET_DATA_HOME/social/files/<H(place_pub)>/<message_id>

### Environment

#### _size_file
Size of file

#### _mime_file
MIME type of file

#### _name_file
Name of file

#### _description_file
Description of file

@{
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
#include "gnunet_psyc_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_psyc_service.h"


/**
 * Version number of GNUnet Social API.
 */
#define GNUNET_SOCIAL_VERSION 0x00000000

/**
 * Maximum size of client ID including '\0' terminator.
 */
#define GNUNET_SOCIAL_APP_MAX_ID_SIZE 256

enum GNUNET_SOCIAL_MsgProcFlags {
  GNUNET_SOCIAL_MSG_PROC_NONE = 0,
  GNUNET_SOCIAL_MSG_PROC_RELAY = 1,
  GNUNET_SOCIAL_MSG_PROC_SAVE= 2,
};

/**
 * Handle for an application.
 */
struct GNUNET_SOCIAL_App;

/**
 * Handle for an ego (own identity)
 */
struct GNUNET_SOCIAL_Ego;

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
 * Handle that can be used to reconnect to a place as host.
 */
struct GNUNET_SOCIAL_HostConnection;

/**
 * Handle that can be used to reconnect to a place as guest.
 */
struct GNUNET_SOCIAL_GuestConnection;

/**
 * Notification about an available identity.
 *
 * @param cls
 *        Closure.
 * @param pub_key
 *        Public key of ego.
 * @param name
 *        Name of ego.
 */
typedef void
(*GNUNET_SOCIAL_AppEgoCallback) (void *cls,
                                 struct GNUNET_SOCIAL_Ego *ego,
                                 const struct GNUNET_CRYPTO_EcdsaPublicKey *ego_pub_key,
                                 const char *name);


/**
 * Entry status of a place.
 */
enum GNUNET_SOCIAL_PlaceState
{
  /**
   * Place was once entered but left since.
   */
  GNUNET_SOCIAL_PLACE_STATE_ARCHIVED = 0,
  /**
   * Place is entered but not subscribed.
   */
  GNUNET_SOCIAL_PLACE_STATE_ENTERED = 1,
  /**
   * Place is entered and subscribed.
   */
  GNUNET_SOCIAL_PLACE_STATE_SUBSCRIBED = 2,
};


/**
 * Notification about a home.
 *
 * @param cls
 *        Closure.
 * @param hconn
 *        Host connection, to be used with GNUNET_SOCIAL_host_enter_reconnect()
 * @param ego
 *        Ego used to enter the place.
 * @param place_pub_key
 *        Public key of the place.
 * @param place_state
 *        @see enum GNUNET_SOCIAL_PlaceState
 */
typedef void
(*GNUNET_SOCIAL_AppHostPlaceCallback) (void *cls,
                                       struct GNUNET_SOCIAL_HostConnection *hconn,
                                       struct GNUNET_SOCIAL_Ego *ego,
                                       const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                                       enum GNUNET_SOCIAL_PlaceState place_state);

/**
 * Notification about a place.
 *
 * @param cls
 *        Closure.
 * @param gconn
 *        Guest connection, to be used with GNUNET_SOCIAL_guest_enter_reconnect()
 * @param ego
 *        Ego used to enter the place.
 * @param place_pub_key
 *        Public key of the place.
 * @param place_state
 *        @see enum GNUNET_SOCIAL_PlaceState
 */
typedef void
(*GNUNET_SOCIAL_AppGuestPlaceCallback) (void *cls,
                                        struct GNUNET_SOCIAL_GuestConnection *gconn,
                                        struct GNUNET_SOCIAL_Ego *ego,
                                        const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                                        enum GNUNET_SOCIAL_PlaceState place_state);


/**
 * Establish application connection to the social service.
 *
 * The @host_place_cb and @guest_place_cb functions are
 * initially called for each entered places,
 * then later each time a new place is entered with the current app ID.
 *
 * @param cfg
 *        Configuration.
 * @param ego_cb
 *        Function to notify about an available ego.
 * @param host_cb
 *        Function to notify about a place entered as host.
 * @param guest_cb
 *        Function to notify about a place entered as guest.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to stop listening.
 */
struct GNUNET_SOCIAL_App *
GNUNET_SOCIAL_app_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           const char *id,
                           GNUNET_SOCIAL_AppEgoCallback ego_cb,
                           GNUNET_SOCIAL_AppHostPlaceCallback host_cb,
                           GNUNET_SOCIAL_AppGuestPlaceCallback guest_cb,
                           void *cls);


/**
 * Disconnect app.
 *
 * @param c
 *        App handle.
 */
void
GNUNET_SOCIAL_app_disconnect (struct GNUNET_SOCIAL_App *app);


/**
 * Get the public key of @a ego.
 *
 * @param ego
 *        Ego.
 *
 * @return Public key of ego.
 */
const struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_ego_get_pub_key (const struct GNUNET_SOCIAL_Ego *ego);


/**
 * Get the name of @a ego.
 *
 * @param ego
 *        Ego.
 *
 * @return Public key of @a ego.
 */
const char *
GNUNET_SOCIAL_ego_get_name (const struct GNUNET_SOCIAL_Ego *ego);


/**
 * Get the public key of a @a nym.
 *
 * Suitable, for example, to be used with GNUNET_SOCIAL_zone_add_nym().
 *
 * @param nym
 *        Pseudonym to map to a cryptographic identifier.
 *
 * @return Public key of nym.
 */
const struct GNUNET_CRYPTO_EcdsaPublicKey *
GNUNET_SOCIAL_nym_get_pub_key (const struct GNUNET_SOCIAL_Nym *nym);


/**
 * Get the hash of the public key of a @a nym.
 *
 * @param nym
 *        Pseudonym to map to a cryptographic identifier.
 *
 * @return Hash of the public key of nym.
 */
const struct GNUNET_HashCode *
GNUNET_SOCIAL_nym_get_pub_key_hash (const struct GNUNET_SOCIAL_Nym *nym);


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
                                     struct GNUNET_PSYC_Environment *env,
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
                                   struct GNUNET_PSYC_Environment *env);


/**
 * Function called after the host entered a home.
 *
 * @param cls
 *        Closure.
 * @param result
 *        #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error.
 * @param place_pub_key
 *        Public key of home.
 * @param max_message_id
 *        Last message ID sent to the channel.
 *        Or 0 if no messages have been sent to the place yet.
 */
typedef void
(*GNUNET_SOCIAL_HostEnterCallback) (void *cls, int result,
                                    const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
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
 * @param enter_cb
 *        Function called when the place is entered and ready to use.
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
GNUNET_SOCIAL_host_enter (const struct GNUNET_SOCIAL_App *app,
                          const struct GNUNET_SOCIAL_Ego *ego,
                          enum GNUNET_PSYC_Policy policy,
                          struct GNUNET_PSYC_Slicer *slicer,
                          GNUNET_SOCIAL_HostEnterCallback enter_cb,
                          GNUNET_SOCIAL_AnswerDoorCallback answer_door_cb,
                          GNUNET_SOCIAL_FarewellCallback farewell_cb,
                          void *cls);


/**
 * Reconnect to an already entered place as host.
 *
 * @param hconn
 *        Host connection handle.
 *        @see GNUNET_SOCIAL_app_connect() & GNUNET_SOCIAL_AppHostPlaceCallback()
 * @param slicer
 *        Slicer to handle incoming messages.
 * @param enter_cb
 *        Function called when the place is entered and ready to use.
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
GNUNET_SOCIAL_host_enter_reconnect (struct GNUNET_SOCIAL_HostConnection *hconn,
                                    struct GNUNET_PSYC_Slicer *slicer,
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
 * Sends a _notice_place_leave announcement to the home.
 *
 * The @a nym reference will remain valid until the
 * #GNUNET_SOCIAL_FarewellCallback is invoked,
 * which should be very soon after this call.
 *
 * @param host
 *        Host of the place.
 * @param nym
 *        Handle for the entity to be ejected.
 * @param env
 *        Environment for the message or NULL.
 *        _nym is set to @e nym regardless whether an @e env is provided.
 */
void
GNUNET_SOCIAL_host_eject (struct GNUNET_SOCIAL_Host *host,
                          const struct GNUNET_SOCIAL_Nym *nym,
                          struct GNUNET_PSYC_Environment *env);


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
                             const struct GNUNET_PSYC_Environment *env,
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
 * Allow relaying messages from guests matching a given @a method_prefix.
 *
 * @param host
 *        The host.
 * @param method_prefix
 *        Method prefix to allow.
 */
void
GNUNET_SOCIAL_host_relay_allow_method (struct GNUNET_SOCIAL_Host *host,
                                       const char *method_prefix);


/**
 * Allow relaying changes to objects of the place.
 *
 * Only applies to messages with an allowed method name.
 * @see GNUNET_SCOIAL_host_relay_allow_method()
 *
 * @param host
 *        The host.
 * @param object_prefix
 *        Object prefix to allow modifying.
 */
void
GNUNET_SOCIAL_host_relay_allow_method (struct GNUNET_SOCIAL_Host *host,
                                       const char *object_prefix);


/**
 * Stop relaying messages from guests.
 *
 * Remove all allowed relay rules.
 *
 *
 *
 */
void
GNUNET_SOCIAL_host_relay_stop (struct GNUNET_SOCIAL_Host *host);


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
 * Disconnect from a home.
 *
 * Invalidates host handle.
 *
 * @param hst
 *        The host to disconnect.
 * @param disconnect_cb
 *        Function called after disconnected from the service.
 * @param cls
 *        Closure for @a disconnect_cb.
 */
void
GNUNET_SOCIAL_host_disconnect (struct GNUNET_SOCIAL_Host *hst,
                               GNUNET_ContinuationCallback disconnect_cb,
                               void *cls);


/**
 * Stop hosting a home.
 *
 * Sends a _notice_place_closed announcement to the home.
 * Invalidates host handle.
 *
 * @param hst
 *        Host leaving.
 * @param env
 *        Environment for the message or NULL.
 * @param disconnect_cb
 *        Function called after the host left the place
 *        and disconnected from the service.
 * @param cls
 *        Closure for @a disconnect_cb.
 */
void
GNUNET_SOCIAL_host_leave (struct GNUNET_SOCIAL_Host *hst,
                          const struct GNUNET_PSYC_Environment *env,
                          GNUNET_ContinuationCallback disconnect_cb,
                          void *cls);


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
 *        Is the guest admitted to the place?
 *        #GNUNET_YES    if admitted,
 *        #GNUNET_NO     if refused entry,
 *        #GNUNET_SYSERR if the request could not be answered.
 * @param data
 *        Entry response message.
 */
typedef void
(*GNUNET_SOCIAL_EntryDecisionCallback) (void *cls,
                                        int is_admitted,
                                        const struct GNUNET_PSYC_Message *entry_resp);


/**
 * Request entry to a place as a guest.
 *
 * @param app
 *        Application handle.
 * @param ego
 *        Identity of the guest.
 * @param place_pub_key
 *        Public key of the place to enter.
 * @param flags
 *        Flags for the entry.
 * @param origin
 *        Peer identity of the origin of the underlying multicast group.
 * @param relay_count
 *        Number of elements in the @a relays array.
 * @param relays
 *        Relays for the underlying multicast group.
 * @param method_name
 *        Method name for the message.
 * @param env
 *        Environment containing variables for the message, or NULL.
 * @param data
 *        Payload for the message to give to the enter callback.
 * @param data_size
 *        Number of bytes in @a data.
 * @param slicer
 *        Slicer to use for processing incoming requests from guests.
 *
 * @return NULL on errors, otherwise handle for the guest.
 */
struct GNUNET_SOCIAL_Guest *
GNUNET_SOCIAL_guest_enter (const struct GNUNET_SOCIAL_App *app,
                           const struct GNUNET_SOCIAL_Ego *ego,
                           const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                           enum GNUNET_PSYC_SlaveJoinFlags flags,
                           const struct GNUNET_PeerIdentity *origin,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_PSYC_Message *entry_msg,
                           struct GNUNET_PSYC_Slicer *slicer,
                           GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                           GNUNET_SOCIAL_EntryDecisionCallback entry_dcsn_cb,
                           void *cls);


/**
 * Request entry to a place by name as a guest.
 *
 * @param app
 *        Application handle.
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
GNUNET_SOCIAL_guest_enter_by_name (const struct GNUNET_SOCIAL_App *app,
                                   const struct GNUNET_SOCIAL_Ego *ego,
                                   const char *gns_name,
                                   const char *password,
                                   const struct GNUNET_PSYC_Message *join_msg,
                                   struct GNUNET_PSYC_Slicer *slicer,
                                   GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
                                   GNUNET_SOCIAL_EntryDecisionCallback entry_decision_cb,
                                   void *cls);


/**
 * Reconnect to an already entered place as guest.
 *
 * @param gconn
 *        Guest connection handle.
 *        @see GNUNET_SOCIAL_app_connect() & GNUNET_SOCIAL_AppGuestPlaceCallback()
 * @param flags
 *        Flags for the entry.
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
GNUNET_SOCIAL_guest_enter_reconnect (struct GNUNET_SOCIAL_GuestConnection *gconn,
                                     enum GNUNET_PSYC_SlaveJoinFlags flags,
                                     struct GNUNET_PSYC_Slicer *slicer,
                                     GNUNET_SOCIAL_GuestEnterCallback local_enter_cb,
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
                          const struct GNUNET_PSYC_Environment *env,
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
 * Disconnect from a place.
 *
 * Invalidates guest handle.
 *
 * @param gst
 *        The guest to disconnect.
 * @param disconnect_cb
 *        Function called after disconnected from the service.
 * @param cls
 *        Closure for @a disconnect_cb.
 */
void
GNUNET_SOCIAL_guest_disconnect (struct GNUNET_SOCIAL_Guest *gst,
                                GNUNET_ContinuationCallback disconnect_cb,
                                void *cls);


/**
 * Leave a place temporarily or permanently.
 *
 * Notifies the owner of the place about leaving, and destroys the place handle.
 *
 * @param place
 *        Place to leave.
 * @param env
 *        Optional environment for the leave message if @a keep_active
 *        is #GNUNET_NO.  NULL if not needed.
 * @param disconnect_cb
 *        Called upon disconnecting from the social service.
 */
void
GNUNET_SOCIAL_guest_leave (struct GNUNET_SOCIAL_Guest *gst,
                           struct GNUNET_PSYC_Environment *env,
                           GNUNET_ContinuationCallback disconnect_cb,
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
 * Set message processing @a flags for a @a method_prefix.
 *
 * @param plc
 *        Place.
 * @param method_prefix
 *        Method prefix @a flags apply to.
 * @param flags
 *        The flags that apply to a matching @a method_prefix.
 */
void
GNUNET_SOCIAL_place_msg_proc_set (struct GNUNET_SOCIAL_Place *plc,
                                  const char *method_prefix,
                                  enum GNUNET_SOCIAL_MsgProcFlags flags);

/**
 * Clear all message processing flags previously set for this place.
 */
void
GNUNET_SOCIAL_place_msg_proc_clear (struct GNUNET_SOCIAL_Place *plc);


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
                                    struct GNUNET_PSYC_Slicer *slicer,
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
                                           struct GNUNET_PSYC_Slicer *slicer,
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
 * Advertise a @e place in the GNS zone of @a ego.
 *
 * @param app
 *        Application handle.
 * @param ego
 *        Ego.
 * @param place_pub_key
 *        Public key of place to add.
 * @param name
 *        The name for the PLACE record to put in the zone.
 * @param password
 *        Password used to encrypt the record or NULL to keep it cleartext.
 * @param relay_count
 *        Number of elements in the @a relays array.
 * @param relays
 *        List of relays to put in the PLACE record to advertise
 *        as entry points to the place in addition to the origin.
 * @param expiration_time
 *        Expiration time of the record, use 0 to remove the record.
 * @param result_cb
 *        Function called with the result of the operation.
 * @param result_cls
 *        Closure for @a result_cb
 *
 * @return #GNUNET_OK if the request was sent,
 *         #GNUNET_SYSERR on error, e.g. the name/password is too long.
 */
int
GNUNET_SOCIAL_zone_add_place (const struct GNUNET_SOCIAL_App *app,
                              const struct GNUNET_SOCIAL_Ego *ego,
                              const char *name,
                              const char *password,
                              const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key,
                              const struct GNUNET_PeerIdentity *origin,
                              uint32_t relay_count,
                              const struct GNUNET_PeerIdentity *relays,
                              struct GNUNET_TIME_Absolute expiration_time,
                              GNUNET_ResultCallback result_cb,
                              void *result_cls);


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
 *
 * @return #GNUNET_OK if the request was sent,
 *         #GNUNET_SYSERR on error, e.g. the name is too long.
 */
int
GNUNET_SOCIAL_zone_add_nym (const struct GNUNET_SOCIAL_App *app,
                            const struct GNUNET_SOCIAL_Ego *ego,
                            const char *name,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *nym_pub_key,
                            struct GNUNET_TIME_Absolute expiration_time,
                            GNUNET_ResultCallback result_cb,
                            void *result_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SOCIAL_SERVICE_H */
#endif

/** @} */  /* end of group */
