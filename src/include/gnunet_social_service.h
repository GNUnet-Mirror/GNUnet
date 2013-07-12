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
 * @file include/gnunet_social_service.h
 * @brief Social service; implements social functionality using the PSYC service.
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

#include "gnunet_util_lib.h"
#include "gnunet_psyc_lib.h"
#include "gnunet_psyc_service.h"
#include "gnunet_multicast_service.h"


/** 
 * Version number of GNUnet Social API.
 */
#define GNUNET_SOCIAL_VERSION 0x00000000

/** 
 * Handle for our own presence in the network (we can of course have
 * alter-egos).
 */
struct GNUNET_SOCIAL_Ego;

/** 
 * Handle for another user (who is likely pseudonymous) in the network.
 */
struct GNUNET_SOCIAL_Nym;

/** 
 * Handle for a place where social interactions happen.
 */
struct GNUNET_SOCIAL_Place;

/** 
 * Handle for a place that one of our egos hosts.
 */
struct GNUNET_SOCIAL_Home;

/** 
 * Handle to an implementation of try-and-slice.
 */
struct GNUNET_SOCIAL_Slicer;


/** 
 * Method called from SOCIAL upon receiving a message indicating a call
 * to a @e method.
 *
 * @param cls Closure.
 * @param full_method_name Original method name from PSYC (may be more
 *        specific than the registered method name due to try-and-slice matching).

 * @param message_id Unique message counter for this message
 *                   (unique only in combination with the given sender for
 *                    this channel).
 * @param header_length Number of modifiers in header.
 * @param header Modifiers present in the message.
 * @param data_off Byte offset of @a data in the overall data of the method.
 * @param data_size Number of bytes in @a data.
 * @param data Data stream given to the method (might not be zero-terminated 
 *             if data is binary).
 * @param frag Fragmentation status for the data.
 */
typedef int (*GNUNET_SOCIAL_Method)(void *cls,
				    const char *full_method_name,
				    uint64_t message_id,
                                    size_t header_length,
                                    GNUNET_PSYC_Modifier *header,
				    uint64_t data_off,
				    size_t data_size,
				    const void *data,
				    enum GNUNET_PSYC_FragmentStatus frag);


/** 
 * Create a try-and-slice instance.
 *
 * @return A new try-and-slice construct.
 */
struct GNUNET_SOCIAL_Slicer *
GNUNET_SOCIAL_slicer_create (void);


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
			  GNUNET_SOCIAL_Method method,
			  void *method_cls);

/* FIXME: No slicer_remove for now, is it needed? */

/** 
 * Destroy a given try-and-slice instance.
 *
 * @param slicer slicer to destroy
 */
void
GNUNET_SOCIAL_slicer_destroy (struct GNUNET_SOCIAL_Slicer *slicer);


/** 
 * Create an ego.
 *
 * Create an ego using the private key from the given file.  If the file does
 * not exist, a fresh key is created.
 *
 * @param keyfile Name of the file with the private key for the ego,
 *                NULL for ephemeral egos.
 * @return Handle to the ego, NULL on error.
 */
struct GNUNET_SOCIAL_Ego *
GNUNET_SOCIAL_ego_create (const char *keyfile);


/** 
 * Destroy a handle to an ego.
 *
 * @param ego Ego to destroy.
 */
void
GNUNET_SOCIAL_ego_destroy (struct GNUNET_SOCIAL_Ego *ego);


/** 
 * Function called asking for nym to be admitted to the place.
 *
 * Should call either GNUNET_SOCIAL_home_admit() or
 * GNUNET_SOCIAL_home_reject_entry() (possibly asynchronously).  If this owner
 * cannot decide, it is fine to call neither function, in which case hopefully
 * some other owner of the home exists that will make the decision. The @a nym
 * reference remains valid until the #GNUNET_SOCIAL_FarewellCallback is invoked
 * for it.
 *
 * @param cls Closure.
 * @param nym Handle for the user who wants to join.
 * @param header_length Number of modifiers in header.
 * @param header Modifiers present in the message.
 * @param msg_size Number of bytes in @a msg.
 * @param msg Payload given on enter (e.g. a password).
 */
typedef void (*GNUNET_SOCIAL_AnswerDoorCallback)(void *cls,
						 struct GNUNET_SOCIAL_Nym *nym,
                                                 size_t header_length,
                                                 GNUNET_PSYC_Modifier *header,
						 size_t msg_size,
						 const void *msg);


/** 
 * Function called when a @a nym leaves the place.
 * 
 * This is also called if the @a nym was never given permission to enter
 * (i.e. the @a nym stopped asking to get in).
 *
 * @param cls Closure.
 * @param nym Handle for the user who left.
 * @param header_length Number of modifiers in header.
 * @param header Modifiers present in the message.
 */
typedef void (*GNUNET_SOCIAL_FarewellCallback)(void *cls,
					       struct GNUNET_SOCIAL_Nym *nym,
                                               size_t header_length,
                                               GNUNET_PSYC_Modifier *header);


/** 
 * Enter a home where guests (nyms) can be hosted.
 *
 * A home is created upon first entering, and exists until
 * GNUNET_SOCIAL_home_destroy() is called. It can also be left temporarily using
 * GNUNET_SOCIAL_home_leave().
 *
 * @param cfg Configuration to contact the social service.
 * @param home_keyfile File with the private key for the home,
 * 		created if the file does not exist;
 *              pass NULL for ephemeral homes.
 * @param join_policy What is our policy for allowing people in?
 * @param ego Owner of the home (host).
 * @param slicer Slicer to handle guests talking.
 * @param listener_cb Function to handle new nyms that want to join.
 * @param farewell_cb Function to handle departing nyms.
 * @param cls Closure for @a listener_cb and @a farewell_cb.
 * @return Handle for a new home.
 */
struct GNUNET_SOCIAL_Home *
GNUNET_SOCIAL_home_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
			  const char *home_keyfile,
			  enum GNUNET_MULTICAST_JoinPolicy join_policy,
			  struct GNUNET_SOCIAL_Ego *ego,
			  struct GNUNET_SOCIAL_Slicer *slicer,
			  GNUNET_SOCIAL_AnswerDoorCallback listener_cb,
			  GNUNET_SOCIAL_FarewellCallback farewell_cb,
			  void *cls);


/** 
 * Admit @a nym to the @a home.
 *
 * The @a nym reference will remain valid until either the home is destroyed or
 * @a nym leaves.
 *
 * @param home Home to allow @a nym to join.
 * @param nym Handle for the entity that wants to join.
 */
void
GNUNET_SOCIAL_home_admit (struct GNUNET_SOCIAL_Home *home,
			  struct GNUNET_SOCIAL_Nym *nym);


/** 
 * Throw @a nym out of the @a home.
 *
 * The @a nym reference will remain valid until the
 * #GNUNET_SOCIAL_FarewellCallback is invoked,
 * which should be very soon after this call.
 *
 * @param home Home to eject @a nym from.
 * @param nym Handle for the entity to be ejected.
 */
void
GNUNET_SOCIAL_home_eject (struct GNUNET_SOCIAL_Home *home,
                          struct GNUNET_SOCIAL_Nym *nym);


/** 
 * Refuse @a nym entry into the @a home.
 *
 * @param home Home to disallow @a nym to join.
 * @param nym Handle for the entity that wanted to join.
 * @param method Method name to invoke on caller.
 * @param message_size Number of bytes in @a message for method.
 * @param message Rejection message to send back.
 *
 * FIXME: allow setting variables as well for the message
 */
void
GNUNET_SOCIAL_home_reject_entry (struct GNUNET_SOCIAL_Home *home,
				 struct GNUNET_SOCIAL_Nym *nym,
				 const char *method,
				 size_t message_size,
				 const void *message);


/** 
 * Get the identity of a user.
 *
 * Suitable, for example, to be used with GNUNET_NAMESTORE_zone_to_name().
 *
 * @param nym Pseudonym to map to a cryptographic identifier.
 * @param[out] identity Set to the identity of the nym (short hash of the public key).
 */
void
GNUNET_SOCIAL_nym_get_identity (struct GNUNET_SOCIAL_Nym *nym,
				struct GNUNET_CRYPTO_ShortHashCode *identity);


/** 
 * Obtain the (cryptographic, binary) address for the home.
 * 
 * @param home Home to get the (public) address from.
 * @param[out] crypto_address Address suitable for storing in GADS, i.e. in
 *        'HEX.place' or within the respective GADS record type ("PLACE")
 */
void
GNUNET_SOCIAL_home_get_address (struct GNUNET_SOCIAL_Home *home,
				struct GNUNET_HashCode *crypto_address);



/** 
 * Advertise @a home under @a name in the GADS zone of the @e ego.
 *
 * @param home The home to advertise.
 * @param name The name to put in the zone.
 * @param expiration_time Expiration time of the record, use 0 to remove the record.
 */
void
GNUNET_SOCIAL_home_advertise (struct GNUNET_SOCIAL_Home *home,
                              const char *name,
                              GNUNET_TIME_Relative expiration_time);



/** 
 * (Re)decorate the home by changing objects in it.
 *
 * If the operation is #GNUNET_PSYC_OP_SET then the decoration only
 * applies to the next announcement by the home owner.
 *
 * @param home The home to decorate.
 * @param operation Operation to perform on the object.
 * @param object_name Name of the object to modify.
 * @param object_value_size Size of the given @a object_value.
 * @param object_value Value to use for the modification.
 */
void
GNUNET_SOCIAL_home_decorate (struct GNUNET_SOCIAL_Home *home,
			     enum GNUNET_PSYC_Operator operation,
			     const char *object_name,
			     size_t object_value_size,
			     const void *object_value);


/** 
 * Handle for an announcement request.
 */
struct GNUNET_SOCIAL_Announcement;


/** 
 * Send a message to all nyms that are present in the home.
 *
 * This function is restricted to the home owner.  Nyms can only send requests
 * to the home owner who can decide to relay it to other guests.
 *
 * @param home Home to address the announcement to.
 * @param method_name Method to use for the announcement.
 * @param notify Function to call to get the payload of the announcement.
 * @param notify_cls Closure for @a notify.
 * @return NULL on error (announcement already in progress?).
 */
struct GNUNET_SOCIAL_Announcement *
GNUNET_SOCIAL_home_announce (struct GNUNET_SOCIAL_Home *home,
                             const char *method_name,
                             GNUNET_PSYC_OriginReadyNotify notify,
                             void *notify_cls);


/** 
 * Cancel announcement.
 *
 * @param a The announcement to cancel.
 */
void
GNUNET_SOCIAL_home_announce_cancel (struct GNUNET_SOCIAL_Announcement *a);


/** 
 * Convert our home to a place so we can access it via the place API.
 *
 * @param home Handle for the home.
 * @return Place handle for the same home, valid as long as @a home is valid;
 *         do NOT try to GNUNET_SOCIAL_place_leave() this place, it's your home!
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_home_to_place (struct GNUNET_SOCIAL_Home *home);


/** 
 * Leave a home temporarily, visitors can stay.
 *
 * After leaving, handling of incoming messages are left to other clients of the
 * social service, and stops after the last client exits.
 *
 * @param home Home to leave temporarily (handle becomes invalid).
 */
void
GNUNET_SOCIAL_home_away (struct GNUNET_SOCIAL_Home *home);


/** 
 * Destroy a home, all guests will be ejected.
 *
 * @param home Home to destroy.
 */
void
GNUNET_SOCIAL_home_destroy (struct GNUNET_SOCIAL_Home *home);

/** 
 * Request entry to a place (home hosted by someone else).
 *
 * @param cfg Configuration to contact the social service.
 * @param ego Owner of the home (host).
 * @param address Address of the place to enter (GADS name, i.e. 'room.friend.gads'),
 *        if the name has the form 'HEX.place', GADS is not
 *        used and HEX is assumed to be the hash of the public
 *        key already; 'HEX.zkey' however would refer to
 *        the 'PLACE' record in the GADS zone with the public key
 *        'HEX'.
 * @param msg_size Number of bytes in @a msg.
 * @param msg Message to give to the enter callback.
 * @param slicer Slicer to use for processing incoming requests from guests.
 * @return NULL on errors, otherwise handle to the place.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_place_enter (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           struct GNUNET_SOCIAL_Ego *ego,
                           char *address,
                           size_t msg_size,
                           const void *msg,
                           struct GNUNET_SOCIAL_Slicer *slicer);

/** 
 * Request entry to a place (home hosted by someone else).
 *
 * @param cfg Configuration to contact the social service.
 * @param ego Owner of the home (host).
 * @param crypto_address Public key of the place to enter.
 * @param peer Peer to send request to.
 * @param slicer Slicer to use for processing incoming requests from guests.
 * @param msg_size Number of bytes in @a msg.
 * @param msg Message to give to the enter callback.
 * @return NULL on errors, otherwise handle to the place.
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_place_enter2 (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           struct GNUNET_SOCIAL_Ego *ego,
                           struct GNUNET_HashCode *crypto_address,
                           struct GNUNET_PeerIdentity *peer,
                           struct GNUNET_SOCIAL_Slicer *slicer,
                           size_t msg_size,
                           const void *msg);


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
			   void *state_cb_cls);


/** 
 * Cancel watching a place for changed objects.
 *
 * @param wh Watch handle to cancel.
 */
void
GNUNET_SOCIAL_place_watch_cancel (struct GNUNET_SOCIAL_WatchHandle *wh);


struct GNUNET_SOCIAL_LookHandle;

/** 
 * Look at all objects in the place.
 *
 * @param place The place to look its objects at.
 * @param state_cb Function to call for each object found.
 * @param state_cb_cls Closure for callback function.
 * 
 * @return Handle that can be used to stop looking at objects.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look (struct GNUNET_SOCIAL_Place *place,
			  GNUNET_PSYC_StateCallback state_cb,
			  void *state_cb_cls);


/** 
 * Look at matching objects in the place.
 *
 * @param place The place to look its objects at.
 * @param object_filter Only look at objects with names beginning with this filter value. 
 * @param state_cb Function to call for each object found.
 * @param state_cb_cls Closure for callback function.
 * 
 * @return Handle that can be used to stop looking at objects.
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look_for (struct GNUNET_SOCIAL_Place *place,
			      const char *object_filter,
			      GNUNET_PSYC_StateCallback state_cb,
			      void *state_cb_cls);


/** 
 * Stop looking at objects.
 *
 * @param lh Look handle to stop.
 */
void
GNUNET_SOCIAL_place_look_cancel (struct GNUNET_SOCIAL_LookHandle *lh);



/** 
 * Look at a particular object in the place.
 *
 * @param place The place to look the object at.
 * @param object_name Full name of the object.
 * @param value_size Set to the size of the returned value.
 * @return NULL if there is no such object at this place.
 */
const void *
GNUNET_SOCIAL_place_look_at (struct GNUNET_SOCIAL_Place *place,
			     const char *object_name,
			     size_t *value_size);


/** 
 * Frame the (next) talk by setting some variables for it.
 *
 * FIXME: use a TalkFrame struct instead that can be passed to
 * place_talk, nym_talk and home_reject_entry.
 *
 * @param place Place to talk in.
 * @param variable_name Name of variable to set.
 * @param value_size Number of bytes in @a value.
 * @param value Value of variable.
 */
void
GNUNET_SOCIAL_place_frame_talk (struct GNUNET_SOCIAL_Place *place,
				const char *variable_name,
				size_t value_size,
				const void *value);


/** 
 * A talk request.
 */
struct GNUNET_SOCIAL_TalkRequest;

/** 
 * Talk to the host of the place.
 *
 * @param place Place where we want to talk to the host.
 * @param method_name Method to invoke on the host.
 * @param cb Function to use to get the payload for the method.
 * @param cb_cls Closure for @a cb.
 * @return NULL if we are already trying to talk to the host,
 *         otherwise handle to cancel the request.
 */
struct GNUNET_SOCIAL_TalkRequest *
GNUNET_SOCIAL_place_talk (struct GNUNET_SOCIAL_Place *place,
			  const char *method_name,
			  GNUNET_PSYC_OriginReadyNotify cb,
			  void *cb_cls);


/** 
 * Cancel talking to the host of the place.
 *
 * @param tr Talk request to cancel.
 */
void
GNUNET_SOCIAL_place_talk_cancel (struct GNUNET_SOCIAL_TalkRequest *tr);


/** 
 * A history lesson.
 */
struct GNUNET_SOCIAL_HistoryLesson;

/** 
 * Learn about the history of a place.
 *
 * Sends messages through the given slicer function where
 * start_message_id <= message_id <= end_message_id.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 * 
 * @param place Place we want to learn more about.
 * @param start_message_id First historic message we are interested in.
 * @param end_message_id Last historic message we are interested in (inclusive).
 * @param slicer Slicer to use to process history.
 * @return Handle to abort history lesson, never NULL (multiple lessons
 *        at the same time are allowed).
 */
struct GNUNET_SOCIAL_HistoryLesson *
GNUNET_SOCIAL_place_get_history (struct GNUNET_SOCIAL_Place *place,
				 uint64_t start_message_id,
				 uint64_t end_message_id,
				 struct GNUNET_SOCIAL_Slicer *slicer);


/** 
 * Stop processing messages from the history lesson.
 *
 * Must also be called explicitly after all of the requested messages have been
 * received.
 *
 * @param hist History lesson to cancel.
 */
void
GNUNET_SOCIAL_place_get_history_cancel (struct GNUNET_SOCIAL_HistoryLesson *hist);

	  
/** 
 * Leave a place permanently.
 *
 * Notifies the owner of the place about leaving, and destroys the place handle.
 * 
 * @param place Place to leave permanently.
 */
void
GNUNET_SOCIAL_place_leave (struct GNUNET_SOCIAL_Place *place);


/** 
 * Leave a place temporarily.
 *
 * Stop following the conversation for the @a place and destroy the @a place
 * handle.  Only affects the application calling this function, other clients of
 * the service continue receiving the messages.
 *
 * @param place Place to leave temporarily.
 */
void
GNUNET_SOCIAL_place_away (struct GNUNET_SOCIAL_Place *place);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SOCIAL_SERVICE_H */
#endif
/* end of gnunet_social_service.h */
