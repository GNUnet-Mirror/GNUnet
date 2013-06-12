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
 * @brief Social service; implements social functionality using the PSYC service
 * @author tg
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
#include "gnunet_psyc_service.h"
#include "gnunet_multicast_service.h"


/**
 * Version number of GNUnet Social API.
 */
#define GNUNET_SOCIAL_VERSION 0x00000000


/**
 * Handle for a place where social interactions happen.
 */
struct GNUNET_SOCIAL_Place;

/**
 * Handle for a place that one of our egos hosts.
 */
struct GNUNET_SOCIAL_Home;

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
 * Handle to an implementation of try-and-slice.
 */
struct GNUNET_SOCIAL_Slicer;


/**
 * Method called from SOCIAL upon receiving a message indicating a call
 * to a 'method'.  
 *
 * @param cls closure
 * @param full_method_name original method name from PSYC (may be more
 *        specific than the registered method name due to try-and-slice matching)
 * @param message_id unique message counter for this message;
 *                   (unique only in combination with the given sender for
 *                    this channel)
 * @param data_off byte offset of 'data' in the overall data of the method
 * @param data_size number of bytes in 'data'; 
 * @param data data stream given to the method (might not be zero-terminated 
 *             if data is binary)
 * @param frag fragmentation status for the data
 */
typedef int (*GNUNET_SOCIAL_Method)(void *cls,
				    const char *full_method_name,
				    uint64_t message_id,
				    uint64_t data_off,
				    size_t data_size,
				    const void *data,
				    enum GNUNET_PSYC_FragmentStatus frag);


/**
 * Create a try-and-slice instance.
 *
 * @return try-and-slice construct
 */
struct GNUNET_SOCIAL_Slicer *
GNUNET_SOCIAL_slicer_create (void);


/**
 * Add a method to the try-and-slice instance.
 *
 * @param slicer try-and-slice instance to extend
 * @param method_name name of the given method, use empty string for default
 * @param method method to invoke
 * @param method_cls closure for method
 */
void
GNUNET_SOCIAL_slicer_add (struct GNUNET_SOCIAL_Slicer *slicer,
			  const char *method_name,
			  GNUNET_SOCIAL_Method method,
			  void *method_cls);


/**
 * Destroy a given try-and-slice instance.
 *
 * @param slicer slicer to destroy
 */
void
GNUNET_SOCIAL_slicer_destroy (struct GNUNET_SOCIAL_Slicer *slicer);


/**
 * Create an ego using the private key from the given
 * file.  If the file does not exist, a fresh key is
 * created.
 *
 * @param keyfile name of the file with the private key for the ego,
 *                NULL for ephemeral egos
 * @return handle to the ego, NULL on error
 */
struct GNUNET_SOCIAL_Ego *
GNUNET_SOCIAL_ego_create (const char *keyfile);


/**
 * Destroy a handle to an ego.
 *
 * @param ego ego to destroy
 */
void
GNUNET_SOCIAL_ego_destroy (struct GNUNET_SOCIAL_Ego *ego);


/**
 * Function called asking for nym to be admitted to the room.  Should
 * call either 'GNUNET_SOCIAL_home_admit' or
 * 'GNUNET_SOCIAL_home_reject_entry' (possibly asynchronously).  If
 * this owner cannot decide, it is fine to call neither function, in
 * which case hopefully some other owner of the home exists that will
 * make the decision. The 'nym' reference remains valid until the
 * 'GNUNET_SOCIAL_FarewellCallback' is invoked for it.
 *
 * @param cls closure
 * @param nym handle for the user who wants to join
 * @param join_msg_size number of bytes in 'join_msg'
 * @param join_msg payload given on join
 */
typedef void (*GNUNET_SOCIAL_AnswerDoorCallback)(void *cls,
						 struct GNUNET_SOCIAL_Nym *nym,
						 size_t join_msg_size,
						 const void *join_msg);


/**
 * Function called when a 'nym' leaves the room.  This is
 * also called if the 'nym' was never given permission to
 * enter (i.e. the 'nym' stopped asking to get in).
 *
 * @param cls closure
 * @param nym handle for the user who left
 */
typedef void (*GNUNET_SOCIAL_FarewellCallback)(void *cls,
					       struct GNUNET_SOCIAL_Nym *nym);


/**
 * Create a new home to host guests (nyms).
 *
 * @param cfg configuration to contact the social service
 * @param home_keyfile file with the private key for the home, 
 *              created if the file does not exist; 
 *              pass NULL for ephemeral homes
 * @param join_policy what is our policy for allowing people in?
 * @param ego owner of the home (host)
 * @param slicer slicer to handle guests talking
 * @param listener_cb function to handle new nyms that want to join
 * @param farewell_cb function to handle departing nyms
 * @param cls closure for 'listener_cb' and 'farewell_cb'
 * @return handle for a new home
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
 * Admit 'nym' to the 'home'.  'nym' will remain valid until either
 * the home is destroyed or 'nym' leaves.
 *
 * @param home home to allow 'nym' to join
 * @param nym handle for the entity that wants to join
 */
void
GNUNET_SOCIAL_home_admit (struct GNUNET_SOCIAL_Home *home,
			  struct GNUNET_SOCIAL_Nym *nym);


/**
 * Throw 'nym' out of the 'home'.  'nym' will remain valid
 * until the 'GNUNET_SOCIAL_FarewellCallback' is invoked, which
 * should be very soon after this call.
 *
 * @param home home to allow 'nym' to join
 * @param nym handle for the entity that wants to join
 */
void
GNUNET_SOCIAL_home_evict (struct GNUNET_SOCIAL_Home *home,
			  struct GNUNET_SOCIAL_Nym *nym);


/**
 * Refuse 'nym' entry into the 'home'.
 *
 * @param home home to disallow 'nym' to join
 * @param nym handle for the entity that wanted to join
 * @param method method name to invoke on caller
 * @param message_size number of bytes in 'message' for method
 * @param message rejection message to send back
 */
void
GNUNET_SOCIAL_home_reject_entry (struct GNUNET_SOCIAL_Home *home,
				 struct GNUNET_SOCIAL_Nym *nym,
				 const char *method,
				 size_t message_size,
				 const void *message);


/**
 * Get the identity of a user (suitable, for example, to be used
 * with 'GNUNET_NAMESTORE_zone_to_name').
 *
 * @param nym pseydonym to map to a cryptographic identifier
 * @param identity set to the identity of the nym (short hash of the public key)
 */
void
GNUNET_SOCIAL_nym_get_identity (struct GNUNET_SOCIAL_Nym *nym,
				struct GNUNET_CRYPTO_ShortHashCode *identity);


/**
 * Obtain the (cryptographic, binary) address for the home.
 * 
 * @param home home to get the (public) address from
 * @param crypto_address address suitable for storing in GADS,
 *        i.e. in 'HEX.place' or within the respective GADS record type ("PLACE")
 */
void
GNUNET_SOCIAL_home_get_address (struct GNUNET_SOCIAL_Home *home,
				struct GNUNET_HashCode *crypto_address);


/**
 * (re)decorate the home by changing objects in it.  If
 * the operation is 'GNUNET_PSYC_SOT_SET_VARIABLE' then
 * the decoration only applies to the next announcement
 * by the home owner.
 *
 * @param home the home to decorate
 * @param operation operation to perform on the object
 * @param object_name name of the object to modify
 * @param object_value_size size of the given 'object_value'
 * @param object_value value to use for the modification
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
 * This function allows the home owner to send a message to all
 * nyms that are present in the home.
 *
 * @param home home to address the announcement to
 * @param full_method_name method to use for the announcement
 * @param notify function to call to get the payload of the announcement
 * @param notify_cls closure for 'notify'
 * @return NULL on error (announcement already in progress?)
 */
struct GNUNET_SOCIAL_Announcement *
GNUNET_SOCIAL_place_announce (struct GNUNET_SOCIAL_Home *home,
			      const char *full_method_name,
			      GNUNET_PSYC_OriginReadyNotify notify,
			      void *notify_cls);


/**
 * Cancel announcement.
 *
 * @param a the announcement to cancel
 */
void
GNUNET_SOCIAL_place_announce_cancel (struct GNUNET_SOCIAL_Announcement *a);


/**
 * Convert our home to a place so we can access it via the place API.
 *
 * @param home handle for the home
 * @return place handle for the same home, valid as long as 'home' is valid;
 *         do NOT try to 'GNUNET_SOCIAL_place_leave' this place, it's your home!
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_home_to_place (struct GNUNET_SOCIAL_Home *home);


/**
 * Leave a home, visitors can stay.
 *
 * @param home home to leave (handle becomes invalid).
 */
void
GNUNET_SOCIAL_home_leave (struct GNUNET_SOCIAL_Home *home);


/**
 * Destroy a home, all guests will be evicted.
 *
 * @param home home to destroy
 */
void
GNUNET_SOCIAL_home_destroy (struct GNUNET_SOCIAL_Home *home);


/**
 * Join a place (home hosted by someone else).
 *
 * @param cfg configuration to contact the social service
 * @param ego owner of the home (host)
 * @param address address of the place to join (GADS name, i.e. 'room.friend.gads'),
 *        if the name has the form 'HEX.place', GADS is not
 *        used and HEX is assumed to be the hash of the public
 *        key already; 'HEX.zkey' however would refer to
 *        the 'PLACE' record in the GADS zone with the public key
 *        'HEX'.
 * @param join_msg_size number of bytes in 'join_msg'
 * @param join_msg message to give to the join callback
 * @return NULL on errors, otherwise handle to the place
 */
struct GNUNET_SOCIAL_Place *
GNUNET_SOCIAL_place_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
			  struct GNUNET_SOCIAL_Ego *ego,
			  const char *address,
			  struct GNUNET_SOCIAL_Slicer *slicer,
			  size_t join_msg_size,
			  const void *join_msg);


/**
 *
 */
struct GNUNET_SOCIAL_WatchHandle;

/**
 * 
 *
 * @param
 * @param
 * @param
 * @param
 */
struct GNUNET_SOCIAL_WatchHandle *
GNUNET_SOCIAL_place_watch (struct GNUNET_SOCIAL_Place *place,
			   const char *object_filter,
			   GNUNET_PSYC_StateCallback state_cb,
			   void *state_cb_cls);


/**
 * 
 *
 * @param
 */
void
GNUNET_SOCIAL_place_watch_cancel (struct GNUNET_SOCIAL_WatchHandle *wh);


/**
 *
 */
struct GNUNET_SOCIAL_LookHandle;

/**
 * Look at all objects in the place.
 *
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look (struct GNUNET_SOCIAL_Place *place,
			  GNUNET_PSYC_StateCallback state_cb,
			  void *state_cb_cls);


/**
 * Look at matching objects in the place.
 *
 */
struct GNUNET_SOCIAL_LookHandle *
GNUNET_SOCIAL_place_look_for (struct GNUNET_SOCIAL_Place *place,
			      const char *object_filter,
			      GNUNET_PSYC_StateCallback state_cb,
			      void *state_cb_cls);


/**
 * 
 *
 * @param lh
 */
void
GNUNET_SOCIAL_place_look_cancel (struct GNUNET_SOCIAL_LookHandle *lh);



/**
 * Look at a particular object in the place.
 *
 * @param place
 * @param object_name
 * @param value_size set to the size of the returned value
 * @return NULL if there is no such object at this place
 */
const void *
GNUNET_SOCIAL_place_look_at (struct GNUNET_SOCIAL_Place *place,
			     const char *object_name,
			     size_t *value_size);


/**
 * Frame the (next) talk by setting some variables for it.
 *
 * @param place
 * @param variable_name
 * @param value_size number of bytes in 'value'
 * @param value
 */
void
GNUNET_SOCIAL_place_frame_talk (struct GNUNET_SOCIAL_Place *place,
				const char *variable_name,
				size_t value_size,
				const void *value);


/**
 *
 */
struct GNUNET_SOCIAL_TalkRequest;


/**
 * Talk to the host of the place.
 *
 * @param place place at which we want to talk to the host
 * @param method_name method to invoke on the host
 * @param cb function to use to get the payload for the method
 * @param cb_cls closure for 'cb'
 * @return NULL if we are already trying to talk to the host,
 *         otherwise handle to cancel the request
 */
struct GNUNET_SOCIAL_TalkRequest *
GNUNET_SOCIAL_place_talk (struct GNUNET_SOCIAL_Place *place,
			  const char *method_name,
			  GNUNET_PSYC_OriginReadyNotify cb,
			  void *cb_cls);


/**
 * 
 *
 * @param tr
 */
void
GNUNET_SOCIAL_place_talk_cancel (struct GNUNET_SOCIAL_TalkRequest *tr);
		

/**
 *
 */
struct GNUNET_SOCIAL_HistoryLesson;


/**
 *
 * 
 * @param place place we want to learn more about
 * @param start_message_id first historic message we are interested in
 * @param end_message_id last historic message we are interested in (inclusive)
 * @param slicer slicer to use to process history
 * @return handle to abort history lesson, never NULL (multiple lesssons
 *        at the same time are allowed)
 */
struct GNUNET_SOCIAL_HistoryLesson *
GNUNET_SOCIAL_place_get_history (struct GNUNET_SOCIAL_Place *place,
				 uint64_t start_message_id,
				 uint64_t end_message_id,
				 struct GNUNET_SOCIAL_Slicer *slicer);


/**
 * Stop processing messages from the history lesson.  Must also be
 * called explicitly after all of the requested messages have been
 * received.
 *
 * @param hist history lesson to cancel
 */
void
GNUNET_SOCIAL_place_get_history_cancel (struct GNUNET_SOCIAL_HistoryLesson *hist);

	  
/**
 * Leave a place (destroys the place handle).  Can either move our
 * user into an 'away' state (in which we continue to record ongoing
 * conversations and state changes if our peer is running), or 
 * leave the place entirely and stop following the conversation.
 *
 * @param place place to leave
 * @param keep_following GNUNET_YES to ask the social service to continue
 *        to follow the conversation, GNUNET_NO to fully leave the place
 */
void
GNUNET_SOCIAL_place_leave (struct GNUNET_SOCIAL_Place *place,
			   int keep_following);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SOCIAL_SERVICE_H */
#endif
/* end of gnunet_social_service.h */
