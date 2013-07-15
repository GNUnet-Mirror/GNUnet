/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_psyc_service.h
 * @brief PSYC service; high-level access to the PSYC protocol
 *        note that clients of this API are NOT expected to
 *        understand the PSYC message format, only the semantics!
 *        Parsing (and serializing) the PSYC stream format is done
 *        within the implementation of the libgnunetpsyc library,
 *        and this API deliberately exposes as little as possible
 *        of the actual data stream format to the application!
 * @author Christian Grothoff
 * @author Gabor X Toth
 *
 * NOTE:
 * - this API does not know about psyc's "root" and "places";
 *   there is no 'root' in GNUnet-Psyc as we're decentralized;
 *   'places' and 'persons' are combined within the same 
 *   abstraction, that of a "channel".  Channels are identified
 *   and accessed in this API using a public/private key.  
 *   Higher-level applications should use NAMES within GADS
 *   to obtain public keys, and the distinction between 
 *   'places' and 'persons' can then be made with the help
 *   of the naming system (and/or conventions).
 *   Channels are (as in PSYC) organized into a hierarchy; each
 *   channel owner (the one with the private key) is then
 *   the operator of the multicast group (its Origin in 
 *   the terminology of the multicast API).
 * - The API supports passing large amounts of data using
 *   'streaming' for the argument passed to a method.  State
 *   and variables must fit into memory and cannot be streamed
 *   (thus, no passing of 4 GB of data in a variable; 
 *   once we implement this, we might want to create a
 *   @c \#define for the maximum size of a variable).
 * - PSYC defines standard variables, methods, etc.  This
 *   library deliberately abstracts over all of these; a
 *   higher-level API should combine the naming system (GADS)
 *   and standard methods (message, join, part, warn,
 *   fail, error) and variables (action, color, time,
 *   tag, etc.).  However, this API does take over the
 *   routing variables, specifically 'context' (channel),
 *   and 'source'.  We only kind-of support 'target', as
 *   the target is either everyone in the group or the
 *   origin, and never just a single member of the group;
 *   for such individual messages, an application needs to
 *   construct an 'inbox' channel where the owner (only)
 *   receives messages (but never forwards; private responses
 *   would be transmitted by joining the senders 'inbox'
 *   channel -- or a inbox#bob subchannel).  The
 *   goal for all of this is to keep the abstractions in this 
 *   API minimal: interaction with multicast, try \& slice,
 *   state/variable/channel management.  Higher-level
 *   operations belong elsewhere (so maybe this API should
 *   be called 'PSYC-low', whereas a higher-level API
 *   implementing defaults for standard methods and
 *   variables might be called 'PSYC-std' or 'PSYC-high'.
 *
 * Idee (lynx): 
 * - rename "channel" to "master"
 * - rename "member" to "slave"
 * - rename "group" to "channel"
 */

#ifndef GNUNET_PSYC_SERVICE_H
#define GNUNET_PSYC_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_psyc_lib.h"
#include "gnunet_multicast_service.h"


/** 
 * Version number of GNUnet-PSYC API.
 */
#define GNUNET_PSYC_VERSION 0x00000000


enum GNUNET_PSYC_MessageFlags
{
  /**
   * First fragment of a message.
   */
  GNUNET_PSYC_MESSAGE_FIRST_FRAGMENT = GNUNET_MULTICAST_MESSAGE_FIRST_FRAGMENT,

  /**
   * Last fragment of a message.
   */
  GNUNET_PSYC_MESSAGE_LAST_FRAGMENT = GNUNET_MULTICAST_MESSAGE_LAST_FRAGMENT,

  /** 
   * OR'ed flags if message is not fragmented.
   */
  GNUNET_PSYC_MESSAGE_NOT_FRAGMENTED = GNUNET_MULTICAST_MESSAGE_NOT_FRAGMENTED
};


/** 
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_PSYC_JoinCallback to the
 * corresponding calls to GNUNET_PSYC_join_decision().
 */
struct GNUNET_PSYC_JoinHandle;

/** 
 * Handle that identifies a part request.
 *
 * Used to match calls to #GNUNET_PSYC_PartCallback to the
 * corresponding calls to GNUNET_PSYC_part_ack().
 */
struct GNUNET_PSYC_PartHandle;


/** 
 * Method called from PSYC upon receiving a message indicating a call
 * to a @e method.  
 *
 * @param cls Closure.
 * @param sender Who transmitted the message (origin, except for messages
 *        from one of the members to the origin).
 * @param message_id Unique message counter for this message;
 *                   (unique only in combination with the given sender for
 *                    this channel).
 * @param method_name Original method name from PSYC (may be more
 *        specific than the registered method name due to try-and-slice matching).
 *        FIXME: no try-and-slice for methods defined here.
 * @param header_length Number of modifiers in header.
 * @param header Modifiers present in the message.
 * @param data_offset Byte offset of @a data in the overall data of the method.
 * @param data_size Number of bytes in @a data.
 * @param data Data stream given to the method (might not be zero-terminated 
 *             if data is binary).
 * @param frag Fragmentation status for the data.
 */
typedef int (*GNUNET_PSYC_Method)(void *cls,
				  const struct GNUNET_PeerIdentity *sender,
				  uint64_t message_id,
				  const char *method_name,
                                  size_t header_length,
                                  GNUNET_PSYC_Modifier *header,                                 
				  uint64_t data_offset,
				  size_t data_size,
				  const void *data,
				  enum GNUNET_PSYC_MessageFlags flags);


/** 
 * Method called from PSYC upon receiving a join request.
 *
 * @param cls Closure.
 * @param peer Peer requesting to join.
 * @param method_name Method name in the join request.
 * @param header_length Number of modifiers in header.
 * @param header Modifiers present in the message.
 * @param data_size Number of bytes in @a data.
 * @param data Data stream given to the method (might not be zero-terminated 
 *             if data is binary).
 */
typedef int (*GNUNET_PSYC_JoinCallback)(void *cls,
                                        const struct GNUNET_PeerIdentity *peer,
                                        const char *method_name,
                                        size_t header_length,
                                        GNUNET_PSYC_Modifier *header,
                                        size_t data_size,
                                        const void *data,
                                        struct GNUNET_PSYC_JoinHandle *jh);


/** 
 * Method called from PSYC upon receiving a part request.
 *
 * @param cls Closure.
 * @param peer Peer requesting to leave.
 * @param method_name Method name in the part request.
 * @param header_length Number of modifiers in header.
 * @param header Modifiers present in the message.
 * @param data_size Number of bytes in @a data.
 * @param data Data stream given to the method (might not be zero-terminated 
 *             if data is binary).
 */
typedef int (*GNUNET_PSYC_PartCallback)(void *cls,
                                        const struct GNUNET_PeerIdentity *peer,
                                        const char *method_name,
                                        size_t header_length,
                                        GNUNET_PSYC_Modifier *header,
                                        size_t data_size,
                                        const void *data,
                                        struct GNUNET_PSYC_PartHandle *ph);


/** 
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_PSYC_JoinCallback.
 *
 * @param jh Join request handle.
 * @param is_admitted #GNUNET_YES if joining is approved,
 *        #GNUNET_NO if it is disapproved
 * @param method_name Method name for the message transmitted with the response.
 * @param data_size Size of @a data.
 * @param data Data of the message.
 */
void
GNUNET_PSYC_join_decision (struct GNUNET_PSYC_JoinHandle *jh,
                           int is_admitted,
                           const char *method_name,
                           size_t data_size,
                           const void *data);


/** 
 * Send a part acknowledgment.
 *
 * @param ph Part handle.
 */
void
GNUNET_PSYC_part_ack (struct GNUNET_PSYC_PartHandle *ph);


/** 
 * Handle for the channel of a PSYC group.
 */
struct GNUNET_PSYC_Channel;


/** 
 * Create a PSYC channel.
 *
 * Will create a multicast group identified by the given ECC key.  Messages
 * received from group members will be given to the respective handler methods.
 * If a new member wants to join a group, the "join" method handler will be
 * invoked; the join handler must then generate a "join" message to approve the
 * joining of the new member.  The channel can also change group membership
 * without explicit requests.  Note that PSYC doesn't itself "understand" join
 * or part messages, the respective methods must call other PSYC functions to
 * inform PSYC about the meaning of the respective events.
 *
 * @param cfg Configuration to use (to connect to PSYC service).
 * @param priv_key ECC key that will be used to sign messages for this
 *                 PSYC session; public key is used to identify the
 *                 PSYC group; FIXME: we'll likely want to use
 *                 NOT the p521 curve here, but a cheaper one in the future
 *                 Note that end-users will usually not use the private key
 *                 directly, but rather look it up in GADS for groups 
 *                 managed by other users, or select a file with the private
 *                 key(s) when setting up their own channels
 * @param join_policy What is the membership policy of the group?
 *                 Used to automate group management decisions.
 * @param method_cb Function to invoke on messages received from members.
 * @param join_cb Function to invoke when a peer wants to join.
 * @param part_cb Function to invoke when a peer wants to part.
 * @param cls Closure for the callbacks.
 * @return Handle for the channel, NULL on error.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_channel_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            const struct GNUNET_CRYPTO_EccPrivateKey *priv_key,
                            enum GNUNET_MULTICAST_JoinPolicy join_policy,
                            GNUNET_PSYC_Method method_cb,
                            GNUNET_PSYC_JoinCallback join_cb,
                            GNUNET_PSYC_PartCallback part_cb,
                            void *cls);


/** 
 * Modify channel state (or set a transient variable).
 *
 * The state of a channel must fit into the memory of each member (and the
 * channel); large values that require streaming must only be passed as the
 * stream arguments to methods.  State modifications might not be transmitted to
 * group members until the next call to GNUNET_PSYC_channel_transmit().
 * Variable updates must be given just before the call to the respective method
 * that needs the variables.
 *
 * @param channel Handle to the PSYC group / channel.
 * @param oper Kind of update operation (add, remove, replace, delete).
 * @param name Name of the state or transient variable to modify.
 * @param value_size Number of bytes in @a value.
 * @param value Value of state variable.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on internal error
 *        (i.e. state too large).
 */
int
GNUNET_PSYC_channel_state_modify (struct GNUNET_PSYC_Channel *channel,
				  enum GNUNET_PSYC_Operator oper,
				  const char *name,
				  size_t value_size,
				  const void *value);


/** 
 * Function called to provide data for a transmission via PSYC.
 *
 * Note that returning #GNUNET_OK or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param message_id Set to the unique message ID that was generated for
 *        this message.
 * @param data_size[in,out] Initially set to the number of bytes available in @a data,
 *        should be set to the number of bytes written to data (IN/OUT).
 * @param[out] data Where to write the body of the message to give to the method;
 *        function must copy at most @a *data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission)
 *         #GNUNET_NO on success, if more data is to be transmitted later 
 *         (should be used if @a *data_size was not big enough to take all the data)
 *         #GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int (*GNUNET_PSYC_ChannelReadyNotify)(void *cls,
                                              uint64_t message_id,
                                              size_t *data_size,
                                              void *data);


/** 
 * Handle for a pending PSYC transmission operation. 
 */
struct GNUNET_PSYC_ChannelTransmitHandle;


/** 
 * Send a message to call a method to all members in the PSYC channel.
 *
 * @param channel Handle to the PSYC multicast group.
 * @param increment_group_generation #GNUNET_YES if we need to increment
 *        the group generation counter after transmitting this message.
 * @param method_name Which method should be invoked.
 * @param notify Function to call to obtain the arguments.
 * @param notify_cls Closure for @a notify.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_ChannelTransmitHandle *
GNUNET_PSYC_channel_transmit (struct GNUNET_PSYC_Channel *channel,
                              int increment_group_generation,
                              const char *method_name,
                              GNUNET_PSYC_ChannelReadyNotify notify,
                              void *notify_cls);


/** 
 * Abort transmission request to channel.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_channel_transmit_cancel (struct GNUNET_PSYC_ChannelTransmitHandle *th);


/** 
 * Destroy a PSYC channel.
 *
 * @param channel PSYC channel to terminate.
 */
tvoid
GNUNET_PSYC_channel_destroy (struct GNUNET_PSYC_Channel *channel);


/** 
 * Handle to access PSYC group operations for all members.
 */
struct GNUNET_PSYC_Group;


/** 
 * Convert @a channel to a @e group handle to access the @e group APIs.
 * 
 * @param channel Channel handle.
 * @return Group handle, valid for as long as @a channel is valid.
 */ 
struct GNUNET_PSYC_Group *
GNUNET_PSYC_channel_get_group (struct GNUNET_PSYC_Channel *channel);


/** 
 * Convert @a member to a @e group handle to access the @e group APIs.
 * 
 * @param member Membership handle.
 * @return Group handle, valid for as long as @a member is valid.
 */ 
struct GNUNET_PSYC_Group *
GNUNET_PSYC_member_get_group (struct GNUNET_PSYC_Member *member);


/** 
 * Add a member to the group.
 *
 * Note that this will NOT generate any PSYC traffic, it will merely update the
 * local data base to modify how we react to <em>membership test</em> queries.  The
 * channel still needs to explicitly transmit a @e join message to notify other
 * group members and they then also must still call this function in their
 * respective methods handling the @e join message.  This way, how @e join and
 * @e part operations are exactly implemented is still up to the application;
 * for example, there might be a @e part_all method to kick out everyone.
 *
 * Note that group members are explicitly trusted to execute such methods
 * correctly; not doing so correctly will result in either denying members
 * access or offering access to group data to non-members.
 *
 * @param group Group handle.
 * @param member Which peer to add.
 * @param message_id Message ID for the message that changed the membership.
 */
void
GNUNET_PSYC_group_member_add (struct GNUNET_PSYC_Group *group,
			      const struct GNUNET_PeerIdentity *member,
			      uint64_t message_id);


/** 
 * Remove a member from the group.
 *
 * Note that this will NOT generate any PSYC traffic, it will merely update the
 * local data base to modify how we react to <em>membership test</em> queries.  The
 * channel still needs to explicitly transmit a @e part message to notify other
 * group members and they then also must still call this function in their
 * respective methods handling the @e part message.  This way, how @e join and
 * @e part operations are exactly implemented is still up to the application;
 * for example, there might be a @e part_all message to kick out everyone.
 *
 * Note that group members are explicitly trusted to perform these
 * operations correctly; not doing so correctly will result in either
 * denying members access or offering access to group data to
 * non-members.
 *
 * @param group Group handle.
 * @param member Which peer to remove.
 * @param message_id Message ID for the message that changed the membership.
 */
void
GNUNET_PSYC_group_member_remove (struct GNUNET_PSYC_Group *group,
				 const struct GNUNET_PeerIdentity *member,
				 uint64_t message_id);


/** 
 * Function called to inform a member about stored state values for a channel.
 *
 * @param cls Closure.
 * @param name Name of the state variable.
 * @param value Value of the state variable.
 * @param value_size Number of bytes in @a value.
 */
typedef void (*GNUNET_PSYC_StateCallback)(void *cls,
					  const char *name,
					  size_t value_size,
					  const void *value);


/** 
 * Join a PSYC group.
 *
 * The entity joining is always the local peer.  The user must immediately use
 * the GNUNET_PSYC_member_to_origin() (and possibly
 * GNUNET_PSYC_member_variable_set()) functions to transmit a @e join_msg to
 * the channel; if the join request succeeds, the channel state (and @e recent
 * method calls) will be replayed to the joining member.  There is no explicit
 * notification on failure (as the channel may simply take days to approve, a-v/snd
 * disapproval is simply being ignored).
 *
 * @param cfg Configuration to use.
 * @param pub_key ECC key that identifies the channel we wish to join
 * @param origin Peer identity of the origin.
 * @param method Function to invoke on messages received from the channel,
 *                typically at least contains functions for @e join and @e part.
 * @param method_cls Closure for @a method.
 * @return Handle for the member, NULL on error.
 */
struct GNUNET_PSYC_Member *
GNUNET_PSYC_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			 const struct GNUNET_CRYPTO_EccPublicKey *pub_key,
			 const struct GNUNET_PeerIdentity *origin,
			 GNUNET_PSYC_Method method,
			 void *method_cls);


/** 
 * Part a PSYC group.
 *
 * Will terminate the connection to the PSYC service.  Polite clients should
 * first explicitly send a @e part request (via GNUNET_PSYC_member_to_origin()).
 *
 * @param member membership handle
 */
void
GNUNET_PSYC_member_part (struct GNUNET_PSYC_Member *member);


/** 
 * Function called to provide data for a transmission to the channel
 * owner (aka the @e host of the channel).
 *
 * Note that returning #GNUNET_OK or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param data_size[in,out] Initially set to the number of bytes available in @a data,
 *        should be set to the number of bytes written to data (IN/OUT).
 * @param[out] data Where to write the body of the message to give to the method;
 *        function must copy at most @a *data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission).
 *         #GNUNET_NO on success, if more data is to be transmitted later.
 *         #GNUNET_YES if this completes the transmission (all data supplied).
 */
typedef int (*GNUNET_PSYC_MemberReadyNotify)(void *cls,
					     size_t *data_size,
					     char *data);


/** 
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_MemberTransmitHandle;


/** 
 * Request a message to be sent to the channel origin.
 *
 * @param member Membership handle.
 * @param method_name Which (PSYC) method should be invoked (on host).
 * @param notify Function to call when we are allowed to transmit (to get data).
 * @param notify_cls Closure for @a notify.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_MemberTransmitHandle *
GNUNET_PSYC_member_to_origin (struct GNUNET_PSYC_Member *member,
                              const char *method_name,
                              GNUNET_PSYC_MemberReadyNotify notify,
                              void *notify_cls);


/** 
 * Set a (temporary, ":") variable for the next message being transmitted
 * via GNUNET_PSYC_member_to_origin().
 *
 * If GNUNET_PSYC_member_to_origin() is called and then cancelled, all
 * variables that were set using this function will be unset (lost/forgotten).
 * To clear a variable state after setting it, you can also call this function
 * again with NULL/0 for the @a value.
 *
 * @param member Membership handle.
 * @param name Name of the variable to set.
 * @param value_size Number of bytes in @a value.
 * @param value Value to set for the given variable.
 */
uint64_t
GNUNET_PSYC_member_variable_set (struct GNUNET_PSYC_Member *member,
                                 const char *name,
                                 size_t value_size,
                                 const void *value);


/** 
 * Abort transmission request to origin.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_member_to_origin_cancel (struct GNUNET_PSYC_MemberTransmitHandle *th);


/** 
 * Handle to a story telling operation.
 */
struct GNUNET_PSYC_Story;


/** 
 * Request to be told the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is permitted.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param member Which channel should be replayed?
 * @param start_message_id Earliest interesting point in history.
 * @param end_message_id Last (exclusive) interesting point in history.
 * @param method Function to invoke on messages received from the story.
 * @param method_cls Closure for @a method.
 * @param finish_cb Function to call when the requested story has been fully 
 *        told (counting message IDs might not suffice, as some messages
 *        might be secret and thus the listener would not know the story is 
 *        finished without being told explicitly); once this function
 *        has been called, the client must not call
 *        GNUNET_PSYC_member_story_tell_cancel() anymore.
 * @param finish_cb_cls Closure to finish_cb.
 * @return Handle to cancel story telling operation.
 */
struct GNUNET_PSYC_Story *
GNUNET_PSYC_member_story_tell (struct GNUNET_PSYC_Member *member,
			       uint64_t start_message_id,
			       uint64_t end_message_id,
			       GNUNET_PSYC_Method method,
			       void *method_cls,
			       void (*finish_cb)(void *),
			       void *finish_cb_cls);


/** 
 * Abort story telling.
 *
 * This function must not be called from within method handlers (as given to
 * GNUNET_PSYC_member_join()) of the member.
 *
 * @param story Story telling operation to stop.
 */
void
GNUNET_PSYC_member_story_tell_cancel (struct GNUNET_PSYC_Story *story);


/** 
 * Call the given callback on all matching values (including variables) in the
 * channel state.
 *
 * The callback is invoked synchronously on all matching states (as the state is
 * fully replicated in the library in this process; channel states should be
 * small, large data is to be passed as streaming data to methods).
 *
 * A name matches if it includes the @a state_name prefix, thus requesting the
 * empty state ("") will match all values; requesting "_a_b" will also return
 * values stored under "_a_b_c".
 *
 * @param member Membership handle.
 * @param state_name Name of the state to query (full name 
 *        might be longer, this is only the prefix that must match).
 * @param cb Function to call on the matching state values.
 * @param cb_cls Closure for @a cb.
 * @return Message ID for which the state was returned (last seen
 *         message ID).
 */
uint64_t
GNUNET_PSYC_member_state_get_all (struct GNUNET_PSYC_Member *member,
				  const char *state_name,
				  GNUNET_PSYC_StateCallback cb,
				  void *cb_cls);


/** 
 * Obtain the current value of the best-matching value in the state
 * (including variables).
 *
 * Note that variables are only valid during a #GNUNET_PSYC_Method invocation, as
 * variables are only valid for the duration of a method invocation.
 *
 * If the requested variable name does not have an exact state in
 * the state, the nearest less-specific name is matched; for example,
 * requesting "_a_b" will match "_a" if "_a_b" does not exist.
 *
 * @param member Membership handle.
 * @param variable_name Name of the variable to query.
 * @param[out] return_value_size Set to number of bytes in variable, 
 *        needed as variables might contain binary data and
 *        might also not be 0-terminated; set to 0 on errors.
 * @return NULL on error (no matching state or variable), pointer
          to the respective value otherwise.
 */
const void *
GNUNET_PSYC_member_state_get (struct GNUNET_PSYC_Member *member,
			      const char *variable_name,
			      size_t *return_value_size);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYC_SERVICE_H */
#endif
/* end of gnunet_psyc_service.h */
