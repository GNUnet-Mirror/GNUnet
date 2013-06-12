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
 *   #define for the maximum size of a variable).
 * - PSYC defines standard variables, methods, etc.  This
 *   library deliberately abstracts over all of these; a
 *   higher-level API should combine the naming system (GADS)
 *   and standard methods (message, join, leave, warn,
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
#include "gnunet_multicast_service.h"


/**
 * Version number of GNUnet-PSYC API.
 */
#define GNUNET_PSYC_VERSION 0x00000000


/**
 * Information flags for data fragments set via PSYC.
 */
enum GNUNET_PSYC_FragmentStatus
{
  /**
   * This is the first part of data for the given method call.
   */
  GNUNET_PSYC_FS_FIRST = 1,
  
  /**
   * This is the last part of data for the given method call.
   */
  GNUNET_PSYC_FS_LAST = 2,

  /**
   * OR'ed flags if payload is not fragmented.
   */
  GNUNET_PSYC_FS_NOT_FRAGMENTED = (GNUNET_PSYC_FS_FIRST | GNUNET_PSYC_FS_LAST)
};


/**
 * Method called from PSYC upon receiving a message indicating a call
 * to a 'method'.  
 *
 * @param cls closure
 * @param full_method_name original method name from PSYC (may be more
 *        specific than the registered method name due to try-and-slice matching)
 * @param sender who transmitted the message (origin, except for messages
 *        from one of the members to the origin)
 * @param message_id unique message counter for this message;
 *                   (unique only in combination with the given sender for
 *                    this channel)
 * @param group_generation group generation counter for this message
 *                   (always zero for messages from members to channel owner); FIXME: needed?
 * @param data_off byte offset of 'data' in the overall data of the method
 * @param data_size number of bytes in 'data'; 
 * @param data data stream given to the method (might not be zero-terminated 
 *             if data is binary)
 * @param frag fragmentation status for the data
 */
typedef int (*GNUNET_PSYC_Method)(void *cls,
				  const char *full_method_name,
				  const struct GNUNET_PeerIdentity *sender,
				  uint64_t message_id,
				  uint64_t group_generation,
				  uint64_t data_off,
				  size_t data_size,
				  const void *data,
				  enum GNUNET_PSYC_FragmentStatus frag);


/**
 * Handle for the channel of a PSYC group.
 */
struct GNUNET_PSYC_Channel;


/**
 * Start a PSYC channel.  Will create a multicast group identified by
 * the given ECC key.  Messages recevied from group members will be
 * given to the respective handler methods.  If a new member wants to
 * join a group, the "join" method handler will be invoked; the join
 * handler must then generate a "join" message to approve the joining
 * of the new member.  The channel can also change group membership
 * without explicit requests.  Note that PSYC doesn't itself "understand"
 * join or leave messages, the respective methods must call other
 * PSYC functions to inform PSYC about the meaning of the respective
 * events.
 *
 * @param cfg configuration to use (to connect to PSYC service)
 * @param method functions to invoke on messages received from members,
 *                typcially at least contains functions for 'join' and 'leave'.
 * @param method_cls closure for 'method'
 * @param priv_key ECC key that will be used to sign messages for this
 *                 PSYC session; public key is used to identify the
 *                 PSYC group; FIXME: we'll likely want to use
 *                 NOT the p521 curve here, but a cheaper one in the future
 *                 Note that end-users will usually not use the private key
 *                 directly, but rather look it up in GADS for groups 
 *                 managed by other users, or select a file with the private
 *                 key(s) when setting up their own channels
 * @param join_policy what is the membership policy of the group?
 *                 Used to automate group management decisions.
 * @return handle for the channel, NULL on error 
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_channel_start (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			   GNUNET_PSYC_Method method,
			   void *method_cls,
			   const struct GNUNET_CRYPTO_EccPrivateKey *priv_key,
			   enum GNUNET_MULTICAST_JoinPolicy join_policy);


/**
 * Possible operations on PSYC state (persistent) and variables (per message).
 */
enum GNUNET_PSYC_Operator
{
  /**
   * Replace the full state with the new value ("=").
   */
  GNUNET_PSYC_SOT_SET_STATE = 0,
  
  /**
   * Delete the complete entry from the state (given data must be
   * empty).  Equivalent to 'SET' with emtpy data, but more
   * explicit ("=");
   */
  GNUNET_PSYC_SOT_DELETE = 0,
  
  /**
   * Set the value of a variable to a new value (":").
   */
  GNUNET_PSYC_SOT_SET_VARIABLE,
  
  /**
   * Add the given value to the set of values in the state ("+").
   */
  GNUNET_PSYC_SOT_ADD_STATE,
  
  /**
   * Remove the given value from the set of values in the state ("-").
   */
  GNUNET_PSYC_SOT_REMOVE_STATE
  
};


/**
 * Update channel state (or set a variable).  The state of a channel
 * must fit into the memory of each member (and the channel); large
 * values that require streaming must only be passed as the stream
 * arguments to methods.  State updates might not be transmitted to
 * group members until the next call to
 * 'GNUNET_PSYC_channel_notify_transmit_ready'.  Variable updates must
 * be given just before the call to the respective method that needs
 * the variables.
 *
 * @param channel handle to the PSYC group / channel
 * @param full_state_name name of the field in the channel state to change
 * @param type kind of update operation (add, remove, replace, delete)
 * @param data_size number of bytes in data
 * @param data new state value
 * @return GNUNET_OK on success, GNUNET_SYSERR on internal error
 *        (i.e. state too large)
 */
int
GNUNET_PSYC_channel_state_update (struct GNUNET_PSYC_Channel *channel,
				  const char *full_state_name,
				  enum GNUNET_PSYC_Operator type,
				  size_t data_size,
				  const void *data);


/**
 * Function called to provide data for a transmission via PSYC.  Note
 * that returning GNUNET_OK or GNUNET_SYSERR (but not GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls closure
 * @param message_id set to the unique message ID that was generated for
 *        this message
 * @param group_generation set to the group generation used for this
 *        message
 * @param data_size initially set to the number of bytes available in 'data',
 *        should be set to the number of bytes written to data (IN/OUT)
 * @param data where to write the body of the message to give to the method;
 *        function must copy at most '*data_size' bytes to 'data'.
 * @return GNUNET_SYSERR on error (fatal, aborts transmission)
 *         GNUNET_NO on success, if more data is to be transmitted later 
 *         (should be used if 'data_size' was not big enough to take all the data)
 *         GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int (*GNUNET_PSYC_ChannelReadyNotify)(void *cls,
					      uint64_t message_id,
					      uint64_t group_generation,
					      size_t *data_size,
					      void *data);


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_ChannelTransmitHandle;


/**
 * Send a message to call a method to all members in the PSYC channel.
 *
 * @param channel handle to the PSYC multicast group
 * @param increment_group_generation GNUNET_YES if we need to increment
 *        the group generation counter after transmitting this message
 * @param full_method_name which method should be invoked
 * @param notify function to call to obtain the arguments
 * @param notify_cls closure for 'notify'
 * @return transmission handle, NULL on error (i.e. more than one request queued)
 */
struct GNUNET_PSYC_ChannelTransmitHandle *
GNUNET_PSYC_channel_notify_transmit_ready (struct GNUNET_PSYC_Channel *channel,
					   int increment_group_generation,
					   const char *full_method_name,
					   GNUNET_PSYC_ChannelReadyNotify notify,
					   void *notify_cls);


/**
 * Abort transmission request to channel.
 *
 * @param th handle of the request that is being aborted
 */
void
GNUNET_PSYC_channel_notify_transmit_ready_cancel (struct GNUNET_PSYC_ChannelTransmitHandle *th);


/**
 * End a PSYC channel.
 *
 * @param channel PSYC channel to terminate
 */
void
GNUNET_PSYC_channel_end (struct GNUNET_PSYC_Channel *channel);


/**
 * Handle to access PSYC group operations for all members.
 */
struct GNUNET_PSYC_Group;


/**
 * Convert 'channel' to a 'group' handle to access the 'group' APIs.
 * 
 * @param channel channel handle
 * @return group handle, valid for as long as 'channel' is valid
 */ 
struct GNUNET_PSYC_Group *
GNUNET_PSYC_channel_get_group (struct GNUNET_PSYC_Channel *channel);


/**
 * Convert 'member' to a 'group' handle to access the 'group' APIs.
 * 
 * @param member membership handle
 * @return group handle, valid for as long as 'member' is valid
 */ 
struct GNUNET_PSYC_Group *
GNUNET_PSYC_member_get_group (struct GNUNET_PSYC_Member *member);


/**
 * Add a member to the group.    Note that this will NOT generate any
 * PSYC traffic, it will merely update the local data base to modify
 * how we react to 'membership test' queries.  The channel still needs to
 * explicitly transmit a 'join' message to notify other group members
 * and they then also must still call this function in their respective
 * methods handling the 'join' message.  This way, how 'join' and 'leave'
 * operations are exactly implemented is still up to the application;
 * for example, there might be a 'leave_all' method to kick out everyone.
 *
 * Note that group members are explicitly trusted to execute such 
 * methods correctly; not doing so correctly will result in either
 * denying members access or offering access to group data to
 * non-members.
 *
 * @param group group handle
 * @param member which peer to add
 * @param message_id message ID for the message that changed the membership
 * @param group_generation the generation ID where the change went into effect
 */
void
GNUNET_PSYC_group_member_add (struct GNUNET_PSYC_Group *group,
			      const struct GNUNET_PeerIdentity *member,
			      uint64_t message_id,
			      uint64_t group_generation);


/**
 * Remove a member from the group.  Note that this will NOT generate any
 * PSYC traffic, it will merely update the local data base to modify
 * how we react to 'membership test' queries.  The channel still needs to
 * explicitly transmit a 'leave' message to notify other group members
 * and they then also must still call this function in their respective
 * methods handling the 'leave' message.  This way, how 'join' and 'leave'
 * operations are exactly implemented is still up to the application;
 * for example, there might be a 'leave_all' message to kick out everyone.
 *
 * Note that group members are explicitly trusted to perform these
 * operations correctly; not doing so correctly will result in either
 * denying members access or offering access to group data to
 * non-members.
 *
 * @param group group handle
 * @param member which peer to remove
 * @param message_id message ID for the message that changed the membership
 * @param group_generation the generation ID where the change went into effect
 */
void
GNUNET_PSYC_group_member_remove (struct GNUNET_PSYC_Group *group,
				 const struct GNUNET_PeerIdentity *member,
				 uint64_t message_id,
				 uint64_t group_generation);


/**
 * Function called to inform a member about state changes for a
 * channel.  Note that (for sets) only the delta is communicated, not
 * the full state.
 *
 * @param cls closure
 * @param full_state_name full name of the state
 * @param type how to interpret the change
 * @param state_value information about the new state
 * @param state_value_size number of bytes in 'state_value'
 */
typedef void (*GNUNET_PSYC_StateCallback)(void *cls,
					  const char *full_state_name,
					  enum GNUNET_PSYC_Operator type,
					  const void *state_value,
					  size_t state_value_size);


/**
 * Descriptor for an event handler handling PSYC state updates.
 */
struct GNUNET_PSYC_StateHandler
{

  /**
   * Name of the state this handler calls about, used in try-and-slice matching.
   */
  const char *state_name;

  /**
   * Function to call whenever the respective state changes.
   */
  GNUNET_PSYC_StateCallback event_handler;

  /**
   * Closure for the 'event_handler' function.
   */
  void *event_handler_cls;

};


/**
 * Join a PSYC group.  The entity joining is always the local peer.
 * The user must immediately use the 'GNUNET_PSYC_member_send_to_host'
 * (and possibly 'GNUNET_PSYC_member_host_variable_set') functions to
 * transmit a 'join_msg' to the channel; if the join request succeeds,
 * the channel state (and 'recent' method calls) will be replayed to
 * the joining member.  There is no explicit notification on failure
 * (as the channel may simply take days to approve, and disapproval is
 * simply being ignored).
 *
 * @param cfg configuration to use
 * @param pub_key ECC key that identifies the channel we wish to join
 * @param method function to invoke on messages received from the channel,
 *                typcially at least contains functions for 'join' and 'leave'.
 * @param method_cls closure for 'method'
 * @param state_count number of state handlers
 * @param state_handlers array of state event handlers
 * @return handle for the member, NULL on error 
 */
struct GNUNET_PSYC_Member *
GNUNET_PSYC_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			 const struct GNUNET_CRYPTO_EccPublicKey *pub_key,
			 GNUNET_PSYC_Method method,
			 void *method_cls,
			 unsigned int state_count,
			 struct GNUNET_PSYC_StateHandler *state_handlers);


/**
 * Leave a multicast group.  Will terminate the connection to the PSYC
 * service.  Polite clients should first explicitly send a 'leave'
 * request (via 'GNUNET_PSYC_member_send_to_host').  
 *
 * @param member membership handle
 */
void
GNUNET_PSYC_member_leave (struct GNUNET_PSYC_Member *member);


/**
 * Function called to provide data for a transmission to the channel
 * owner (aka the 'host' of the channel).  Note that returning
 * GNUNET_OK or GNUNET_SYSERR (but not GNUNET_NO) invalidates the
 * respective transmission handle.
 *
 * @param cls closure
 * @param data_size initially set to the number of bytes available in 'data',
 *        should be set to the number of bytes written to data (IN/OUT)
 * @param data where to write the body of the message to give to the method;
 *        function must copy at most '*data_size' bytes to 'data'.
 * @return GNUNET_SYSERR on error (fatal, aborts transmission)
 *         GNUNET_NO on success, if more data is to be transmitted later
 *         GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int (*GNUNET_PSYC_OriginReadyNotify)(void *cls,
					     size_t *data_size,
					     char *data);


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_OriginTransmitHandle;


/**
 * Request a message to be sent to the channel origin.
 *
 * @param member membership handle
 * @param method_name which (PSYC) method should be invoked (on host)
 * @param notify function to call when we are allowed to transmit (to get data)
 * @param notify_cls closure for 'notify'
 * @return transmission handle, NULL on error (i.e. more than one request queued)
 */
struct GNUNET_PSYC_OriginTransmitHandle *
GNUNET_PSYC_member_send_to_origin (struct GNUNET_PSYC_Member *member,
				   const char *method_name,
				   GNUNET_PSYC_OriginReadyNotify notify,
				   void *notify_cls);


/**
 * Set a (temporary, ":") variable for the next message being transmitted
 * via 'GNUNET_PSYC_member_send_to_host'. If 'GNUNET_PSYC_member_send_to_host'
 * is called and then cancelled, all variables that were set using this
 * function will be unset (lost/forgotten).  To clear a variable state after
 * setting it, you can also call this function again with NULL/0 for the value.
 *
 * @param member membership handle
 * @param variable_name name of the variable to set
 * @param value value to set for the given variable
 * @param value_size number of bytes in 'value'
 */
uint64_t
GNUNET_PSYC_member_origin_variable_set (struct GNUNET_PSYC_Member *member,
					const char *variable_name,
					const void *value,
					size_t value_size);


/**
 * Abort transmission request to origin.
 *
 * @param th handle of the request that is being aborted
 */
void
GNUNET_PSYC_member_send_to_origin_cancel (struct GNUNET_PSYC_OriginTransmitHandle *th);


/**
 * Handle to a story telling operation.
 */
struct GNUNET_PSYC_Story;


/**
 * Request to be told the message history of the channel.  Historic
 * messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is
 * permitted.
 *
 * @param member which channel should be replayed?
 * @param start earliest interesting point in history
 * @param end last (exclusive) interesting point in history
 * @param method function to invoke on messages received from the story
 * @param method_cls closure for 'method'
 * @param finish_cb function to call when the requested story has been fully 
 *        told (counting message IDs might not suffice, as some messages
 *        might be secret and thus the listener would not know the story is 
 *        finished without being told explicitly); once this function
 *        has been called, the client must not call
 *        'GNUNET_PSYC_member_story_tell_cancel' anymore
 * @param finish_cb_cls closure to finish_cb
 * @return handle to cancel story telling operation
 */
struct GNUNET_PSYC_Story *
GNUNET_PSYC_member_story_tell (struct GNUNET_PSYC_Member *member,
			       uint64_t start,
			       uint64_t end,
			       GNUNET_PSYC_Method method,
			       void *method_cls,
			       void (*finish_cb)(void *),
			       void *finish_cb_cls);


/**
 * Abort story telling.  This function must not be called from within
 * method handlers (as given to 'GNUNET_PSYC_member_join') of the
 * member.
 *
 * @param story story telling operation to stop
 */
void
GNUNET_PSYC_member_story_tell_cancel (struct GNUNET_PSYC_Story *story);


/**
 * Call the given callback on all matching values (including
 * variables) in the channel state.  The callback is invoked
 * synchronously on all matching states (as the state is fully
 * replicated in the library in this process; channel states should be
 * small, large data is to be passed as streaming data to methods).
 *
 * A name matches if it includes the 'state_name' prefix, thus
 * requesting the empty state ("") will match all values; requesting
 * "a_b" will also return values stored under "a_b_c".
 *
 * @param member membership handle
 * @param state_name name of the state to query (full name 
 *        might be longer, this is only the prefix that must match)
 * @param cb function to call on the matching state values
 * @param cb_cls closure for 'cb'
 * @return message ID for which the state was returned (last seen
 *         message ID)
 */
uint64_t
GNUNET_PSYC_member_state_get_all (struct GNUNET_PSYC_Member *member,
				  const char *state_name,
				  GNUNET_PSYC_StateCallback cb,
				  void *cb_cls);


/**
 * Obtain the current value of the best-matching value in the state
 * (including variables).  Note that variables are only valid during a
 * GNUNET_PSYC_Method invocation, as variables are only valid for the
 * duration of a method invocation.  
 *
 * If the requested variable name does not have an exact state in
 * the state, the nearest less-specific name is matched; for example,
 * requesting "a_b" will match "a" if "a_b" does not exist.
 *
 * @param member membership handle
 * @param variable_name name of the variable to query 
 * @param return_value_size set to number of bytes in variable, 
 *        needed as variables might contain binary data and
 *        might also not be 0-terminated; set to 0 on errors
 * @return NULL on error (no matching state or variable), pointer
          to the respective value otherwise
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
