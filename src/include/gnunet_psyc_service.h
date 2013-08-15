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
 *   channel master (the one with the private key) is then
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
 *   construct an 'inbox' channel where the master (only)
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
#include "gnunet_psyc_lib.h"
#include "gnunet_multicast_service.h"


/** 
 * Version number of GNUnet-PSYC API.
 */
#define GNUNET_PSYC_VERSION 0x00000000


/** 
 * Policy flags for a channel.
 */
enum GNUNET_PSYC_ChannelFlags
{
  /**
   * Admission must be confirmed by the master.
   */
  GNUNET_PSYC_CHANNEL_ADMISSION_CONTROL = 1 << 0,

  /**
   * Past messages are only available to slaves who were admitted at the time
   * they were sent to the channel.
   */
  GNUNET_PSYC_CHANNEL_RESTRICTED_HISTORY = 1 << 1,
};

/** 
 * PSYC channel policies.
 */
enum GNUNET_PSYC_Policy
{
  /**
   * Anyone can join the channel, without announcing his presence;
   * all messages are always public and can be distributed freely.
   * Joins may be announced, but this is not required.
   */
  GNUNET_PSYC_CHANNEL_ANONYMOUS = 0,

  /** 
   * The master must approve membership to the channel, messages must only be
   * distributed to current channel slaves.  This includes the channel
   * state as well as transient messages.
   */
  GNUNET_PSYC_CHANNEL_PRIVATE
    = GNUNET_PSYC_CHANNEL_ADMISSION_CONTROL
    | GNUNET_PSYC_CHANNEL_RESTRICTED_HISTORY,

#if IDEAS_FOR_FUTURE
  /** 
   * Anyone can freely join the channel (no approval required);
   * however, messages must only be distributed to current channel
   * slaves, so the master must still acknowledge that the slave
   * joined before transient messages are delivered.  As approval is
   * guaranteed, the presistent channel state can be synchronized freely
   * immediately, prior to master confirmation.
   */
  GNUNET_PSYC_CHANNEL_OPEN
    = GNUNET_PSYC_CHANNEL_RESTRICTED_HISTORY,

  /**
   * The master must approve joins to the channel, but past messages can be
   * freely distributed to slaves.
   */
  GNUNET_PSYC_CHANNEL_CLOSED
    = GNUNET_PSYC_CHANNEL_ADMISSION_CONTROL,
,
#endif

};


enum GNUNET_PSYC_MessageFlags
{
  /**
   * First fragment of a message.
   */
  GNUNET_PSYC_MESSAGE_FIRST_FRAGMENT = 1 << 0,

  /**
   * Last fragment of a message.
   */
  GNUNET_PSYC_MESSAGE_LAST_FRAGMENT = 1 << 1,

  /** 
   * OR'ed flags if message is not fragmented.
   */
  GNUNET_PSYC_MESSAGE_NOT_FRAGMENTED
    = GNUNET_PSYC_MESSAGE_FIRST_FRAGMENT
    | GNUNET_PSYC_MESSAGE_LAST_FRAGMENT,

  /**
   * Historic message, retrieved from PSYCstore.
   */
  GNUNET_PSYC_MESSAGE_HISTORIC = 1 << 30
};


/** 
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_PSYC_JoinCallback to the
 * corresponding calls to GNUNET_PSYC_join_decision().
 */
struct GNUNET_PSYC_JoinHandle;


/** 
 * Method called from PSYC upon receiving a message indicating a call
 * to a @e method.
 *
 * @param cls Closure.
 * @param slave_key Who transmitted the message.
 *        - NULL for multicast messages from the master.
 *        - The hash of the sending slave's public key for unicast requests from
 *          one of the slaves to the master.
 * @param message_id Unique message counter for this message.
 *        Unique only in combination with the given sender for this channel.
 * @param method_name Method name from PSYC.
 * @param modifier_count Number of elements in the @a modifiers array.
 * @param modifiers State modifiers and transient variables for the message.
 * @param data_offset Byte offset of @a data in the overall data of the method.
 * @param data_size Number of bytes in @a data.
 * @param data Data stream given to the method (might not be zero-terminated
 *             if data is binary).
 * @param frag Fragmentation status for the data.
 */
typedef int
(*GNUNET_PSYC_Method) (void *cls,
                       const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                       uint64_t message_id,
                       const char *method_name,
                       size_t modifier_count,
                       const GNUNET_ENV_Modifier *modifiers,
                       uint64_t data_offset,
                       size_t data_size,
                       const void *data,
                       enum GNUNET_PSYC_MessageFlags flags);


/** 
 * Method called from PSYC upon receiving a join request.
 *
 * @param cls Closure.
 * @param slave  requesting to join.
 * @param method_name Method name in the join request.
 * @param variable_count Number of elements in the @a variables array.
 * @param variables Transient variables for the join request.
 * @param data_size Number of bytes in @a data.
 * @param data Data stream given to the method (might not be zero-terminated
 *             if data is binary).
 */
typedef int
(*GNUNET_PSYC_JoinCallback) (void *cls,
                             const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                             const char *method_name,
                             size_t variable_count,
                             const GNUNET_ENV_Modifier *variables,
                             size_t data_size,
                             const void *data,
                             struct GNUNET_PSYC_JoinHandle *jh);


/** 
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_PSYC_JoinCallback.
 *
 * @param jh Join request handle.
 * @param is_admitted #GNUNET_YES if joining is approved,
 *        #GNUNET_NO if it is disapproved.
 * @param relay_count Number of relays given.
 * @param relays Array of suggested peers that might be useful relays to use
 *        when joining the multicast group (essentially a list of peers that
 *        are already part of the multicast group and might thus be willing
 *        to help with routing).  If empty, only this local peer (which must
 *        be the multicast origin) is a good candidate for building the
 *        multicast tree.  Note that it is unnecessary to specify our own
 *        peer identity in this array.
 * @param method_name Method name for the message transmitted with the response.
 * @param env Environment containing transient variables for the message, or NULL.
 * @param data_size Size of @a data.
 * @param data Data of the message.
 */
void
GNUNET_PSYC_join_decision (struct GNUNET_PSYC_JoinHandle *jh,
                           int is_admitted,
                           unsigned int relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const char *method_name,
                           const struct GNUNET_ENV_Environment *env,
                           size_t data_size,
                           const void *data);


/** 
 * Handle for the master of a PSYC channel.
 */
struct GNUNET_PSYC_Master;


/** 
 * Start a PSYC master channel.
 *
 * Will start a multicast group identified by the given ECC key.  Messages
 * received from group members will be given to the respective handler methods.
 * If a new member wants to join a group, the "join" method handler will be
 * invoked; the join handler must then generate a "join" message to approve the
 * joining of the new member.  The channel can also change group membership
 * without explicit requests.  Note that PSYC doesn't itself "understand" join
 * or part messages, the respective methods must call other PSYC functions to
 * inform PSYC about the meaning of the respective events.
 *
 * @param cfg Configuration to use (to connect to PSYC service).
 * @param channel_key ECC key that will be used to sign messages for this
 *        PSYC session. The public key is used to identify the PSYC channel.
 *        Note that end-users will usually not use the private key directly, but
 *        rather look it up in GADS for places managed by other users, or select
 *        a file with the private key(s) when setting up their own channels
 *        FIXME: we'll likely want to use NOT the p521 curve here, but a cheaper
 *        one in the future.
 * @param policy Channel policy specifying join and history restrictions.
 *        Used to automate join decisions.
 * @param method Function to invoke on messages received from slaves.
 * @param join_cb Function to invoke when a peer wants to join.
 * @param cls Closure for @a method and @a join_cb.
 * @return Handle for the channel master, NULL on error.
 */
struct GNUNET_PSYC_Master *
GNUNET_PSYC_master_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_CRYPTO_EccPrivateKey *channel_key,
                          enum GNUNET_PSYC_Policy policy,
                          GNUNET_PSYC_Method method,
                          GNUNET_PSYC_JoinCallback join_cb,
                          void *cls);


/** 
 * Function called to provide data for a transmission via PSYC.
 *
 * Note that returning #GNUNET_OK or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param message_id Set to the unique message ID that was generated for
 *        this message.
 * @param[in,out] data_size Initially set to the number of bytes available in @a data,
 *        should be set to the number of bytes written to data (IN/OUT).
 * @param[out] data Where to write the body of the message to give to the method;
 *        function must copy at most @a *data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission)
 *         #GNUNET_NO on success, if more data is to be transmitted later
 *         (should be used if @a *data_size was not big enough to take all the data)
 *         #GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int
(*GNUNET_PSYC_MasterTransmitNotify)(void *cls,
                                    uint64_t message_id,
                                    size_t *data_size,
                                    void *data);



/**
 * Flags for transmitting messages to a channel by the master.
 */
enum GNUNET_PSYC_MasterTransmitFlags
{
  /** 
   * Whether this message should reset the channel state,
   * i.e. remove all previously stored state variables.
   */
  GNUNET_PSYC_MASTER_TRANSMIT_RESET_STATE = 1 << 0,

  /** 
   * Whether we need to increment the group generation counter after
   * transmitting this message.
   */
  GNUNET_PSYC_MASTER_TRANSMIT_INC_GROUP_GEN = 1 << 1,

  /**
   * Add PSYC header variable with the hash of the current channel state.
   */
  GNUNET_PSYC_MASTER_TRANSMIT_ADD_STATE_HASH = 1 << 2
};


/** 
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_MasterTransmitHandle;


/** 
 * Send a message to call a method to all members in the PSYC channel.
 *
 * @param master Handle to the PSYC channel.
 * @param method_name Which method should be invoked.
 * @param env Environment containing state operations and transient variables
 *            for the message, or NULL.
 * @param notify Function to call to obtain the arguments.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_MasterTransmitHandle *
GNUNET_PSYC_master_transmit (struct GNUNET_PSYC_Master *master,
                             const char *method_name,
                             const struct GNUNET_ENV_Environment *env,
                             GNUNET_PSYC_MasterTransmitNotify notify,
                             void *notify_cls,
                             enum GNUNET_PSYC_TransmitFlags flags);


/** 
 * Abort transmission request to channel.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_master_transmit_cancel (struct GNUNET_PSYC_MasterTransmitHandle *th);


/** 
 * Stop a PSYC master channel.
 *
 * @param master PSYC channel master to stop.
 */
void
GNUNET_PSYC_master_stop (struct GNUNET_PSYC_Master *master);


/** 
 * Handle for a PSYC channel slave.
 */
struct GNUNET_PSYC_Slave;


/** 
 * Join a PSYC channel.
 *
 * The entity joining is always the local peer.  The user must immediately use
 * the GNUNET_PSYC_slave_to_master() functions to transmit a @e join_msg to the
 * channel; if the join request succeeds, the channel state (and @e recent
 * method calls) will be replayed to the joining member.  There is no explicit
 * notification on failure (as the channel may simply take days to approve,
 * and disapproval is simply being ignored).
 *
 * @param cfg Configuration to use.
 * @param channel_key ECC public key that identifies the channel we wish to join.
 * @param slave_key ECC private-public key pair that identifies the slave, and
 *        used by multicast to sign the join request and subsequent unicast
 *        requests sent to the master.
 * @param origin Peer identity of the origin.
 * @param relay_count Number of peers in the @a relays array.
 * @param relays Peer identities of members of the multicast group, which serve
 *        as relays and used to join the group at.
 * @param method Function to invoke on messages received from the channel,
 *        typically at least contains functions for @e join and @e part.
 * @param join_cb Function to invoke when a peer wants to join.
 * @param cls Closure for @a method_cb and @a join_cb.
 * @param method_name Method name for the join request.
 * @param env Environment containing transient variables for the request, or NULL.
 * @param data_size Number of bytes in @a data.
 * @param data Payload for the join message.
 * @return Handle for the slave, NULL on error.
 */
struct GNUNET_PSYC_Slave *
GNUNET_PSYC_slave_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
                        const struct GNUNET_CRYPTO_EccPublicKey *channel_key,
                        const struct GNUNET_CRYPTO_EccPrivateKey *slave_key,
                        const struct GNUNET_PeerIdentity *origin,
                        size_t relay_count,
                        const struct GNUNET_PeerIdentity *relays,
                        GNUNET_PSYC_Method method,
                        GNUNET_PSYC_JoinCallback join_cb,
                        void *cls,
                        const char *method_name,
                        const struct GNUNET_ENV_Environment *env,
                        size_t data_size,
                        const void *data);


/** 
 * Part a PSYC channel.
 *
 * Will terminate the connection to the PSYC service.  Polite clients should
 * first explicitly send a @e part request (via GNUNET_PSYC_slave_to_master()).
 *
 * @param slave Slave handle.
 */
void
GNUNET_PSYC_slave_part (struct GNUNET_PSYC_Slave *slave);


/** 
 * Function called to provide data for a transmission to the channel
 * master (aka the @e host of the channel).
 *
 * Note that returning #GNUNET_OK or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param[in,out] data_size Initially set to the number of bytes available in @a data,
 *        should be set to the number of bytes written to data (IN/OUT).
 * @param[out] data Where to write the body of the message to give to the method;
 *        function must copy at most @a *data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission).
 *         #GNUNET_NO on success, if more data is to be transmitted later.
 *         #GNUNET_YES if this completes the transmission (all data supplied).
 */
typedef int
(*GNUNET_PSYC_SlaveTransmitNotify) (void *cls,
                                    size_t *data_size,
                                    char *data);


/**
 * Flags for transmitting messages to the channel master by a slave.
 */
enum GNUNET_PSYC_SlaveTransmitFlags;

/** 
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_SlaveTransmitHandle;


/** 
 * Request a message to be sent to the channel master.
 *
 * @param slave Slave handle.
 * @param method_name Which (PSYC) method should be invoked (on host).
 * @param env Environment containing transient variables for the message, or NULL.
 * @param notify Function to call when we are allowed to transmit (to get data).
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_SlaveTransmitHandle *
GNUNET_PSYC_slave_transmit (struct GNUNET_PSYC_Slave *slave,
                            const char *method_name,
                            const struct GNUNET_ENV_Environment *env,
                            GNUNET_PSYC_SlaveTransmitNotify notify,
                            void *notify_cls,
                            enum GNUNET_PSYC_SlaveTransmitFlags flags);


/** 
 * Abort transmission request to master.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_slave_transmit_cancel (struct GNUNET_PSYC_SlaveTransmitHandle *th);


/** 
 * Handle to access PSYC channel operations for both the master and slaves.
 */
struct GNUNET_PSYC_Channel;


/** 
 * Convert a channel @a master to a @e channel handle to access the @e channel APIs.
 *
 * @param master Channel master handle.
 * @return Channel handle, valid for as long as @a master is valid.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_master_get_channel (struct GNUNET_PSYC_Master *master);


/** 
 * Convert @a slave to a @e channel handle to access the @e channel APIs.
 *
 * @param slave Slave handle.
 * @return Channel handle, valid for as long as @a slave is valid.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_slave_get_channel (struct GNUNET_PSYC_Slave *slave);


/** 
 * Add a slave to the channel's membership list.
 *
 * Note that this will NOT generate any PSYC traffic, it will merely update the
 * local database to modify how we react to <em>membership test</em> queries.
 * The channel master still needs to explicitly transmit a @e join message to
 * notify other channel members and they then also must still call this function
 * in their respective methods handling the @e join message.  This way, how @e
 * join and @e part operations are exactly implemented is still up to the
 * application; for example, there might be a @e part_all method to kick out
 * everyone.
 *
 * Note that channel slaves are explicitly trusted to execute such methods
 * correctly; not doing so correctly will result in either denying other slaves
 * access or offering access to channel data to non-members.
 *
 * @param channel Channel handle.
 * @param slave_key Identity of channel slave to add.
 * @param announced_at ID of the message that announced the membership change.
 * @param effective_since Addition of slave is in effect since this message ID.
 */
void
GNUNET_PSYC_channel_slave_add (struct GNUNET_PSYC_Channel *channel,
                               const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                               uint64_t announced_at,
                               uint64_t effective_since);


/** 
 * Remove a slave from the channel's membership list.
 *
 * Note that this will NOT generate any PSYC traffic, it will merely update the
 * local database to modify how we react to <em>membership test</em> queries.
 * The channel master still needs to explicitly transmit a @e part message to
 * notify other channel members and they then also must still call this function
 * in their respective methods handling the @e part message.  This way, how
 * @e join and @e part operations are exactly implemented is still up to the
 * application; for example, there might be a @e part_all message to kick out
 * everyone.
 *
 * Note that channel members are explicitly trusted to perform these
 * operations correctly; not doing so correctly will result in either
 * denying members access or offering access to channel data to
 * non-members.
 *
 * @param channel Channel handle.
 * @param slave_key Identity of channel slave to remove.
 * @param announced_at ID of the message that announced the membership change.
 * @param effective_since Removal of slave is in effect since this message ID.
 */
void
GNUNET_PSYC_channel_slave_remove (struct GNUNET_PSYC_Channel *channel,
                                  const struct GNUNET_CRYPTO_EccPublicKey *slave_key,
                                  uint64_t announced_at,
                                  uint64_t effective_since);


/** 
 * Function called to inform a member about stored state values for a channel.
 *
 * @param cls Closure.
 * @param name Name of the state variable.  A NULL value indicates that there
 *        are no more state variables to be returned.
 * @param value_size Number of bytes in @a value.
 * @param value Value of the state variable.
 */
typedef void
(*GNUNET_PSYC_StateCallback) (void *cls,
                              const char *name,
                              size_t value_size,
                              const void *value);


/**
 * Function called when a requested operation has finished.
 *
 * @param cls Closure.
 */
typedef void
(*GNUNET_PSYC_FinishCallback) (void *cls);


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
 * @param channel Which channel should be replayed?
 * @param start_message_id Earliest interesting point in history.
 * @param end_message_id Last (exclusive) interesting point in history.
 * @param method Function to invoke on messages received from the story.
 * @param finish_cb Function to call when the requested story has been fully
 *        told (counting message IDs might not suffice, as some messages
 *        might be secret and thus the listener would not know the story is
 *        finished without being told explicitly); once this function
 *        has been called, the client must not call
 *        GNUNET_PSYC_channel_story_tell_cancel() anymore.
 * @param cls Closure for the callbacks.
 * @return Handle to cancel story telling operation.
 */
struct GNUNET_PSYC_Story *
GNUNET_PSYC_channel_story_tell (struct GNUNET_PSYC_Channel *channel,
                                uint64_t start_message_id,
                                uint64_t end_message_id,
                                GNUNET_PSYC_Method method,
                                GNUNET_PSYC_FinishCallback *finish_cb,
                                void *cls);


/** 
 * Abort story telling.
 *
 * This function must not be called from within method handlers (as given to
 * GNUNET_PSYC_slave_join()) of the slave.
 *
 * @param story Story telling operation to stop.
 */
void
GNUNET_PSYC_channel_story_tell_cancel (struct GNUNET_PSYC_Story *story);

struct GNUNET_PSYC_StateQuery;


/** 
 * Return all channel state variables whose name matches a given prefix.
 *
 * A name matches if it starts with the given @a name_prefix, thus requesting the
 * empty prefix ("") will match all values; requesting "_a_b" will also return
 * values stored under "_a_b_c".
 *
 * The @a state_cb is invoked on all matching state variables asynchronously, as
 * the state is stored in and retrieved from the PSYCstore,
 *
 * @param channel Channel handle.
 * @param name_prefix Prefix of the state variable name to match.
 * @param cb Function to call with the matching state variables.
 * @param cb_cls Closure for the callbacks.
 * @return Handle that can be used to cancel the query operation.
 */
struct GNUNET_PSYC_StateQuery *
GNUNET_PSYC_channel_state_get_all (struct GNUNET_PSYC_Channel *channel,
                                   const char *name_prefix,
                                   GNUNET_PSYC_StateCallback cb,
                                   void *cb_cls);


/** 
 * Retrieve the best matching channel state variable.
 *
 * If the requested variable name is not present in the state, the nearest
 * less-specific name is matched; for example, requesting "_a_b" will match "_a"
 * if "_a_b" does not exist.
 *
 * @param channel Channel handle.
 * @param full_name Full name of the requested variable, the actual variable
 *        returned might have a shorter name..
 * @param cb Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param cb_cls Closure for the callbacks.
 * @return Handle that can be used to cancel the query operation.
 */
struct GNUNET_PSYC_StateQuery *
GNUNET_PSYC_channel_state_get (struct GNUNET_PSYC_Channel *channel,
                               const char *full_name,
                               GNUNET_PSYC_StateCallback cb,
                               void *cb_cls);


/** 
 * Cancel a state query operation.
 *
 * @param query Handle for the operation to cancel.
 */
void
GNUNET_PSYC_channel_state_get_cancel (struct GNUNET_PSYC_StateQuery *query);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYC_SERVICE_H */
#endif
/* end of gnunet_psyc_service.h */
