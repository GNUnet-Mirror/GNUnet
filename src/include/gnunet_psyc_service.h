/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * PSYC service
 *
 * @defgroup psyc  PSYC service
 * Send/receive messages in PSYC channels and access the PSYC Store.
 *
 * Note that clients of this API are NOT expected to understand the PSYC message
 * format, only the semantics!  Parsing (and serializing) the PSYC stream format
 * is done within the implementation of the libgnunetpsyc library, and this API
 * deliberately exposes as little as possible of the actual data stream format
 * to the application!
 *
 * NOTE:
 * - this API does not know about PSYC's "root" and "places";
 *   there is no 'root' in GNUnet-PSYC as we're decentralized;
 *   'places' and 'persons' are combined within the same
 *   abstraction, that of a "channel".  Channels are identified
 *   and accessed in this API using a public/private key.
 *   Higher-level applications should use NAMES within GNS
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
 *   higher-level API should combine the naming system (GNS)
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
 *
 * @{
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
//Mingw work around
#ifdef MINGW
    # ifndef  UINT64_MAX
    # define  UINT64_MAX 0xffffffffffffffffULL
    # endif
#endif

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
  GNUNET_PSYC_CHANNEL_RESTRICTED_HISTORY = 1 << 1
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
    | GNUNET_PSYC_CHANNEL_RESTRICTED_HISTORY

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
#endif
};


enum GNUNET_PSYC_MessageFlags
{
  /**
   * Default / no flags.
   */
  GNUNET_PSYC_MESSAGE_DEFAULT = 0,

  /**
   * Historic message, retrieved from PSYCstore.
   */
  GNUNET_PSYC_MESSAGE_HISTORIC = 1 << 0,

  /**
   * Request from slave to master.
   */
  GNUNET_PSYC_MESSAGE_REQUEST = 1 << 1,

  /**
   * Message can be delivered out of order.
   */
  GNUNET_PSYC_MESSAGE_ORDER_ANY = 1 << 2
};


/**
 * Values for the @a state_delta field of GNUNET_PSYC_MessageHeader.
 */
enum GNUNET_PSYC_StateDeltaValues
{
  GNUNET_PSYC_STATE_RESET = 0,

  GNUNET_PSYC_STATE_NOT_MODIFIED = UINT64_MAX
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * A PSYC message.
 *
 * Used for single-fragment messages e.g. in a join request or response.
 */
struct GNUNET_PSYC_Message
{
  /**
   * Message header with size and type information.
   */
  struct GNUNET_MessageHeader header;

  /* Followed by concatenated PSYC message parts:
   * messages with GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_* types
   */
};


/**
 * Header of a PSYC message.
 *
 * The PSYC service adds this when delivering the message to local clients,
 * not present on the multicast layer.
 */
struct GNUNET_PSYC_MessageHeader
{
  /**
   * Generic message header with size and type information.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Flags for this message fragment.
   *
   * @see enum GNUNET_PSYC_MessageFlags
   */
  uint32_t flags GNUNET_PACKED;

  /**
   * Number of the message this message part belongs to.
   * Monotonically increasing from 1.
   */
  uint64_t message_id GNUNET_PACKED;

  /**
   * Byte offset of this @e fragment of the @e message.
   * FIXME: use data_offset instead
   */
  uint64_t fragment_offset GNUNET_PACKED;

  /**
   * Sending slave's public key.
   * Not set if the message is from the master.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

  /* Followed by concatenated PSYC message parts:
   * messages with GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_* types
   */
};


/**
 * The method of a message.
 */
struct GNUNET_PSYC_MessageMethod
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD
   */
  struct GNUNET_MessageHeader header;

  /**
   * OR'ed GNUNET_PSYC_MasterTransmitFlags
   */
  uint32_t flags GNUNET_PACKED;

  /**
   * Number of message IDs since the last message that contained state
   * operations. @see enum GNUNET_PSYC_StateDeltaValues
   */
  uint64_t state_delta GNUNET_PACKED;

  /* Followed by NUL-terminated method name. */
};


/**
 * A modifier of a message.
 */
struct GNUNET_PSYC_MessageModifier
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of value.
   */
  uint32_t value_size GNUNET_PACKED;

  /**
   * Size of name, including NUL terminator.
   */
  uint16_t name_size GNUNET_PACKED;

  /**
   * enum GNUNET_ENV_Operator
   */
  uint8_t oper;

  /* Followed by NUL-terminated name, then the value. */
};


struct GNUNET_PSYC_CountersResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_RESULT_COUNTERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code for the operation.
   */
  uint32_t result_code GNUNET_PACKED;

  /**
   * Last message ID sent to the channel.
   */
  uint64_t max_message_id GNUNET_PACKED;
};


/**
 * Join request sent to a PSYC master.
 */
struct GNUNET_PSYC_JoinRequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_MASTER_JOIN_REQUEST
   */
  struct GNUNET_MessageHeader header;
  /**
   * Public key of the joining slave.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

  /* Followed by struct GNUNET_MessageHeader join_request */
};


/**
 * Join decision sent in reply to a join request.
 */
struct GNUNET_PSYC_JoinDecisionMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES if the slave was admitted.
   */
  int32_t is_admitted;

  /**
   * Public key of the joining slave.
   * Only set when the master is sending the decision,
   * not set when a slave is receiving it.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;

  /* Followed by struct GNUNET_MessageHeader join_response */
};


enum GNUNET_PSYC_HistoryReplayFlags
{
  /**
   * Replay locally available messages.
   */
  GNUNET_PSYC_HISTORY_REPLAY_LOCAL  = 0,

  /**
   * Replay messages from remote peers if not found locally.
   */
  GNUNET_PSYC_HISTORY_REPLAY_REMOTE = 1,
};


struct GNUNET_PSYC_HistoryRequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_HISTORY_REPLAY
   */
  struct GNUNET_MessageHeader header;

  /**
   * @see enum GNUNET_PSYC_HistoryReplayFlags
   */
  uint32_t flags GNUNET_PACKED;

  /**
   * ID for this operation.
   */
  uint64_t op_id GNUNET_PACKED;

  uint64_t start_message_id GNUNET_PACKED;

  uint64_t end_message_id GNUNET_PACKED;

  uint64_t message_limit GNUNET_PACKED;

  /* Followed by NUL-terminated method name prefix. */
};


struct GNUNET_PSYC_StateRequestMessage
{
  /**
   * Types:
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_GET
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_GET_PREFIX
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * ID for this operation.
   */
  uint64_t op_id GNUNET_PACKED;

  /* Followed by NUL-terminated name. */
};


/**** service -> library ****/


/**
 * Answer from service to client about last operation.
 */
struct GNUNET_PSYC_OperationResultMessage
{
  /**
   * Types:
   * - GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_RESULT
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Status code for the operation.
   */
  uint64_t result_code GNUNET_PACKED;

  /* Followed by:
   * - on error: NUL-terminated error message
   * - on success: one of the following message types
   *
   *   For a STATE_RESULT, one of:
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END
   */
};

GNUNET_NETWORK_STRUCT_END


#define GNUNET_PSYC_MODIFIER_MAX_PAYLOAD        \
  GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD         \
  - sizeof (struct GNUNET_PSYC_MessageModifier)

#define GNUNET_PSYC_MOD_CONT_MAX_PAYLOAD        \
  GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD         \
  - sizeof (struct GNUNET_MessageHeader)

#define GNUNET_PSYC_DATA_MAX_PAYLOAD            \
  GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD         \
  - sizeof (struct GNUNET_MessageHeader)


/**
 * PSYC message part processing states.
 */
enum GNUNET_PSYC_MessageState
{
  GNUNET_PSYC_MESSAGE_STATE_START    = 0,
  GNUNET_PSYC_MESSAGE_STATE_HEADER   = 1,
  GNUNET_PSYC_MESSAGE_STATE_METHOD   = 2,
  GNUNET_PSYC_MESSAGE_STATE_MODIFIER = 3,
  GNUNET_PSYC_MESSAGE_STATE_MOD_CONT = 4,
  GNUNET_PSYC_MESSAGE_STATE_DATA     = 5,
  GNUNET_PSYC_MESSAGE_STATE_END      = 6,
  GNUNET_PSYC_MESSAGE_STATE_CANCEL   = 7,
  GNUNET_PSYC_MESSAGE_STATE_ERROR    = 8,
};


/**
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_PSYC_JoinCallback to the
 * corresponding calls to GNUNET_PSYC_join_decision().
 */
struct GNUNET_PSYC_JoinHandle;


/**
 * Method called from PSYC upon receiving a message.
 *
 * @param cls  Closure.
 * @param message_id  Sequence number of the message.
 * @param flags  OR'ed GNUNET_PSYC_MessageFlags
 * @param msg  Message part, one of the following types:
 */
typedef void
(*GNUNET_PSYC_MessageCallback) (void *cls,
                                uint64_t message_id,
                                uint32_t flags,
                                const struct GNUNET_PSYC_MessageHeader *msg);


/**
 * Method called from PSYC upon receiving part of a message.
 *
 * @param cls
 *        Closure.
 * @param slave_pub_key
 *        Public key of the slave sending the message.
 *        Only set for channel master.
 * @param message_id
 *        Sequence number of the message.
 * @param flags
 *        OR'ed GNUNET_PSYC_MessageFlags
 * @param data_offset
 *        Byte offset of data, only set if @a msg has a type
 *        #GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA
 * @param msg  Message part, one of the following types:
 * - #GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_HEADER
 * - #GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD
 * - #GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER
 * - #GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT
 * - #GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA
 * or NULL if an error occurred while receiving a message.
 */
typedef void
(*GNUNET_PSYC_MessagePartCallback) (void *cls,
                                    const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                                    uint64_t message_id,
                                    uint32_t flags,
                                    uint64_t data_offset,
                                    const struct GNUNET_MessageHeader *msg);


/**
 * Method called from PSYC upon receiving a join request.
 *
 * @param cls
 *        Closure.
 * @param slave_pub_key
 *        Public key of the slave requesting join.
 * @param join_msg
 *        Join message sent along with the request.
 * @param jh
 *        Join handle to use with GNUNET_PSYC_join_decision()
 */
typedef void
(*GNUNET_PSYC_JoinRequestCallback) (void *cls,
                                    const struct GNUNET_PSYC_JoinRequestMessage *req,
                                    const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                                    const struct GNUNET_PSYC_Message *join_msg,
                                    struct GNUNET_PSYC_JoinHandle *jh);


/**
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_PSYC_JoinCallback.
 *
 * @param jh  Join request handle.
 * @param is_admitted
 *   #GNUNET_YES    if the join is approved,
 *   #GNUNET_NO     if it is disapproved,
 *   #GNUNET_SYSERR if we cannot answer the request.
 * @param relay_count  Number of relays given.
 * @param relays  Array of suggested peers that might be useful relays to use
 *        when joining the multicast group (essentially a list of peers that
 *        are already part of the multicast group and might thus be willing
 *        to help with routing).  If empty, only this local peer (which must
 *        be the multicast origin) is a good candidate for building the
 *        multicast tree.  Note that it is unnecessary to specify our own
 *        peer identity in this array.
 * @param join_resp  Application-dependent join response message to send along
 *        with the decision.
 *
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if @a join_resp is too large.
 */
int
GNUNET_PSYC_join_decision (struct GNUNET_PSYC_JoinHandle *jh,
                           int is_admitted,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_PSYC_Message *join_resp);


/**
 * Handle for the master of a PSYC channel.
 */
struct GNUNET_PSYC_Master;


/**
 * Function called after connected to the PSYC service
 * and the channel master started.
 *
 * Also called when reconnected to the service
 * after the connection closed unexpectedly.
 *
 * @param cls
 *        Closure.
 * @param result
 *        #GNUNET_YES if there were already messages sent to the channel,
 *        #GNUNET_NO  if the message history is empty,
 *        #GNUNET_SYSERR on error.
 * @param max_message_id
 *        Last message ID sent to the channel.
 */
typedef void
(*GNUNET_PSYC_MasterStartCallback) (void *cls, int result,
                                    uint64_t max_message_id);


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
 * @param cfg  Configuration to use (to connect to PSYC service).
 * @param channel_key  ECC key that will be used to sign messages for this
 *        PSYC session. The public key is used to identify the PSYC channel.
 *        Note that end-users will usually not use the private key directly, but
 *        rather look it up in GNS for places managed by other users, or select
 *        a file with the private key(s) when setting up their own channels
 *        FIXME: we'll likely want to use NOT the p521 curve here, but a cheaper
 *        one in the future.
 * @param policy  Channel policy specifying join and history restrictions.
 *        Used to automate join decisions.
 * @param master_start_cb  Function to invoke after the channel master started.
 * @param join_request_cb  Function to invoke when a slave wants to join.
 * @param message_cb  Function to invoke on message parts sent to the channel
 *        and received from slaves
 * @param cls  Closure for @a method and @a join_cb.
 *
 * @return Handle for the channel master, NULL on error.
 */
struct GNUNET_PSYC_Master *
GNUNET_PSYC_master_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key,
                          enum GNUNET_PSYC_Policy policy,
                          GNUNET_PSYC_MasterStartCallback master_start_cb,
                          GNUNET_PSYC_JoinRequestCallback join_request_cb,
                          GNUNET_PSYC_MessageCallback message_cb,
                          GNUNET_PSYC_MessagePartCallback message_part_cb,
                          void *cls);


/**
 * Function called to provide data for a transmission via PSYC.
 *
 * Note that returning #GNUNET_YES or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param[in,out] data_size Initially set to the number of bytes available in
 *        @a data, should be set to the number of bytes written to data.
 * @param[out] data Where to write the body of the message to give to the
 *         method. The function must copy at most @a data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission)
 *         #GNUNET_NO on success, if more data is to be transmitted later.
 *         Should be used if @a data_size was not big enough to take all the
 *         data.  If 0 is returned in @a data_size the transmission is paused,
 *         and can be resumed with GNUNET_PSYC_master_transmit_resume().
 *         #GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int
(*GNUNET_PSYC_TransmitNotifyData) (void *cls,
                                   uint16_t *data_size,
                                   void *data);

/**
 * Function called to provide a modifier for a transmission via PSYC.
 *
 * Note that returning #GNUNET_YES or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param[in,out] data_size  Initially set to the number of bytes available in
 *         @a data, should be set to the number of bytes written to data.
 * @param[out] data  Where to write the modifier's name and value.
 *         The function must copy at most @a data_size bytes to @a data.
 *         When this callback is first called for a modifier, @a data should
 *         contain: "name\0value".  If the whole value does not fit, subsequent
 *         calls to this function should write continuations of the value to
 *         @a data.
 * @param[out] oper  Where to write the operator of the modifier.
 *         Only needed during the first call to this callback at the beginning
 *         of the modifier.  In case of subsequent calls asking for value
 *         continuations @a oper is set to #NULL.
 * @param[out] full_value_size  Where to write the full size of the value.
 *         Only needed during the first call to this callback at the beginning
 *         of the modifier.  In case of subsequent calls asking for value
 *         continuations @a value_size is set to #NULL.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission)
 *         #GNUNET_NO on success, if more data is to be transmitted later.
 *         Should be used if @a data_size was not big enough to take all the
 *         data for the modifier's value (the name must be always returned
 *         during the first call to this callback).
 *         If 0 is returned in @a data_size the transmission is paused,
 *         and can be resumed with GNUNET_PSYC_master_transmit_resume().
 *         #GNUNET_YES if this completes the modifier (the whole value is supplied).
 */
typedef int
(*GNUNET_PSYC_TransmitNotifyModifier) (void *cls,
                                       uint16_t *data_size,
                                       void *data,
                                       uint8_t *oper,
                                       uint32_t *full_value_size);

/**
 * Flags for transmitting messages to a channel by the master.
 */
enum GNUNET_PSYC_MasterTransmitFlags
{
  GNUNET_PSYC_MASTER_TRANSMIT_NONE = 0,

  /**
   * Whether this message should reset the channel state,
   * i.e. remove all previously stored state variables.
   */

  GNUNET_PSYC_MASTER_TRANSMIT_STATE_RESET = 1 << 0,

  /**
   * Whether this message contains any state modifiers.
   */
  GNUNET_PSYC_MASTER_TRANSMIT_STATE_MODIFY = 1 << 1,

  /**
   * Add PSYC header variable with the hash of the current channel state.
   */
  GNUNET_PSYC_MASTER_TRANSMIT_STATE_HASH = 1 << 2,

  /**
   * Whether we need to increment the group generation counter after
   * transmitting this message.
   */
  GNUNET_PSYC_MASTER_TRANSMIT_INC_GROUP_GEN = 1 << 3
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
 * @param notify_mod Function to call to obtain modifiers.
 * @param notify_data Function to call to obtain fragments of the data.
 * @param notify_cls Closure for @a notify_mod and @a notify_data.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_MasterTransmitHandle *
GNUNET_PSYC_master_transmit (struct GNUNET_PSYC_Master *master,
                             const char *method_name,
                             GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                             GNUNET_PSYC_TransmitNotifyData notify_data,
                             void *notify_cls,
                             enum GNUNET_PSYC_MasterTransmitFlags flags);


/**
 * Resume transmission to the channel.
 *
 * @param th Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_master_transmit_resume (struct GNUNET_PSYC_MasterTransmitHandle *th);


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
 * @param master
 *        PSYC channel master to stop.
 * @param keep_active
 *        Keep place active after last application disconnected.
 * @param stop_cb
 *        Function called after the master stopped
 *        and disconnected from the psyc service.
 * @param stop_cls
 *        Closure for @a part_cb.
 */
void
GNUNET_PSYC_master_stop (struct GNUNET_PSYC_Master *master,
                         int keep_active,
                         GNUNET_ContinuationCallback stop_cb,
                         void *stop_cls);


/**
 * Handle for a PSYC channel slave.
 */
struct GNUNET_PSYC_Slave;


/**
 * Function called after the slave connected to the PSYC service.
 *
 * Also called when reconnected to the service
 * after the connection closed unexpectedly.
 *
 * @param cls
 *        Closure.
 * @param result
 *        #GNUNET_YES if there were already messages sent to the channel,
 *        #GNUNET_NO  if the message history is empty,
 *        #GNUNET_SYSERR on error.
 * @param max_message_id
 *        Last message ID sent to the channel.
 */
typedef void
(*GNUNET_PSYC_SlaveConnectCallback) (void *cls, int result,
                                     uint64_t max_message_id);


/**
 * Method called to inform about the decision in response to a join request.
 *
 * If @a is_admitted is not #GNUNET_YES, then sending messages to the channel is
 * not possible, but earlier history can be still queried.
 *
 * @param cls  Closure.
 * @param is_admitted  #GNUNET_YES or #GNUNET_NO or #GNUNET_SYSERR
 * @param join_msg  Application-dependent join message from the origin.
 */
typedef void
(*GNUNET_PSYC_JoinDecisionCallback) (void *cls,
                                     const struct GNUNET_PSYC_JoinDecisionMessage *dcsn,
                                     int is_admitted,
                                     const struct GNUNET_PSYC_Message *join_msg);

/**
 * Flags for GNUNET_PSYC_slave_join()
 */
enum GNUNET_PSYC_SlaveJoinFlags
{
  GNUNET_PSYC_SLAVE_JOIN_NONE	= 0,

  /**
   * Local join for history access, no network connection is established.
   */
  GNUNET_PSYC_SLAVE_JOIN_LOCAL	= 1,
};


/**
 * Join a PSYC channel.
 *
 * The entity joining is always the local peer.  The user must immediately use
 * the GNUNET_PSYC_slave_transmit() functions to transmit a @e join_msg to the
 * channel; if the join request succeeds, the channel state (and @e recent
 * method calls) will be replayed to the joining member.  There is no explicit
 * notification on failure (as the channel may simply take days to approve,
 * and disapproval is simply being ignored).
 *
 * @param cfg
 *        Configuration to use.
 * @param channel_pub_key
 *        ECC public key that identifies the channel we wish to join.
 * @param slave_pub_key
 *        ECC private-public key pair that identifies the slave, and
 *        used by multicast to sign the join request and subsequent unicast
 *        requests sent to the master.
 * @param flags
 *        Join flags.
 * @param origin
 *        Peer identity of the origin.
 * @param relay_count
 *        Number of peers in the @a relays array.
 * @param relays
 *        Peer identities of members of the multicast group, which serve
 *        as relays and used to join the group at.
 * @param message_cb
 *        Function to invoke on message fragments received from the channel.
 * @param message_part_cb
 *        Function to invoke on message parts received from the channel.
 * @param slave_connect_cb
 *        Function invoked once we have connected to the PSYC service.
 * @param join_decision_cb
 *        Function invoked once we have received a join decision.
 * @param cls
 *        Closure for @a message_cb and @a slave_joined_cb.
 * @param join_msg
 *        Join message.
 *
 * @return Handle for the slave, NULL on error.
 */
struct GNUNET_PSYC_Slave *
GNUNET_PSYC_slave_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
                        const struct GNUNET_CRYPTO_EddsaPublicKey *channel_pub_key,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *slave_pub_key,
                        enum GNUNET_PSYC_SlaveJoinFlags flags,
                        const struct GNUNET_PeerIdentity *origin,
                        uint32_t relay_count,
                        const struct GNUNET_PeerIdentity *relays,
                        GNUNET_PSYC_MessageCallback message_cb,
                        GNUNET_PSYC_MessagePartCallback message_part_cb,
                        GNUNET_PSYC_SlaveConnectCallback slave_connect_cb,
                        GNUNET_PSYC_JoinDecisionCallback join_decision_cb,
                        void *cls,
                        const struct GNUNET_PSYC_Message *join_msg);


/**
 * Part a PSYC channel.
 *
 * Will terminate the connection to the PSYC service.  Polite clients should
 * first explicitly send a part request (via GNUNET_PSYC_slave_transmit()).
 *
 * @param slave
 *        Slave handle.
 * @param keep_active
 *        Keep place active after last application disconnected.
 * @param part_cb
 *        Function called after the slave parted the channel
 *        and disconnected from the psyc service.
 * @param part_cls
 *        Closure for @a part_cb.
 */
void
GNUNET_PSYC_slave_part (struct GNUNET_PSYC_Slave *slave,
                        int keep_active,
                        GNUNET_ContinuationCallback part_cb,
                        void *part_cls);


/**
 * Flags for transmitting messages to the channel master by a slave.
 */
enum GNUNET_PSYC_SlaveTransmitFlags
{
  GNUNET_PSYC_SLAVE_TRANSMIT_NONE = 0
};


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_SlaveTransmitHandle;


/**
 * Request a message to be sent to the channel master.
 *
 * @param slave Slave handle.
 * @param method_name Which (PSYC) method should be invoked (on host).
 * @param notify_mod Function to call to obtain modifiers.
 * @param notify_data Function to call to obtain fragments of the data.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_SlaveTransmitHandle *
GNUNET_PSYC_slave_transmit (struct GNUNET_PSYC_Slave *slave,
                            const char *method_name,
                            GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                            GNUNET_PSYC_TransmitNotifyData notify_data,
                            void *notify_cls,
                            enum GNUNET_PSYC_SlaveTransmitFlags flags);


/**
 * Resume transmission to the master.
 *
 * @param th Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_slave_transmit_resume (struct GNUNET_PSYC_SlaveTransmitHandle *th);


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
 * Convert a channel @a master to a @e channel handle to access the @e channel
 * APIs.
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
 * @param channel
 *        Channel handle.
 * @param slave_pub_key
 *        Identity of channel slave to add.
 * @param announced_at
 *        ID of the message that announced the membership change.
 * @param effective_since
 *        Addition of slave is in effect since this message ID.
 * @param result_cb
 *        Function to call with the result of the operation.
 *        The @e result_code argument is #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error.  In case of an error, the @e data argument
 *        can contain an optional error message.
 * @param cls
 *        Closure for @a result_cb.
 */
void
GNUNET_PSYC_channel_slave_add (struct GNUNET_PSYC_Channel *channel,
                               const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                               uint64_t announced_at,
                               uint64_t effective_since,
                               GNUNET_ResultCallback result_cb,
                               void *cls);


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
 * @param channel
 *        Channel handle.
 * @param slave_pub_key
 *        Identity of channel slave to remove.
 * @param announced_at
 *        ID of the message that announced the membership change.
 * @param result_cb
 *        Function to call with the result of the operation.
 *        The @e result_code argument is #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error.  In case of an error, the @e data argument
 *        can contain an optional error message.
 * @param cls
 *        Closure for @a result_cb.
 */
void
GNUNET_PSYC_channel_slave_remove (struct GNUNET_PSYC_Channel *channel,
                                  const struct GNUNET_CRYPTO_EcdsaPublicKey
                                  *slave_pub_key,
                                  uint64_t announced_at,
                                  GNUNET_ResultCallback result_cb,
                                  void *cls);


/**
 * History request handle.
 */
struct GNUNET_PSYC_HistoryRequest;


/**
 * Request to replay a part of the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is permitted.
 *
 * @param channel
 *        Which channel should be replayed?
 * @param start_message_id
 *        Earliest interesting point in history.
 * @param end_message_id
 *        Last (inclusive) interesting point in history.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 * @param flags
 *        OR'ed enum GNUNET_PSYC_HistoryReplayFlags
 * @param result_cb
 *        Function to call when the requested history has been fully replayed.
 *        Once this function has been called, the client must not call
 *        GNUNET_PSYC_channel_history_replay_cancel() anymore.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle to cancel history replay operation.
 */
struct GNUNET_PSYC_HistoryRequest *
GNUNET_PSYC_channel_history_replay (struct GNUNET_PSYC_Channel *channel,
                                    uint64_t start_message_id,
                                    uint64_t end_message_id,
                                    const char *method_prefix,
                                    uint32_t flags,
                                    GNUNET_PSYC_MessageCallback message_cb,
                                    GNUNET_PSYC_MessagePartCallback message_part_cb,
                                    GNUNET_ResultCallback result_cb,
                                    void *cls);


/**
 * Request to replay the latest messages from the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is permitted.
 *
 * @param channel
 *        Which channel should be replayed?
 * @param message_limit
 *        Maximum number of messages to replay.
 * @param flags
 *        OR'ed enum GNUNET_PSYC_HistoryReplayFlags
 * @param finish_cb
 *        Function to call when the requested history has been fully replayed
 *        (counting message IDs might not suffice, as some messages might be
 *        secret and thus the listener would not know the story is finished
 *        without being told explicitly)o once this function has been called, the
 *        client must not call GNUNET_PSYC_channel_history_replay_cancel() anymore.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle to cancel history replay operation.
 */
struct GNUNET_PSYC_HistoryRequest *
GNUNET_PSYC_channel_history_replay_latest (struct GNUNET_PSYC_Channel *channel,
                                           uint64_t message_limit,
                                           const char *method_prefix,
                                           uint32_t flags,
                                           GNUNET_PSYC_MessageCallback message_cb,
                                           GNUNET_PSYC_MessagePartCallback message_part_cb,
                                           GNUNET_ResultCallback result_cb,
                                           void *cls);


void
GNUNET_PSYC_channel_history_replay_cancel (struct GNUNET_PSYC_Channel *channel,
                                           struct GNUNET_PSYC_HistoryRequest *hr);


/**
 * Function called to inform a member about stored state values for a channel.
 *
 * If @a full_value_size > value_size then this function is called multiple
 * times until the whole value arrived.
 *
 * @param cls
 *        Closure.
 * @param name
 *        Name of the state variable.
 *        NULL if there are no more state variables to be returned.
 * @param value
 *        Value of the state variable.
 * @param value_size
 *        Number of bytes in @a value.
 * @param full_value_size
 *        Number of bytes in the full value, including continuations.
 *        Only set for the first part of a variable,
 *        in case of a continuation it is 0.
 */
typedef void
(*GNUNET_PSYC_StateVarCallback) (void *cls,
                                 const struct GNUNET_MessageHeader *mod,
                                 const char *name,
                                 const void *value,
                                 uint32_t value_size,
                                 uint32_t full_value_size);


/**
 * State request handle.
 */
struct GNUNET_PSYC_StateRequest;


/**
 * Retrieve the best matching channel state variable.
 *
 * If the requested variable name is not present in the state, the nearest
 * less-specific name is matched; for example, requesting "_a_b" will match "_a"
 * if "_a_b" does not exist.
 *
 * @param channel
 *        Channel handle.
 * @param full_name
 *        Full name of the requested variable.
 *        The actual variable returned might have a shorter name.
 * @param var_cb
 *        Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param result_cb
 *        Function called after the operation finished.
 *        (i.e. all state variables have been returned via @a state_cb)
 * @param cls
 *        Closure for the callbacks.
 */
struct GNUNET_PSYC_StateRequest *
GNUNET_PSYC_channel_state_get (struct GNUNET_PSYC_Channel *channel,
                               const char *full_name,
                               GNUNET_PSYC_StateVarCallback var_cb,
                               GNUNET_ResultCallback result_cb,
                               void *cls);


/**
 * Return all channel state variables whose name matches a given prefix.
 *
 * A name matches if it starts with the given @a name_prefix, thus requesting
 * the empty prefix ("") will match all values; requesting "_a_b" will also
 * return values stored under "_a_b_c".
 *
 * The @a state_cb is invoked on all matching state variables asynchronously, as
 * the state is stored in and retrieved from the PSYCstore,
 *
 * @param channel
 *        Channel handle.
 * @param name_prefix
 *        Prefix of the state variable name to match.
 * @param var_cb
 *        Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param result_cb
 *        Function called after the operation finished.
 *        (i.e. all state variables have been returned via @a state_cb)
 * @param cls
 *        Closure for the callbacks.
 */
struct GNUNET_PSYC_StateRequest *
GNUNET_PSYC_channel_state_get_prefix (struct GNUNET_PSYC_Channel *channel,
                                      const char *name_prefix,
                                      GNUNET_PSYC_StateVarCallback var_cb,
                                      GNUNET_ResultCallback result_cb,
                                      void *cls);

/**
 * Cancel a state request operation.
 *
 * @param sr
 *        Handle for the operation to cancel.
 */
void
GNUNET_PSYC_channel_state_get_cancel (struct GNUNET_PSYC_StateRequest *sr);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYC_SERVICE_H */
#endif

/** @} */  /* end of group */
