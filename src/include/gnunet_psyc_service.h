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
 * @brief psyc service; high-level access to the PSYC protocol
 *        note that clients of this API are NOT expected to
 *        understand the PSYC message format, only the semantics!
 * @author Christian Grothoff
 *
 * TODO:
 * - how to deal with very large channel state (i.e. channel
 *   containing a movie); this might relate to the question
 *   of how (when/etc.) we replay method calls; is only the
 *   channel state persistent? What about a 'bounded' 
 *   channel history, how would we enable that?
 * - how to deal with seeking in large channel state (i.e. 
 *   skip to minute 45 in movie)
 * - need to change send operations to 'notify_transmit_ready'-style;
 *   deal better with 'streaming' arguments while we're at it
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
 * Bits describing special properties of arguments.
 */
enum GNUNET_PSYC_ArgumentFlags
{
  /**
   * Argument is fixed size.
   */
  GNUNET_PSYC_AF_FIXED_SIZE = 0,

  /**
   * Argument is variable-length
   */
  GNUNET_PSYC_AF_VARIABLE_SIZE = 1,

  /**
   * Argument may be supplied incrementally to the callback 
   */
  GNUNET_PSYC_AF_STREAMABLE = 2,

  /**
   * Argument is variable-length, incrementally supplied
   * data stream.
   */
  GNUNET_PSYC_AF_STREAM = 3,

  /**
   * Argument is zero-terminated character array.
   */
  GNUNET_PSYC_AF_ZERO_TERMINATED_CHARARRAY = 4,

  /**
   * Argument is variable-length UTF-8 encoded, zero-terminated string.
   */
  GNUNET_PSYC_AF_UTF8 = 5,

  /**
   * Payload is an unsigned integer and might thus be encoded as an
   * integer when generating PSYC stream (useful if we want to
   * generate human-readable PSYC streams, instead of just always
   * using length-prefixed binary encodings).  Note that it
   * is not sufficient to just test for this bit, as it is
   * also set for 'REAL' numbers!
   */
  GNUNET_PSYC_AF_UNSIGNED_INTEGER = 8,

  /**
   * Payload is an unsigned integer and might thus be encoded as an
   * integer when generating PSYC stream (useful if we want to
   * generate human-readable PSYC streams, instead of just always
   * using length-prefixed binary encodings).  Note that it
   * is not sufficient to just test for this bit, as it is
   * also set for 'REAL' numbers!
   */
  GNUNET_PSYC_AF_SIGNED_INTEGER = 16,

  /**
   * Payload is a 'real' number (float or double).  We save a bit here
   * as a number cannot be both SIGNED and UNSIGNED, so setting both
   * bits is fine to use for REALs.
   */
  GNUNET_PSYC_AF_REAL_NUMBER = 24

};


/**
 * Argument descriptors are used to describe types that can be
 * embedded in a PSYC stream.  For example, a "uint32_t" is 
 * described as 4-byte, fixed-length data, whereas a movie 
 * would be a variable-size, streaming argument.
 */
struct GNUNET_PSYC_ArgumentDescriptor
{

  /**
   * Required length of the argument in bytes, zero for
   * variable-size arguments.
   */
  size_t arg_len;

  /**
   * Flags describing additional properties of the argument,
   * such as variable-size, streaming or 0-termination.  This
   * argument is a bitfield.
   */
  enum GNUNET_PSYC_ArgumentFlags flags;

};


/**
 * Convenience macro to define an argument descriptor for
 * some fixed-size C data type.
 *
 * @param pt C data type (i.e. 'uint32_t')
 */
#define GNUNET_PSYC_AD_C_TYPE(pt) { sizeof (pt), GNUNET_PSYC_AF_FIXED_SIZE }

/**
 * Convenience macro to define an argument descriptor for
 * some fixed-size unsigned integer type.
 *
 * @param it C integer data type (i.e. 'uint32_t')
 */
#define GNUNET_PSYC_AD_C_UINT_TYPE(it) { sizeof (it), GNUNET_PSYC_AF_FIXED_SIZE | GNUNET_PSYC_AF_UNSIGNED_INTEGER }

/**
 * Argument descriptor for a 'uint8_t' argument.
 */
#define GNUNET_PSYC_AD_UINT8 GNUNET_PSYC_AD_C_UINT_TYPE(uint8_t)

/**
 * Argument descriptor for a 'uint16_t' argument.
 */
#define GNUNET_PSYC_AD_UINT16 GNUNET_PSYC_AD_C_UINT_TYPE(uint16_t)

/**
 * Argument descriptor for a 'uint32_t' argument.
 */
#define GNUNET_PSYC_AD_UINT32 GNUNET_PSYC_AD_C_UINT_TYPE(uint32_t)

/**
 * Argument descriptor for a 'uint64_t' argument.
 */
#define GNUNET_PSYC_AD_UINT64 GNUNET_PSYC_AD_C_UINT_TYPE(uint64_t)

/**
 * Convenience macro to define an argument descriptor for
 * a 0-terminated, variable-length UTF-8 string.
 */
#define GNUNET_PSYC_AD_UTF8 { 0, GNUNET_PSYC_AF_UTF8 }


/* TODO: add more convenience macros for argument types later as needed */


/**
 * Abstract argument passed to a GNUNET_PSYC_Method.  
 */
struct GNUNET_PSYC_Argument
{

  /**
   * Data of the argument.
   */
  const void *data;

  /**
   * Number of bytes in 'data', guaranteed to be the argument
   * descriptor 'arg_len' MINUS 'data_off' unless
   * GNUNET_PSYC_AF_VARIABLE_SIZE was set.
   */
  size_t data_size;

  /**
   * Offset of 'data' in the overall argument,
   * always zero unless GNUNET_PSYC_AF_STREAMABLE was
   * set for the argument.
   */
  uint64_t data_off;

  /**
   * Total number of bytes to be expected in 'data',
   * UINT64_MAX for 'unknown' (i.e. for "infinite" 
   * streams).
   */
  uint64_t value_size;
};


/**
 * Method called from PSYC upon receiving a message indicating a call
 * to a 'method'.  The arguments given will match those of the
 * respective argument descriptor.  If some arguments were marked
 * as 'streaming', the function can return a value other than -1
 * to request "more" of the data for that argument.  Note that all
 * non-streaming arguments will be replayed in full for each additional
 * invocation of the method.  Using more than one streaming argument 
 * is possible, in which case PSYC will ONLY advance the stream of the
 * argument for which the index was returned; the values of other
 * streaming arguments will be replayed at the current offset.
 *
 * Returning a value other than -1 or that of a streaming argument is
 * not allowed.  Returning -1 does not indicate an error; it simply
 * indicates that the client wants to proceed with the next method
 * (and not see the rest of the data from any of the streaming
 * arguments).
 *
 * TODO: note that this API currently doesn't allow for seeking
 *       in streaming data (very advanced feature)
 *
 * @param cls closure
 * @param full_method_name original method name from PSYC (may be more
 *        specific than the registered method name due to try&slice matching)
 * @param sender who transmitted the message (origin, except for messages
 *        from one of the members to the origin)
 * @param message_id unique message counter for this message
 * @param group_generation group generation counter for this message
 * @param argc number of arguments in argv
 * @param argv array of argc arguments to the method
 * @return -1 if we're finished with this method, index
 *            of a streaming argument for which more data is
 *            requested otherwise
 */
typedef int (*GNUNET_PSYC_Method)(void *cls,
				  const char *full_method_name,
				  const struct GNUNET_PeerIdentity *sender,
				  unsigned int argc,
				  const struct GNUNET_PSYC_Argument *argv);


/**
 * Descriptor for a PSYC method and its arguments.  Here is how this
 * is expected to be used.  Imagine we have a method with the
 * following signature:
 * <pre>
 * static void 
 * logger (void *cls, uint32_t log_level, const char *log_message);
 * </pre>
 * where 'cls' is supposed to be a 'FILE *'.
 * Then for PSYC to call this method with 'stderr' for 'cls',
 * we would provide the following method descriptor:
 * <pre>
 * .method_name = "log";
 * .method = wrap_logger;
 * .method_cls = stderr;
 * .argc = 2;
 * .argv = { GNUNET_PSYC_AD_UINT32, GNUNET_PSYC_AD_UTF8 };
 * </pre>
 * and define <tt>wrap_logger</tt> as follows:
 * <pre>
 * static void
 * wrap_logger (void *cls, const char full_method_name, 
 *              const struct GNUNET_PeerIdentity *sender,
 *    	        unsigned int argc, const struct GNUNET_PSYC_Argument *argv)
 * {
 *    uint32_t *log_level = argv[0].data;
 *    const char *log_message = argv[1].data;
 *    logger (cls, *log_level, log_message);
 * }
 * </pre> 
 * Note that the PSYC library will take care of making sure
 * that 'argv[0].data_size == 4' and that the log message
 * is 0-terminated, as those requirements were specified
 * in the method descriptor for those arguments.  Finally,
 * it is conceivable to generate the wrappers and method
 * descriptors automatically, as they are trivial.
 * <p>
 * Note that due to try & slice, the given full method name
 * might be more specific; for example, the given method
 * might be called for a request to "log_warning" instead
 * of just a request to "log".
 */
struct GNUNET_PSYC_MethodDescriptor
{

  /**
   * Name of the method to be used in try-and-slice matching.
   */
  const char *method_name;

  /**
   * Function to call.  Note that if a more specific handler exists
   * as well, the more generic handler will not be invoked.
   */
  GNUNET_PSYC_Method method;

  /**
   * Closure for the method (this argument and the 'sender' argument
   * are both not included in 'argc').
   */
  void *method_cls;

  /**
   * Number of arguments to pass to the method (length of the 'ads'
   * array).
   */
  unsigned int argc;

  /**
   * Array of 'argc' argument descriptors describing the arguments to
   * be passed to the method.  Non-matching method calls will be
   * ignored (but logged).  Note that the 'ads' of all methods with
   * the same method name prefix should be identical.
   */
  const struct GNUNET_PSYC_ArgumentDescriptor *ads;

};


/**
 * Handle for the origin of a psyc group.
 */
struct GNUNET_PSYC_Origin;


/**
 * Start a psyc group.  Will create a multicast group identified by
 * the given public key.  Messages recevied from group members will be
 * given to the respective handler methods.  If a new member wants to
 * join a group, the "join" method handler will be invoked; the join
 * handler must then generate a "join" message to approve the joining
 * of the new member.  The origin can also change group membership
 * without explicit requests.  Note that PSYC doesn't itself "understand"
 * join or leave messages, the respective methods must call other
 * PSYC functions to inform PSYC about the meaning of the respective
 * events.
 *
 * @param cfg configuration to use (to connect to PSYC service)
 * @param method_count number of methods in 'methods' array
 * @param methods functions to invoke on messages received from members,
 *                typcially at least contains functions for 'join' and 'leave'.
 * @param priv_key ECC key that will be used to sign messages for this
 *                 psyc session; public key is used to identify the
 *                 psyc group; FIXME: we'll likely want to use
 *                 NOT the p521 curve here, but a cheaper one in the future
 * @param join_policy what is the membership policy of the group?
 * @return handle for the origin, NULL on error 
 */
struct GNUNET_PSYC_Origin *
GNUNET_PSYC_origin_start (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			  unsigned int method_count,
			  const struct GNUNET_PSYC_MethodDescriptor *methods,
			  const struct GNUNET_CRYPTO_EccPrivateKey *priv_key,
			  enum GNUNET_MULTICAST_JoinPolicy join_policy);


/**
 * Update channel state.  The state of a channel must fit into the
 * memory of each member (and the origin); large values that require
 * streaming must only be passed as streaming arguments to methods.
 * State updates might not be transmitted to group members until
 * the next call to 'GNUNET_PSYC_origin_broadcast_call_method'.
 *
 * @param origin handle to the psyc group / channel
 * @param full_state_name name of the field in the channel state to change
 * @param data_size number of bytes in data
 * @param data new state value
 */
void
GNUNET_PSYC_origin_update_state (struct GNUNET_PSYC_Origin *origin,
				 const char *full_state_name,
				 size_t data_size,
				 const void *data);


/**
 * Data needed to construct a PSYC message to call a method.
 */
struct GNUNET_PSYC_CallData
{

  /**
   * Name of the function to call.  This name may be more specific
   * than the registered method name due to try&slice matching.
   */
  const char *full_method_name;

  /**
   * Number of arguments to pass (other than closure and sender),
   * length of the 'argv' array.
   */
  unsigned int argc;

  /**
   * Arguments to pass to the function.
   */
  const struct GNUNET_PSYC_Argument *argv;

};


/**
 * Send a message to call a method to all members in the psyc group.
 *
 * @param origin handle to the psyc group
 * @param increment_group_generation GNUNET_YES if we need to increment
 *        the group generation counter after transmitting this message
 * @param call_data data needed to determine how to call which method 
 * @param message_id set to the unique message ID that was generated for
 *        this message
 * @param group_generation set to the group generation used for this
 *        message
 * FIXME: change to notify_transmit_ready-style to wait for ACKs?
 *        that'd also help with streaming arguments!
 *        => need to change multicast API first as well!
 */
void
GNUNET_PSYC_origin_broadcast_call_method (struct GNUNET_PSYC_Origin *origin,
					  int increment_group_generation,
					  const struct GNUNET_PSYC_CallData *call_data,
					  uint64_t *message_id,
					  uint64_t *group_generation);


/**
 * End a psyc group.
 *
 * @param origin psyc group to terminate
 */
void
GNUNET_PSYC_origin_end (struct GNUNET_PSYC_Origin *origin);


/**
 * Handle to access PSYC group operations for all members.
 */
struct GNUNET_PSYC_Group;


/**
 * Convert 'origin' to a 'group' handle to access the 'group' APIs.
 * 
 * @param origin origin handle
 * @return group handle, valid for as long as 'origin' is valid
 */ 
struct GNUNET_PSYC_Group *
GNUNET_PSYC_origin_get_group (struct GNUNET_PSYC_Origin *origin);


/**
 * Add a member to the group.    Note that this will NOT generate any
 * PSYC traffic, it will merely update the local data base to modify
 * how we react to 'membership test' queries.  The origin still needs to
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
 * @param member which peer to add
 * @param message_id message ID for the message that changed the membership
 * @param group_generation the generation ID where the change went into effect
 */
void
GNUNET_PSYC_group_member_admit (struct GNUNET_PSYC_Group *group,
				const struct GNUNET_PeerIdentity *member,
				uint64_t message_id,
				uint64_t group_generation);


/**
 * Remove a member from the group.  Note that this will NOT generate any
 * PSYC traffic, it will merely update the local data base to modify
 * how we react to 'membership test' queries.  The origin still needs to
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
GNUNET_PSYC_group_member_kick (struct GNUNET_PSYC_Group *group,
			       const struct GNUNET_PeerIdentity *member,
			       uint64_t message_id,
			       uint64_t group_generation);


/**
 * Function called to inform a member about state values for a channel.
 *
 * @param cls closure
 * @param full_state_name full name of the state
 * @param data_size number of bytes in 'data'
 * @param data raw data of the state
 */
typedef void (*GNUNET_PSYC_StateCallback)(void *cls,
					  const char *full_state_name,
					  size_t data_size,
					  const void *data);


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

  /**
   * Description of the kind of state that the handler expects to see.
   * Non-matching state updates will be ignored (but logged).  Note
   * that the state_types of all states with the same state name prefix
   * should be identical.
   */
  struct GNUNET_PSYC_ArgumentDescriptor state_type;

};


/**
 * Join a psyc group.  The entity joining is always the local peer.
 * This will send a 'join_msg' to the origin; if it succeeds, the
 * channel state will be replayed to the joining member and the 'join'
 * method will be invoked to show that we joined successfully.  There
 * is no explicit notification on failure (as the origin may simply
 * take days to approve, and disapproval is simply being ignored).
 *
 * Note that we also specify the message to transmit to origin on
 * 'leave' here, as a sudden crash might otherwise not permit sending
 * a 'nice' leave message.   TODO: we might want an API to change
 * the 'leave' message later during the session.
 * 
 * @param cfg configuration to use
 * @param pub_key ECC key that identifies the group
 * @param method_count number of methods in 'methods' array
 * @param methods functions to invoke on messages received from the origin,
 *                typcially at least contains functions for 'join' and 'leave'.
 * @param state_count number of state handlers
 * @param state_handlers array of state event handlers
 * @param join_data method to invoke on origin to trigger joining;
 *        use NULL to send nothing (useful for anonymous groups that permit anyone);
          arguments to give to join method, must not include streaming args
 * @param leave_data method to invoke on origin on leaving;
 *        use NULL to send nothing (useful for anonymous groups that permit anyone);
          arguments to give to leave method, must not include streaming args
 * @return handle for the member, NULL on error 
 */
struct GNUNET_PSYC_Member *
GNUNET_PSYC_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			 const struct GNUNET_CRYPTO_EccPublicKey *pub_key,
			 unsigned int method_count,
			 const struct GNUNET_PSYC_MethodDescriptor *methods,
			 unsigned int state_count,
			 struct GNUNET_PSYC_StateHandler *state_handlers,
			 const struct GNUNET_PSYC_CallData *join_data,
			 const struct GNUNET_PSYC_CallData *leave_data);


/**
 * Request a message to be send to the origin.
 *
 * @param member membership handle
 * @param request_data which method should be invoked on origin (and how)
 *
 * FIXME: change to notify_transmit_ready-style to wait for ACKs
 * and to enable streaming arguments!
 */
void
GNUNET_PSYC_member_send_to_origin (struct GNUNET_PSYC_Member *member,
				   const struct GNUNET_PSYC_CallData *request_data);


/**
 * Call the given state callback on all matching states in the channel
 * state.  The callback is invoked synchronously on all matching
 * states (as the state is fully replicated in the library in this
 * process; channel states should be small, large data is to be passed
 * as streaming data to methods).
 *
 * @param member membership handle
 * @param state_name name of the state to query (full name 
 *        might be longer, this is only the prefix that must match)
 * @param cb function to call on the matching state values
 * @param cb_cls closure for 'cb'
 */
int
GNUNET_PSYC_member_state_get (struct GNUNET_PSYC_Member *member,
			      const char *state_name,
			      GNUNET_PSYC_StateCallback cb,
			      void *cb_cls);


/**
 * Leave a mutlicast group.  Will terminate the connection to the PSYC
 * service, which will send the 'leave' method that was prepared
 * earlier to the origin.  This function must not be called on a
 * 'member' that was obtained from GNUNET_PSYC_origin_get_group.
 *
 * @param member membership handle
 */
void
GNUNET_PSYC_member_leave (struct GNUNET_PSYC_Member *member);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PSYC_SERVICE_H */
#endif
/* end of gnunet_psyc_service.h */
