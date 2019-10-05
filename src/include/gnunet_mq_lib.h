/*
     This file is part of GNUnet.
     Copyright (C) 2012-2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Florian Dold
 * @author Christian Grothoff
 *
 * @file
 * General-purpose message queue
 *
 * @defgroup mq  MQ library
 * General-purpose message queue
 *
 * @see [Documentation](https://gnunet.org/message-queue-api)
 *
 * @{
 */
#ifndef GNUNET_MQ_LIB_H
#define GNUNET_MQ_LIB_H

#include "gnunet_scheduler_lib.h"

/**
 * Allocate an envelope, with extra space allocated after the space needed
 * by the message struct.
 * The allocated message will already have the type and size field set.
 *
 * @param mvar variable to store the allocated message in;
 *             must have a header field;
 *             can be NULL
 * @param esize extra space to allocate after the message
 * @param type type of the message
 * @return the MQ message
 */
#define GNUNET_MQ_msg_extra(mvar, esize, type)                \
  GNUNET_MQ_msg_ (((struct GNUNET_MessageHeader **) &(mvar)), \
                  (esize) + sizeof *(mvar),                   \
                  (type))

/**
 * Allocate a GNUNET_MQ_Envelope.
 * The contained message will already have the type and size field set.
 *
 * @param mvar variable to store the allocated message in;
 *             must have a header field;
 *             can be NULL
 * @param type type of the message
 * @return the allocated envelope
 */
#define GNUNET_MQ_msg(mvar, type) GNUNET_MQ_msg_extra (mvar, 0, type)


/**
 * Allocate a GNUNET_MQ_Envelope, where the message only consists of a header.
 * The allocated message will already have the type and size field set.
 *
 * @param type type of the message
 */
#define GNUNET_MQ_msg_header(type) \
  GNUNET_MQ_msg_ (NULL, sizeof(struct GNUNET_MessageHeader), type)


/**
 * Allocate a GNUNET_MQ_Envelope, where the message only consists of a header and extra space.
 * The allocated message will already have the type and size field set.
 *
 * @param mh pointer that will changed to point at to the allocated message header
 * @param esize extra space to allocate after the message header
 * @param type type of the message
 */
#define GNUNET_MQ_msg_header_extra(mh, esize, type) \
  GNUNET_MQ_msg_ (&mh, (esize) + sizeof(struct GNUNET_MessageHeader), type)


/**
 * Allocate a GNUNET_MQ_Envelope, and append a payload message after the given
 * message struct.
 *
 * @param mvar pointer to a message struct, will be changed to point at the newly allocated message,
 *        whose size is 'sizeof(*mvar) + ntohs (mh->size)'
 * @param type message type of the allocated message, has no effect on the nested message
 * @param mh message to nest
 * @return a newly allocated 'struct GNUNET_MQ_Envelope *'
 */
#define GNUNET_MQ_msg_nested_mh(mvar, type, mh)                               \
  ({                                                                          \
    struct GNUNET_MQ_Envelope *_ev;                                           \
    _ev = GNUNET_MQ_msg_nested_mh_ ((struct GNUNET_MessageHeader **) &(mvar), \
                                    sizeof(*(mvar)),                         \
                                    (type),                                   \
                                    (mh));                                    \
    (void) (mvar)->header;  /* type check */                                   \
    _ev;                                                                      \
  })


/**
 * Return a pointer to the message at the end of the given message.
 *
 * @param var pointer to a message struct, the type of the expression determines the base size,
 *        the space after the base size is the nested message
 * @return a 'struct GNUNET_MessageHeader *' that points at the nested message of the given message,
 *         or NULL if the given message in @a var does not have any space after the message struct
 */
#define GNUNET_MQ_extract_nested_mh(var)                               \
  GNUNET_MQ_extract_nested_mh_ ((struct GNUNET_MessageHeader *) (var), \
                                sizeof(*(var)))


/**
 * Implementation of the #GNUNET_MQ_extract_nexted_mh macro.
 *
 * @param mh message header to extract nested message header from
 * @param base_size size of the message before the nested message's header appears
 * @return pointer to the nested message, does not copy the message
 *         OR NULL in case of a malformed message.
 */
const struct GNUNET_MessageHeader *
GNUNET_MQ_extract_nested_mh_ (const struct GNUNET_MessageHeader *mh,
                              uint16_t base_size);


/**
 * Opaque handle to an envelope.
 */
struct GNUNET_MQ_Envelope;


/**
 * Obtain message contained in envelope.
 *
 * @param env the envelope
 * @return message contained in the envelope
 */
const struct GNUNET_MessageHeader *
GNUNET_MQ_env_get_msg (const struct GNUNET_MQ_Envelope *env);


/**
 * Return next envelope in queue.
 *
 * @param env a queued envelope
 * @return next one, or NULL
 */
const struct GNUNET_MQ_Envelope *
GNUNET_MQ_env_next (const struct GNUNET_MQ_Envelope *env);


/**
 * Implementation of the #GNUNET_MQ_msg_nested_mh macro.
 *
 * @param mhp pointer to the message header pointer that will be changed to allocate at
 *        the newly allocated space for the message.
 * @param base_size size of the data before the nested message
 * @param type type of the message in the envelope
 * @param nested_mh the message to append to the message after base_size
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_nested_mh_ (struct GNUNET_MessageHeader **mhp,
                          uint16_t base_size,
                          uint16_t type,
                          const struct GNUNET_MessageHeader *nested_mh);


/**
 * Opaque handle to a message queue.
 */
struct GNUNET_MQ_Handle;


/**
 * Error codes for the queue.
 */
enum GNUNET_MQ_Error
{
  /**
   * Failed to read message from the network.
   * FIXME: Likely not properly distinguished
   * from TIMEOUT case in the code!
   */
  GNUNET_MQ_ERROR_READ = 1,

  /**
   * FIXME: document!
   */
  GNUNET_MQ_ERROR_WRITE = 2,

  /**
   * FIXME: document!
   */
  GNUNET_MQ_ERROR_TIMEOUT = 4,

  /**
   * We received a message that was malformed and thus
   * could not be passed to its handler.
   */
  GNUNET_MQ_ERROR_MALFORMED = 8,

  /**
   * We received a message for which we have no matching
   * handler.
   */
  GNUNET_MQ_ERROR_NO_MATCH = 16
};


/**
 * Per envelope preferences and priorities.
 */
enum GNUNET_MQ_PriorityPreferences
{
  /**
   * Lowest priority, i.e. background traffic (i.e. NSE, FS).
   * This is the default!
   */
  GNUNET_MQ_PRIO_BACKGROUND = 0,

  /**
   * Best-effort traffic (i.e. CADET relay, DHT)
   */
  GNUNET_MQ_PRIO_BEST_EFFORT = 1,

  /**
   * Urgent traffic (local peer, i.e. Conversation).
   */
  GNUNET_MQ_PRIO_URGENT = 2,

  /**
   * Highest priority, control traffic (i.e. CORE/CADET KX).
   */
  GNUNET_MQ_PRIO_CRITICAL_CONTROL = 3,

  /**
   * Bit mask to apply to extract the priority bits.
   */
  GNUNET_MQ_PRIORITY_MASK = 3,

  /**
   * Flag to indicate that unreliable delivery is acceptable.  This
   * means TRANSPORT will not attempt to receive an
   * acknowledgment. CORE will just pass this flag through.  CADET
   * will use unreliable delivery if this flag is set.
   *
   * Note that even without this flag, messages may be lost by
   * TRANSPORT and CORE.
   *
   * Thus, how "strong" the semantics of reliable delivery are depends
   * on the layer!
   */
  GNUNET_MQ_PREF_UNRELIABLE = 16,

  /**
   * Flag to indicate that low latency is important.  This flag must
   * generally not be used in combination with
   * #GNUNET_MQ_PREF_CORKING_ALLOWED as it would be a contradiction.
   * When this flags is set, the envelope may skip forward in the
   * queue (depending on priority) and also TRANSPORT should attempt
   * to pick a communicator with particularly low latency.
   */
  GNUNET_MQ_PREF_LOW_LATENCY = 32,

  /**
   * Flag to indicate that CORKing is acceptable. This allows the
   * receiver to delay transmission in hope of combining this message
   * with other messages into a larger transmission with less
   * per-message overhead.
   */
  GNUNET_MQ_PREF_CORK_ALLOWED = 64,

  /**
   * Flag to indicate that high bandwidth is desired. This flag
   * indicates that the method chosen for transmission should focus on
   * overall goodput.  It rarely makes sense to combine this flag with
   * #GNUNET_MQ_PREF_LOW_LATENCY.
   */
  GNUNET_MQ_PREF_GOODPUT = 128,

  /**
   * Flag to indicate that out-of-order delivery is OK.
   */
  GNUNET_MQ_PREF_OUT_OF_ORDER = 256,
};


/**
 * Called when a message has been received.
 *
 * @param cls closure
 * @param msg the received message
 */
typedef void (*GNUNET_MQ_MessageCallback) (
  void *cls,
  const struct GNUNET_MessageHeader *msg);


/**
 * Called when a message needs to be validated.
 *
 * @param cls closure
 * @param msg the received message
 * @return #GNUNET_OK if the message is well-formed,
 *         #GNUNET_SYSERR if not
 */
typedef int (*GNUNET_MQ_MessageValidationCallback) (
  void *cls,
  const struct GNUNET_MessageHeader *msg);


/**
 * Signature of functions implementing the
 * sending functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
typedef void (*GNUNET_MQ_SendImpl) (struct GNUNET_MQ_Handle *mq,
                                    const struct GNUNET_MessageHeader *msg,
                                    void *impl_state);


/**
 * Signature of functions implementing the
 * destruction of a message queue.
 * Implementations must not free @a mq, but should
 * take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
typedef void (*GNUNET_MQ_DestroyImpl) (struct GNUNET_MQ_Handle *mq,
                                       void *impl_state);


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
typedef void (*GNUNET_MQ_CancelImpl) (struct GNUNET_MQ_Handle *mq,
                                      void *impl_state);


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure
 * @param error error code
 */
typedef void (*GNUNET_MQ_ErrorHandler) (void *cls, enum GNUNET_MQ_Error error);


/**
 * Insert @a env into the envelope DLL starting at @a env_head
 * Note that @a env must not be in any MQ while this function
 * is used with DLLs defined outside of the MQ module.  This
 * is just in case some application needs to also manage a
 * FIFO of envelopes independent of MQ itself and wants to
 * re-use the pointers internal to @a env.  Use with caution.
 *
 * @param[in|out] env_head of envelope DLL
 * @param[in|out] env_tail tail of envelope DLL
 * @param[in|out] env element to insert at the tail
 */
void
GNUNET_MQ_dll_insert_head (struct GNUNET_MQ_Envelope **env_head,
                           struct GNUNET_MQ_Envelope **env_tail,
                           struct GNUNET_MQ_Envelope *env);


/**
 * Insert @a env into the envelope DLL starting at @a env_head
 * Note that @a env must not be in any MQ while this function
 * is used with DLLs defined outside of the MQ module.  This
 * is just in case some application needs to also manage a
 * FIFO of envelopes independent of MQ itself and wants to
 * re-use the pointers internal to @a env.  Use with caution.
 *
 * @param[in|out] env_head of envelope DLL
 * @param[in|out] env_tail tail of envelope DLL
 * @param[in|out] env element to insert at the tail
 */
void
GNUNET_MQ_dll_insert_tail (struct GNUNET_MQ_Envelope **env_head,
                           struct GNUNET_MQ_Envelope **env_tail,
                           struct GNUNET_MQ_Envelope *env);


/**
 * Remove @a env from the envelope DLL starting at @a env_head.
 * Note that @a env must not be in any MQ while this function
 * is used with DLLs defined outside of the MQ module. This
 * is just in case some application needs to also manage a
 * FIFO of envelopes independent of MQ itself and wants to
 * re-use the pointers internal to @a env.  Use with caution.
 *
 * @param[in|out] env_head of envelope DLL
 * @param[in|out] env_tail tail of envelope DLL
 * @param[in|out] env element to remove from the DLL
 */
void
GNUNET_MQ_dll_remove (struct GNUNET_MQ_Envelope **env_head,
                      struct GNUNET_MQ_Envelope **env_tail,
                      struct GNUNET_MQ_Envelope *env);


/**
 * Copy an array of handlers.
 *
 * Useful if the array has been delared in local memory and needs to be
 * persisted for future use.
 *
 * @param handlers Array of handlers to be copied.
 * @return A newly allocated array of handlers.
 *         Needs to be freed with #GNUNET_free.
 */
struct GNUNET_MQ_MessageHandler *
GNUNET_MQ_copy_handlers (const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Copy an array of handlers, appending AGPL handler.
 *
 * Useful if the array has been delared in local memory and needs to be
 * persisted for future use.
 *
 * @param handlers Array of handlers to be copied. Can be NULL (nothing done).
 * @param agpl_handler function to call for AGPL handling
 * @param agpl_cls closure for @a agpl_handler
 * @return A newly allocated array of handlers.
 *         Needs to be freed with #GNUNET_free.
 */
struct GNUNET_MQ_MessageHandler *
GNUNET_MQ_copy_handlers2 (const struct GNUNET_MQ_MessageHandler *handlers,
                          GNUNET_MQ_MessageCallback agpl_handler,
                          void *agpl_cls);


/**
 * Count the handlers in a handler array.
 *
 * @param handlers Array of handlers to be counted.
 * @return The number of handlers in the array.
 */
unsigned int
GNUNET_MQ_count_handlers (const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Message handler for a specific message type.
 */
struct GNUNET_MQ_MessageHandler
{
  /**
   * Callback to validate a message of the specified @e type.
   * The closure given to @e mv will be this struct (not @e ctx).
   * Using NULL means only size-validation using
   * @e expected_size.  In this case, @e expected_size must
   * be non-zero.
   */
  GNUNET_MQ_MessageValidationCallback mv;

  /**
   * Callback, called every time a new message of
   * the specified @e type has been receied.
   * The closure given to @e mv will be this struct (not @e ctx).
   */
  GNUNET_MQ_MessageCallback cb;

  /**
   * Closure for @e mv and @e cb.
   */
  void *cls;

  /**
   * Type of the message this handler covers, in host byte order.
   */
  uint16_t type;

  /**
   * Expected size of messages of this type.  Minimum size of the
   * message if @e mv is non-NULL.  Messages of the given type will be
   * discarded (and the connection closed with an error reported to
   * the application) if they do not have the right size.
   */
  uint16_t expected_size;
};


/**
 * End-marker for the handlers array
 */
#define GNUNET_MQ_handler_end() \
  {                             \
    NULL, NULL, NULL, 0, 0      \
  }


/**
 * Defines a static function @a name which takes as a single argument
 * a message handler for fixed-sized messages of type @a code and with
 * a message type argument of @a str.  Given such an argument, the
 * function @name will return a `struct GNUNET_MQ_MessageHandler`
 * for the given message type.
 *
 * The macro is to be used as follows:
 * <code>
 * struct GNUNET_MessageTest { ... }; // must be fixed size
 * static void
 * handle_test_message (void *cls,
 *                      const struct GNUNET_MessageTest *msg)
 * { ... }
 *
 * struct GNUNET_MQ_MessageHandler handlers[] = {
 *   GNUNET_MQ_hd_fixed_size(test_message,
 *                           GNUNET_MESSAGE_TYPE_TEST,
 *                           struct GNUNET_MessageTest,
 *                           "context"),
 *   GNUNET_MQ_handler_end()
 * };
 *
 * @param name unique basename for the functions
 * @param code message type constant
 * @param str type of the message (a struct)
 * @param ctx context for the callbacks
 */
#define GNUNET_MQ_hd_fixed_size(name, code, str, ctx)                   \
  ({                                                                    \
    void (*_cb)(void *cls, const str *msg) = &handle_ ## name;           \
    ((struct GNUNET_MQ_MessageHandler){ NULL,                            \
                                        (GNUNET_MQ_MessageCallback) _cb, \
                                        (ctx),                           \
                                        (code),                          \
                                        sizeof(str) });                  \
  })


/**
 * Defines a static function @a name which takes two arguments and a
 * context-pointer for validating and handling variable-sized messages
 * of type @a code and with a message type argument of @a str.  Given
 * such arguments, the function @name will return a `struct
 * GNUNET_MQ_MessageHandler` for the given message type.
 *
 * The macro is to be used as follows:
 * <code>
 * struct GNUNET_MessageTest { ... }; // can be variable size
 * static int
 * check_test (void *cls,
 *             const struct GNUNET_MessageTest *msg)
 * {
 *   const char *ctx = cls;
 *   GNUNET_assert (0 == strcmp ("context", ctx));
 *   // ...
 * }
 * static void
 * handle_test (void *cls,
 *              const struct GNUNET_MessageTest *msg)
 * {
 *   const char *ctx = cls;
 *   GNUNET_assert (0 == strcmp ("context", ctx));
 *   // ...
 * }
 *
 * struct GNUNET_MQ_MessageHandler handlers[] = {
 *   GNUNET_MQ_hd_var_size(test_message,
 *                         GNUNET_MESSAGE_TYPE_TEST,
 *                         struct GNUNET_MessageTest,
 *                         "context"),
 *   GNUNET_MQ_handler_end()
 * };
 *
 * @param name unique basename for the functions
 * @param code message type constant
 * @param str type of the message (a struct)
 * @param ctx context for the callbacks
 */
#define GNUNET_MQ_hd_var_size(name, code, str, ctx)                          \
  __extension__ ({                                                            \
    int (*_mv)(void *cls, const str *msg) = &check_ ## name;                  \
    void (*_cb)(void *cls, const str *msg) = &handle_ ## name;                \
    ((struct GNUNET_MQ_MessageHandler){ (GNUNET_MQ_MessageValidationCallback) \
                                        _mv,                                \
                                        (GNUNET_MQ_MessageCallback) _cb,      \
                                        (ctx),                                \
                                        (code),                               \
                                        sizeof(str) });                       \
  })


/**
 * Insert code for a "check_" function that verifies that
 * a given variable-length message received over the network
 * is followed by a 0-terminated string.  If the message @a m
 * is not followed by a 0-terminated string, an error is logged
 * and the function is returned with #GNUNET_NO.
 *
 * @param an IPC message with proper type to determine
 *  the size, starting with a `struct GNUNET_MessageHeader`
 */
#define GNUNET_MQ_check_zero_termination(m)                       \
  {                                                               \
    const char *str = (const char *) &m[1];                       \
    const struct GNUNET_MessageHeader *hdr =                      \
      (const struct GNUNET_MessageHeader *) m;                    \
    uint16_t slen = ntohs (hdr->size) - sizeof(*m);              \
    if ((0 == slen) || (memchr (str, 0, slen) != &str[slen - 1])) \
    {                                                             \
      GNUNET_break (0);                                           \
      return GNUNET_NO;                                           \
    }                                                             \
  }


/**
 * Insert code for a "check_" function that verifies that
 * a given variable-length message received over the network
 * is followed by another variable-length message that fits
 * exactly with the given size.  If the message @a m
 * is not followed by another `struct GNUNET_MessageHeader`
 * with a size that adds up to the total size, an error is logged
 * and the function is returned with #GNUNET_NO.
 *
 * @param an IPC message with proper type to determine
 *  the size, starting with a `struct GNUNET_MessageHeader`
 */
#define GNUNET_MQ_check_boxed_message(m)                 \
  {                                                      \
    const struct GNUNET_MessageHeader *inbox =           \
      (const struct GNUNET_MessageHeader *) &m[1];       \
    const struct GNUNET_MessageHeader *hdr =             \
      (const struct GNUNET_MessageHeader *) m;           \
    uint16_t slen = ntohs (hdr->size) - sizeof(*m);     \
    if ((slen < sizeof(struct GNUNET_MessageHeader)) || \
        (slen != ntohs (inbox->size)))                   \
    {                                                    \
      GNUNET_break (0);                                  \
      return GNUNET_NO;                                  \
    }                                                    \
  }


/**
 * Call the message message handler that was registered
 * for the type of the given message in the given @a handlers list.
 *
 * This function is indended to be used for the implementation
 * of message queues.
 *
 * @param handlers a set of handlers
 * @param mh message to dispatch
 * @return #GNUNET_OK on success, #GNUNET_NO if no handler matched,
 *         #GNUNET_SYSERR if message was rejected by check function
 */
int
GNUNET_MQ_handle_message (const struct GNUNET_MQ_MessageHandler *handlers,
                          const struct GNUNET_MessageHeader *mh);


/**
 * Create a new envelope.
 *
 * @param mhp message header to store the allocated message header in, can be NULL
 * @param size size of the message to allocate
 * @param type type of the message, will be set in the allocated message
 * @return the allocated MQ message
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp,
                uint16_t size,
                uint16_t type);


/**
 * Create a new envelope by copying an existing message.
 *
 * @param hdr header of the message to copy
 * @return envelope containing @a hdr
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_copy (const struct GNUNET_MessageHeader *hdr);


/**
 * Discard the message queue message, free all
 * allocated resources. Must be called in the event
 * that a message is created but should not actually be sent.
 *
 * @param mqm the message to discard
 */
void
GNUNET_MQ_discard (struct GNUNET_MQ_Envelope *mqm);


/**
 * Function to obtain the current envelope
 * from within #GNUNET_MQ_SendImpl implementations.
 *
 * @param mq message queue to interrogate
 * @return the current envelope
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_get_current_envelope (struct GNUNET_MQ_Handle *mq);


/**
 * Function to copy an envelope.  The envelope must not yet
 * be in any queue or have any options or callbacks set.
 *
 * @param env envelope to copy
 * @return copy of @a env
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_env_copy (struct GNUNET_MQ_Envelope *env);


/**
 * Function to obtain the last envelope in the queue.
 *
 * @param mq message queue to interrogate
 * @return the last envelope in the queue
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_get_last_envelope (struct GNUNET_MQ_Handle *mq);


/**
 * Set application-specific options for this envelope.
 * Overrides the options set for the queue with
 * #GNUNET_MQ_set_options() for this message only.
 *
 * @param env message to set options for
 * @param pp priority and preferences to set for @a env
 */
void
GNUNET_MQ_env_set_options (struct GNUNET_MQ_Envelope *env,
                           enum GNUNET_MQ_PriorityPreferences pp);


/**
 * Get performance preferences set for this envelope.
 *
 * @param env message to set options for
 * @return priority and preferences to use
 */
enum GNUNET_MQ_PriorityPreferences
GNUNET_MQ_env_get_options (struct GNUNET_MQ_Envelope *env);


/**
 * Combine performance preferences set for different
 * envelopes that are being combined into one larger envelope.
 *
 * @param p1 one set of preferences
 * @param p2 second set of preferences
 * @return combined priority and preferences to use
 */
enum GNUNET_MQ_PriorityPreferences
GNUNET_MQ_env_combine_options (enum GNUNET_MQ_PriorityPreferences p1,
                               enum GNUNET_MQ_PriorityPreferences p2);


/**
 * Remove the first envelope that has not yet been sent from the message
 * queue and return it.
 *
 * @param mq queue to remove envelope from
 * @return NULL if queue is empty (or has no envelope that is not under transmission)
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_unsent_head (struct GNUNET_MQ_Handle *mq);


/**
 * Set application-specific options for this queue.
 *
 * @param mq message queue to set options for
 * @param pp priority and preferences to use by default
 */
void
GNUNET_MQ_set_options (struct GNUNET_MQ_Handle *mq,
                       enum GNUNET_MQ_PriorityPreferences pp);


/**
 * Obtain the current length of the message queue.
 *
 * @param mq queue to inspect
 * @return number of queued, non-transmitted messages
 */
unsigned int
GNUNET_MQ_get_length (struct GNUNET_MQ_Handle *mq);


/**
 * Send a message with the given message queue.
 * May only be called once per message.
 *
 * @param mq message queue
 * @param ev the envelope with the message to send.
 */
void
GNUNET_MQ_send (struct GNUNET_MQ_Handle *mq, struct GNUNET_MQ_Envelope *ev);


/**
 * Send a copy of a message with the given message queue.
 * Can be called repeatedly on the same envelope.
 *
 * @param mq message queue
 * @param ev the envelope with the message to send.
 */
void
GNUNET_MQ_send_copy (struct GNUNET_MQ_Handle *mq,
                     const struct GNUNET_MQ_Envelope *ev);


/**
 * Cancel sending the message. Message must have been sent with
 * #GNUNET_MQ_send before.  May not be called after the notify sent
 * callback has been called
 *
 * @param ev queued envelope to cancel
 */
void
GNUNET_MQ_send_cancel (struct GNUNET_MQ_Envelope *ev);


/**
 * Associate the assoc_data in @a mq with a unique request id.
 *
 * @param mq message queue, id will be unique for the queue
 * @param assoc_data to associate
 */
uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_Handle *mq, void *assoc_data);


/**
 * Get the data associated with a @a request_id in a queue
 *
 * @param mq the message queue with the association
 * @param request_id the request id we are interested in
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_Handle *mq, uint32_t request_id);


/**
 * Remove the association for a @a request_id
 *
 * @param mq the message queue with the association
 * @param request_id the request id we want to remove
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_Handle *mq, uint32_t request_id);


/**
 * Create a message queue for the specified handlers.
 *
 * @param send function the implements sending messages
 * @param destroy function that implements destroying the queue
 * @param cancel function that implements canceling a message
 * @param impl_state for the queue, passed to @a send, @a destroy and @a cancel
 * @param handlers array of message handlers
 * @param error_handler handler for read and write errors
 * @param cls closure for message handlers and error handler
 * @return a new message queue
 */
struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_callbacks (GNUNET_MQ_SendImpl send,
                               GNUNET_MQ_DestroyImpl destroy,
                               GNUNET_MQ_CancelImpl cancel,
                               void *impl_state,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               GNUNET_MQ_ErrorHandler error_handler,
                               void *cls);


/**
 * Change the closure argument in all of the `handlers` of the
 * @a mq.
 *
 * @param mq to modify
 * @param handlers_cls new closure to use
 */
void
GNUNET_MQ_set_handlers_closure (struct GNUNET_MQ_Handle *mq,
                                void *handlers_cls);


/**
 * Call a callback once the envelope has been sent, that is,
 * sending it can not be canceled anymore.
 * There can be only one notify sent callback per envelope.
 *
 * @param ev message to call the notify callback for
 * @param cb the notify callback
 * @param cb_cls closure for the callback
 */
void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Envelope *ev,
                       GNUNET_SCHEDULER_TaskCallback cb,
                       void *cb_cls);


/**
 * Destroy the message queue.
 *
 * @param mq message queue to destroy
 */
void
GNUNET_MQ_destroy (struct GNUNET_MQ_Handle *mq);


/**
 * Handle we return for callbacks registered to be
 * notified when #GNUNET_MQ_destroy() is called on a queue.
 */
struct GNUNET_MQ_DestroyNotificationHandle;


/**
 * Register function to be called whenever @a mq is being
 * destroyed.
 *
 * @param mq message queue to watch
 * @param cb function to call on @a mq destruction
 * @param cb_cls closure for @a cb
 * @return handle for #GNUNET_MQ_destroy_notify_cancel().
 */
struct GNUNET_MQ_DestroyNotificationHandle *
GNUNET_MQ_destroy_notify (struct GNUNET_MQ_Handle *mq,
                          GNUNET_SCHEDULER_TaskCallback cb,
                          void *cb_cls);

/**
 * Cancel registration from #GNUNET_MQ_destroy_notify().
 *
 * @param dnh handle for registration to cancel
 */
void
GNUNET_MQ_destroy_notify_cancel (
  struct GNUNET_MQ_DestroyNotificationHandle *dnh);


/**
 * Call the message message handler that was registered
 * for the type of the given message in the given message queue.
 *
 * This function is indended to be used for the implementation
 * of message queues.
 *
 * @param mq message queue with the handlers
 * @param mh message to dispatch
 */
void
GNUNET_MQ_inject_message (struct GNUNET_MQ_Handle *mq,
                          const struct GNUNET_MessageHeader *mh);


/**
 * Call the error handler of a message queue with the given
 * error code.  If there is no error handler, log a warning.
 *
 * This function is intended to be used for the implementation
 * of message queues.
 *
 * @param mq message queue
 * @param error the error type
 */
void
GNUNET_MQ_inject_error (struct GNUNET_MQ_Handle *mq,
                        enum GNUNET_MQ_Error error);


/**
 * Call the send implementation for the next queued message, if any.
 * Calls the send notification for the current message unless
 * #GNUNET_MQ_impl_send_in_flight was called for this envelope.
 *
 * Only useful for implementing message queues, results in undefined
 * behavior if not used carefully.
 *
 * @param mq message queue to send the next message with
 */
void
GNUNET_MQ_impl_send_continue (struct GNUNET_MQ_Handle *mq);


/**
 * Call the send notification for the current message, but do not
 * try to send the next message until #gnunet_mq_impl_send_continue
 * is called.
 *
 * Only useful for implementing message queues, results in undefined
 * behavior if not used carefully.
 *
 * @param mq message queue to send the next message with
 */
void
GNUNET_MQ_impl_send_in_flight (struct GNUNET_MQ_Handle *mq);


/**
 * Get the implementation state associated with the
 * message queue.
 *
 * While the GNUNET_MQ_Impl* callbacks receive the
 * implementation state, continuations that are scheduled
 * by the implementation function often only have one closure
 * argument, with this function it is possible to get at the
 * implementation state when only passing the `struct GNUNET_MQ_Handle`
 * as closure.
 *
 * @param mq message queue with the current message
 * @return message to send, never NULL
 */
void *
GNUNET_MQ_impl_state (struct GNUNET_MQ_Handle *mq);


/**
 * Get the message that should currently be sent.
 * Fails if there is no current message.
 * Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param mq message queue with the current message
 * @return message to send, never NULL
 */
const struct GNUNET_MessageHeader *
GNUNET_MQ_impl_current (struct GNUNET_MQ_Handle *mq);


/**
 * Enum defining all known preference categories.
 *
 * @deprecated will be replaced by `enum GNUNET_MQ_PriorityPreference`
 */
enum GNUNET_MQ_PreferenceKind
{
  /**
   * No preference was expressed.
   */
  GNUNET_MQ_PREFERENCE_NONE = 0,

  /**
   * The preferred transmission for this envelope focuses on
   * maximizing bandwidth.
   */
  GNUNET_MQ_PREFERENCE_BANDWIDTH = 1,

  /**
   * The preferred transmission for this envelope foces on
   * minimizing latency.
   */
  GNUNET_MQ_PREFERENCE_LATENCY = 2,

  /**
   * The preferred transmission for this envelope foces on
   * reliability.
   */
  GNUNET_MQ_PREFERENCE_RELIABILITY = 3

/**
 * Number of preference values allowed.
 */
#define GNUNET_MQ_PREFERENCE_COUNT 4
};


/**
 * Convert an `enum GNUNET_MQ_PreferenceType` to a string
 *
 * @param type the preference type
 * @return a string or NULL if invalid
 *
 * @deprecated will be replaced by `enum GNUNET_MQ_PriorityPreference`
 */
const char *
GNUNET_MQ_preference_to_string (enum GNUNET_MQ_PreferenceKind type);


#endif

/** @} */ /* end of group mq */
