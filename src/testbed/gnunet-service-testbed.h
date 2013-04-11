/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 2, or (at your
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
 * @file testbed/gnunet-service-testbed.h
 * @brief data structures shared amongst components of TESTBED service
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_core_service.h"

#include "testbed.h"
#include "testbed_api.h"
#include "testbed_api_operations.h"
#include "testbed_api_hosts.h"
#include "gnunet_testing_lib.h"
#include "gnunet-service-testbed_links.h"


/**
 * Generic logging
 */
#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * By how much should the arrays lists grow
 */
#define LIST_GROW_STEP 10


/**
 * A routing entry
 */
struct Route
{
  /**
   * destination host
   */
  uint32_t dest;

  /**
   * The destination host is reachable thru
   */
  uint32_t thru;
};


/**
 * Context information for operations forwarded to subcontrollers
 */
struct ForwardedOperationContext
{
  /**
   * The next pointer for DLL
   */
  struct ForwardedOperationContext *next;

  /**
   * The prev pointer for DLL
   */
  struct ForwardedOperationContext *prev;

  /**
   * The generated operation context
   */
  struct OperationContext *opc;

  /**
   * The client to which we have to reply
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Closure pointer
   */
  void *cls;

  /**
   * Task ID for the timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * The id of the operation that has been forwarded
   */
  uint64_t operation_id;

  /**
   * The type of the operation which is forwarded
   */
  enum OperationType type;

};


/**
 * A DLL of host registrations to be made
 */
struct HostRegistration
{
  /**
   * next registration in the DLL
   */
  struct HostRegistration *next;

  /**
   * previous registration in the DLL
   */
  struct HostRegistration *prev;

  /**
   * The callback to call after this registration's status is available
   */
  GNUNET_TESTBED_HostRegistrationCompletion cb;

  /**
   * The closure for the above callback
   */
  void *cb_cls;

  /**
   * The host that has to be registered
   */
  struct GNUNET_TESTBED_Host *host;
};


/**
 * Context information used while linking controllers
 */
struct LinkControllersContext
{
  /**
   * The client which initiated the link controller operation
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The ID of the operation
   */
  uint64_t operation_id;

};


/**
 * A peer
 */

struct Peer
{

  union
  {
    struct
    {
      /**
       * The peer handle from testing API
       */
      struct GNUNET_TESTING_Peer *peer;

      /**
       * The modified (by GNUNET_TESTING_peer_configure) configuration this
       * peer is configured with
       */
      struct GNUNET_CONFIGURATION_Handle *cfg;

      /**
       * Is the peer running
       */
      int is_running;

    } local;

    struct
    {
      /**
       * The slave this peer is started through
       */
      struct Slave *slave;

      /**
       * The id of the remote host this peer is running on
       */
      uint32_t remote_host_id;

    } remote;

  } details;

  /**
   * Is this peer locally created?
   */
  int is_remote;

  /**
   * Our local reference id for this peer
   */
  uint32_t id;

  /**
   * References to peers are using in forwarded overlay contexts and remote
   * overlay connect contexts. A peer can only be destroyed after all such
   * contexts are destroyed. For this, we maintain a reference counter. When we
   * use a peer in any such context, we increment this counter. We decrement it
   * when we are destroying these contexts
   */
  uint32_t reference_cnt;

  /**
   * While destroying a peer, due to the fact that there could be references to
   * this peer, we delay the peer destroy to a further time. We do this by using
   * this flag to destroy the peer while destroying a context in which this peer
   * has been used. When the flag is set to 1 and reference_cnt = 0 we destroy
   * the peer
   */
  uint32_t destroy_flag;

};


/**
 * The main context information associated with the client which started us
 */
struct Context
{
  /**
   * The client handle associated with this context
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The network address of the master controller
   */
  char *master_ip;

  /**
   * The TESTING system handle for starting peers locally
   */
  struct GNUNET_TESTING_System *system;

  /**
   * Our host id according to this context
   */
  uint32_t host_id;
};


/**
 * The structure for identifying a shared service
 */
struct SharedService
{
  /**
   * The name of the shared service
   */
  char *name;

  /**
   * Number of shared peers per instance of the shared service
   */
  uint32_t num_shared;

  /**
   * Number of peers currently sharing the service
   */
  uint32_t num_sharing;
};


/**
 * Context information to used during operations which forward the overlay
 * connect message
 */
struct ForwardedOverlayConnectContext
{
  /**
   * next ForwardedOverlayConnectContext in the DLL
   */
  struct ForwardedOverlayConnectContext *next;

  /**
   * previous ForwardedOverlayConnectContext in the DLL
   */
  struct ForwardedOverlayConnectContext *prev;

  /**
   * A copy of the original overlay connect message
   */
  struct GNUNET_MessageHeader *orig_msg;

  /**
   * The id of the operation which created this context information
   */
  uint64_t operation_id;

  /**
   * the id of peer 1
   */
  uint32_t peer1;

  /**
   * The id of peer 2
   */
  uint32_t peer2;

  /**
   * Id of the host where peer2 is running
   */
  uint32_t peer2_host_id;
};


/**
 * The type for data structures which commonly arrive at the slave_event_callback
 */
enum ClosureType
{
  /**
   * Type for RegisteredHostContext closures
   */
  CLOSURE_TYPE_RHC = 1,

  /**
   * Type for LinkControllersForwardingContext closures
   */
  CLOSURE_TYPE_LCF
};


/**
 * This context information will be created for each host that is registered at
 * slave controllers during overlay connects.
 */
struct RegisteredHostContext
{
  /**
   * The type of this data structure. Set this to CLOSURE_TYPE_RHC
   */
  enum ClosureType type;

  /**
   * The host which is being registered
   */
  struct GNUNET_TESTBED_Host *reg_host;

  /**
   * The host of the controller which has to connect to the above rhost
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The gateway to which this operation is forwarded to
   */
  struct Slave *gateway;

  /**
   * The gateway through which peer2's controller can be reached
   */
  struct Slave *gateway2;

  /**
   * Handle for sub-operations
   */
  struct GNUNET_TESTBED_Operation *sub_op;

  /**
   * The client which initiated the link controller operation
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Head of the ForwardedOverlayConnectContext DLL
   */
  struct ForwardedOverlayConnectContext *focc_dll_head;

  /**
   * Tail of the ForwardedOverlayConnectContext DLL
   */
  struct ForwardedOverlayConnectContext *focc_dll_tail;

  /**
   * Enumeration of states for this context
   */
  enum RHCState
  {

    /**
     * The initial state
     */
    RHC_INIT = 0,

    /**
     * State where we attempt to get peer2's controller configuration
     */
    RHC_GET_CFG,

    /**
     * State where we attempt to link the controller of peer 1 to the controller
     * of peer2
     */
    RHC_LINK,

    /**
     * State where we attempt to do the overlay connection again
     */
    RHC_OL_CONNECT
  } state;

};


/**
 * Context data for GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS handler
 */
struct HandlerContext_ShutdownPeers
{
  /**
   * The number of slave we expect to hear from since we forwarded the
   * GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS message to them
   */
  unsigned int nslaves;

  /**
   * Did we observe a timeout with respect to this operation at any of the
   * slaves
   */
  int timeout;
};


/**
 * Our configuration
 */
struct GNUNET_CONFIGURATION_Handle *our_config;

/**
 * The master context; generated with the first INIT message
 */
extern struct Context *GST_context;

/**
 * DLL head for forwarded operation contexts
 */
extern struct ForwardedOperationContext *fopcq_head;

/**
 * DLL tail for forwarded operation contexts
 */
extern struct ForwardedOperationContext *fopcq_tail;

/**
 * A list of peers we know about
 */
extern struct Peer **GST_peer_list;

/**
 * Array of hosts
 */
extern struct GNUNET_TESTBED_Host **GST_host_list;

/**
 * Operation queue for open file descriptors
 */
extern struct OperationQueue *GST_opq_openfds;

/**
 * Timeout for operations which may take some time
 */
const extern struct GNUNET_TIME_Relative GST_timeout;

/**
 * The size of the peer list
 */
extern unsigned int GST_peer_list_size;

/**
 * The size of the host list
 */
extern unsigned int GST_host_list_size;

/**
 * The directory where to store load statistics data
 */
extern char *GST_stats_dir;


/**
 * Similar to GNUNET_array_grow(); however instead of calling GNUNET_array_grow()
 * several times we call it only once. The array is also made to grow in steps
 * of LIST_GROW_STEP.
 *
 * @param ptr the array pointer to grow
 * @param size the size of array
 * @param accommodate_size the size which the array has to accommdate; after
 *          this call the array will be big enough to accommdate sizes upto
 *          accommodate_size
 */
#define GST_array_grow_large_enough(ptr, size, accommodate_size) \
  do                                                                    \
  {                                                                     \
    unsigned int growth_size;                                           \
    GNUNET_assert (size <= accommodate_size);                            \
    growth_size = size;                                                 \
    while (growth_size <= accommodate_size)                             \
      growth_size += LIST_GROW_STEP;                                    \
    GNUNET_array_grow (ptr, size, growth_size);                         \
    GNUNET_assert (size > accommodate_size);                            \
  } while (0)


/**
 * Queues a message in send queue for sending to the service
 *
 * @param client the client to whom the queued message has to be sent
 * @param msg the message to queue
 */
void
GST_queue_message (struct GNUNET_SERVER_Client *client,
                   struct GNUNET_MessageHeader *msg);


/**
 * Function to destroy a peer
 *
 * @param peer the peer structure to destroy
 */
void
GST_destroy_peer (struct Peer *peer);


/**
 * Stops and destroys all peers
 */
void
GST_destroy_peers ();


/**
 * Finds the route with directly connected host as destination through which
 * the destination host can be reached
 *
 * @param host_id the id of the destination host
 * @return the route with directly connected destination host; NULL if no route
 *           is found
 */
struct Route *
GST_find_dest_route (uint32_t host_id);


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_OLCONNECT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_overlay_connect (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message);


/**
 * Adds a host registration's request to a slave's registration queue
 *
 * @param slave the slave controller at which the given host has to be
 *          registered
 * @param cb the host registration completion callback
 * @param cb_cls the closure for the host registration completion callback
 * @param host the host which has to be registered
 */
void
GST_queue_host_registration (struct Slave *slave,
                             GNUNET_TESTBED_HostRegistrationCompletion cb,
                             void *cb_cls, struct GNUNET_TESTBED_Host *host);


/**
 * Callback to relay the reply msg of a forwarded operation back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the message to relay
 */
void
GST_forwarded_operation_reply_relay (void *cls,
                                     const struct GNUNET_MessageHeader *msg);


/**
 * Task to free resources when forwarded operation has been timedout
 *
 * @param cls the ForwardedOperationContext
 * @param tc the task context from scheduler
 */
void
GST_forwarded_operation_timeout (void *cls,
                                 const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Clears the forwarded operations queue
 */
void
GST_clear_fopcq ();


/**
 * Send operation failure message to client
 *
 * @param client the client to which the failure message has to be sent to
 * @param operation_id the id of the failed operation
 * @param emsg the error message; can be NULL
 */
void
GST_send_operation_fail_msg (struct GNUNET_SERVER_Client *client,
                             uint64_t operation_id, const char *emsg);


/**
 * Function to send generic operation success message to given client
 *
 * @param client the client to send the message to
 * @param operation_id the id of the operation which was successful
 */
void
GST_send_operation_success_msg (struct GNUNET_SERVER_Client *client,
                                uint64_t operation_id);


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_REQUESTCONNECT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_remote_overlay_connect (void *cls,
                                   struct GNUNET_SERVER_Client *client,
                                   const struct GNUNET_MessageHeader *message);


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_create (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message);


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_destroy (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message);


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_start (void *cls, struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message);


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_stop (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message);


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_get_config (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message);


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_shutdown_peers (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message);


/**
 * Handler for GNUNET_TESTBED_ManagePeerServiceMessage message
 *
 * @param cls NULL
 * @param client identification of client
 * @param message the actual message
 */
void
GST_handle_manage_peer_service (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message);


/**
 * Frees the ManageServiceContext queue
 */
void
GST_free_mctxq ();


/**
 * Cleans up the queue used for forwarding link controllers requests
 */
void
GST_free_lcfq ();


/**
 * Cleans up the route list
 */
void
GST_route_list_clear ();


/**
 * Processes a forwarded overlay connect context in the queue of the given RegisteredHostContext
 *
 * @param rhc the RegisteredHostContext
 */
void
GST_process_next_focc (struct RegisteredHostContext *rhc);


/**
 * Cleans up ForwardedOverlayConnectContext
 *
 * @param focc the ForwardedOverlayConnectContext to cleanup
 */
void
GST_cleanup_focc (struct ForwardedOverlayConnectContext *focc);


/**
 * Clears all pending overlay connect contexts in queue
 */
void
GST_free_occq ();


/**
 * Clears all pending remote overlay connect contexts in queue
 */
void
GST_free_roccq ();


/**
 * Initializes the cache
 *
 * @param size the size of the cache
 */
void
GST_cache_init (unsigned int size);


/**
 * Clear cache
 */
void
GST_cache_clear ();


/**
 * Looks up in the hello cache and returns the HELLO of the given peer
 *
 * @param peer_id the index of the peer whose HELLO has to be looked up
 * @return the HELLO message; NULL if not found
 */
const struct GNUNET_MessageHeader *
GST_cache_lookup_hello (const unsigned int peer_id);


/**
 * Caches the HELLO of the given peer. Updates the HELLO if it was already
 * cached before
 *
 * @param peer_id the peer identity of the peer whose HELLO has to be cached
 * @param hello the HELLO message
 */
void
GST_cache_add_hello (const unsigned int peer_id,
                     const struct GNUNET_MessageHeader *hello);


/**
 * Functions of this type are called when the needed handle is available for
 * usage. These functions are to be registered with either of the functions
 * GST_cache_get_handle_transport() or GST_cache_get_handle_core(). The
 * corresponding handles will be set and if they are not, then it signals an
 * error while opening the handles.
 *
 * @param cls the closure passed to GST_cache_get_handle_transport() or
 *          GST_cache_get_handle_core()
 * @param ch the handle to CORE. Can be NULL if it is not requested
 * @param th the handle to TRANSPORT. Can be NULL if it is not requested
 * @param peer_id the identity of the peer. Will be NULL if ch is NULL. In other
 *          cases, its value being NULL means that CORE connection has failed.
 */
typedef void (*GST_cache_handle_ready_cb) (void *cls,
                                           struct GNUNET_CORE_Handle * ch,
                                           struct GNUNET_TRANSPORT_Handle * th,
                                           const struct GNUNET_PeerIdentity *
                                           peer_id);


/**
 * Callback to notify when the target peer given to
 * GST_cache_get_handle_transport() is connected. Note that this callback may
 * not be called if the target peer is already connected. Use
 * GNUNET_TRANSPORT_check_neighbour_connected() to check if the target peer is
 * already connected or not. This callback will be called only once or never (in
 * case the target cannot be connected).
 *
 * @param cls the closure given to GST_cache_get_handle_done() for this callback
 * @param target the peer identity of the target peer. The pointer should be
 *          valid until GST_cache_get_handle_done() is called.
 */
typedef void (*GST_cache_peer_connect_notify) (void *cls,
                                               const struct GNUNET_PeerIdentity
                                               * target);


/**
 * Get a transport handle with the given configuration. If the handle is already
 * cached before, it will be retured in the given callback; the peer_id is used to lookup in the
 * cache. If not a new operation is started to open the transport handle and
 * will be given in the callback when it is available.
 *
 * @param peer_id the index of the peer
 * @param cfg the configuration with which the transport handle has to be
 *          created if it was not present in the cache
 * @param cb the callback to notify when the transport handle is available
 * @param cb_cls the closure for the above callback
 * @param target the peer identify of the peer whose connection to our TRANSPORT
 *          subsystem will be notified through the connect_notify_cb. Can be NULL
 * @param connect_notify_cb the callback to call when the given target peer is
 *          connected. This callback will only be called once or never again (in
 *          case the target peer cannot be connected). Can be NULL
 * @param connect_notify_cb_cls the closure for the above callback
 * @return the handle which can be used cancel or mark that the handle is no
 *           longer being used
 */
struct GSTCacheGetHandle *
GST_cache_get_handle_transport (unsigned int peer_id,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                GST_cache_handle_ready_cb cb, void *cb_cls,
                                const struct GNUNET_PeerIdentity *target,
                                GST_cache_peer_connect_notify connect_notify_cb,
                                void *connect_notify_cb_cls);


/**
 * Get a CORE handle with the given configuration. If the handle is already
 * cached before, it will be retured in the given callback; the peer_id is used
 * to lookup in the cache. If the handle is not cached before, a new operation
 * is started to open the CORE handle and will be given in the callback when it
 * is available along with the peer identity
 *
 * @param peer_id the index of the peer
 * @param cfg the configuration with which the transport handle has to be
 *          created if it was not present in the cache
 * @param cb the callback to notify when the transport handle is available
 * @param cb_cls the closure for the above callback
 * @param target the peer identify of the peer whose connection to our CORE
 *          subsystem will be notified through the connect_notify_cb. Can be NULL
 * @param connect_notify_cb the callback to call when the given target peer is
 *          connected. This callback will only be called once or never again (in
 *          case the target peer cannot be connected). Can be NULL
 * @param connect_notify_cb_cls the closure for the above callback
 * @return the handle which can be used cancel or mark that the handle is no
 *           longer being used
 */
struct GSTCacheGetHandle *
GST_cache_get_handle_core (unsigned int peer_id,
                           const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GST_cache_handle_ready_cb cb, void *cb_cls,
                           const struct GNUNET_PeerIdentity *target,
                           GST_cache_peer_connect_notify connect_notify_cb,
                           void *connect_notify_cb_cls);


/**
 * Mark the GetCacheHandle as being done if a handle has been provided already
 * or as being cancelled if the callback for the handle hasn't been called.
 *
 * @param cgh the CacheGetHandle handle
 */
void
GST_cache_get_handle_done (struct GSTCacheGetHandle *cgh);


/**
 * Initialize logging CPU and IO statisticfs.  Checks the configuration for
 * "STATS_DIR" and logs to a file in that directory.  The file is name is
 * generated from the hostname and the process's PID.
 */
void
GST_stats_init (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown the status calls module.
 */
void
GST_stats_destroy ();

/* End of gnunet-service-testbed.h */
