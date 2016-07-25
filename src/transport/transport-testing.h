/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2015, 2016 GNUnet e.V.

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
 * @file transport-testing.h
 * @brief testing lib for transport service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef TRANSPORT_TESTING_H
#define TRANSPORT_TESTING_H
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_core_service.h"
#include "gnunet_transport_manipulation_service.h"
#include "gnunet_testing_lib.h"


/* ************* Basic functions for starting/stopping/connecting *********** */

/**
 * Context for a single peer
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext;

/**
 * Definition for a transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_Handle;


/**
 * Context for a single peer
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext
{
  /**
   * Next element in the DLL
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *next;

  /**
   * Previous element in the DLL
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *prev;

  /**
   * Transport testing handle this peer belongs to
   */
  struct GNUNET_TRANSPORT_TESTING_Handle *tth;

  /**
   * Peer's configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Peer's transport service handle
   */
  struct GNUNET_TRANSPORT_CoreHandle *th;

  /**
   * Peer's transport service manipulation handle
   */
  struct GNUNET_TRANSPORT_ManipulationHandle *tmh;

  /**
   * Peer's ATS handle.
   */
  struct GNUNET_ATS_ConnectivityHandle *ats;

  /**
   * Peer's transport get hello handle to retrieve peer's HELLO message
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;

  /**
   * Peer's testing handle
   */
  struct GNUNET_TESTING_Peer *peer;

  /**
   * Peer identity
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Handle for the peer's ARM process
   */
  struct GNUNET_OS_Process *arm_proc;

  /**
   * Receive callback
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Notify connect callback
   */
  GNUNET_TRANSPORT_NotifyConnecT nc;

  /**
   * Notify disconnect callback
   */
  GNUNET_TRANSPORT_NotifyDisconnecT nd;

  /**
   * Startup completed callback
   */
  GNUNET_SCHEDULER_TaskCallback start_cb;

  /**
   * Peers HELLO Message
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Closure for the @a nc and @a nd callbacks
   */
  void *cb_cls;

  /**
   * Closure for @e start_cb.
   */
  void *start_cb_cls;
  
  /**
   * An unique number to identify the peer
   */
  unsigned int no;
};


/**
 * Handle for a request to connect two peers.
 */
struct GNUNET_TRANSPORT_TESTING_ConnectRequest
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *prev;

  /**
   * Peer we want to connect.
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p1;

  /**
   * Peer we want to connect.
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2;

  /**
   * Task by which we accomplish the connection.
   */
  struct GNUNET_SCHEDULER_Task *tct;

  /**
   * Handle by which we ask ATS to faciliate the connection.
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;

  /**
   * Handle by which we inform the peer about the HELLO of
   * the other peer.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;

  /**
   * Function to call upon completion.
   */
  GNUNET_SCHEDULER_TaskCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Message queue for sending from @a p1 to @a p2.
   */
  struct GNUNET_MQ_Handle *mq;

  /** 
   * Set if peer1 says the connection is up to peer2.
   */
  int p1_c;

  /** 
   * Set if peer2 says the connection is up to peer1.
   */
  int p2_c;

  /**
   * #GNUNET_YES if both @e p1_c and @e p2_c are #GNUNET_YES.
   */
  int connected;
};


/**
 * Handle for a test run.
 */
struct GNUNET_TRANSPORT_TESTING_Handle
{
  /**
   * Testing library system handle
   */
  struct GNUNET_TESTING_System *tl_system;

  /**
   * head DLL of connect contexts
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc_head;

  /**
   * head DLL of connect contexts
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc_tail;

  /**
   * head DLL of peers
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p_head;

  /**
   * tail DLL of peers
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p_tail;
};


/**
 * Initialize the transport testing
 *
 * @return transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_Handle *
GNUNET_TRANSPORT_TESTING_init (void);


/**
 * Clean up the transport testing
 *
 * @param tth transport testing handle
 */
void
GNUNET_TRANSPORT_TESTING_done (struct GNUNET_TRANSPORT_TESTING_Handle *tth);


/**
 * Start a peer with the given configuration
 *
 * @param tth the testing handle
 * @param cfgname configuration file
 * @param peer_id the peer_id
 * @param handlers functions for receiving messages
 * @param nc connect callback
 * @param nd disconnect callback
 * @param cb_cls closure for @a nc and @a nd callback
 * @param start_cb start callback
 * @param start_cb_cls closure for @a start_cb
 * @return the peer context
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (struct GNUNET_TRANSPORT_TESTING_Handle *tth,
                                     const char *cfgname,
                                     int peer_id,
                                     const struct GNUNET_MQ_MessageHandler *handlers,
                                     GNUNET_TRANSPORT_NotifyConnecT nc,
                                     GNUNET_TRANSPORT_NotifyDisconnecT nd,
				     void *cb_cls,
                                     GNUNET_SCHEDULER_TaskCallback start_cb,
                                     void *start_cb_cls);


/**
 * Shutdown the given peer
 *
 * @param p the peer
 */
void
GNUNET_TRANSPORT_TESTING_stop_peer (struct GNUNET_TRANSPORT_TESTING_PeerContext *pc);


/**
 * Stops and restarts the given peer, sleeping (!) for 5s in between.
 *
 * @param p the peer
 * @param restart_cb restart callback
 * @param restart_cb_cls callback closure
 * @return #GNUNET_OK in success otherwise #GNUNET_SYSERR
 */
int
GNUNET_TRANSPORT_TESTING_restart_peer (struct GNUNET_TRANSPORT_TESTING_PeerContext *p,
                                       GNUNET_SCHEDULER_TaskCallback restart_cb,
                                       void *restart_cb_cls);



/**
 * Connect the given peers and call the callback when both peers
 * report the inbound connection. Remarks: start_peer's notify_connect
 * callback can be called before.
 *
 * @param p1 peer 1
 * @param p2 peer 2
 * @param cb the callback to call when both peers notified that they are connected
 * @param cls callback cls
 * @return a connect request handle
 */
struct GNUNET_TRANSPORT_TESTING_ConnectRequest *
GNUNET_TRANSPORT_TESTING_connect_peers (struct GNUNET_TRANSPORT_TESTING_PeerContext *p1,
                                        struct GNUNET_TRANSPORT_TESTING_PeerContext *p2,
                                        GNUNET_SCHEDULER_TaskCallback cb,
                                        void *cls);


/**
 * Cancel the request to connect two peers.  You MUST cancel the
 * request if you stop the peers before the peers connected
 * succesfully.
 *
 * @param cc a connect request handle
 */
void
GNUNET_TRANSPORT_TESTING_connect_peers_cancel (struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc);


/**
 * Function called on matching connect requests.
 *
 * @param cls closure
 * @param cc request matching the query
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_ConnectContextCallback)(void *cls,
						   struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc);


/**
 * Find any connecting context matching the given pair of peers.
 *
 * @param p1 first peer
 * @param p2 second peer
 * @param cb function to call 
 * @param cb_cls closure for @a cb
 */
void
GNUNET_TRANSPORT_TESTING_find_connecting_context (struct GNUNET_TRANSPORT_TESTING_PeerContext *p1,
						  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2,
						  GNUNET_TRANSPORT_TESTING_ConnectContextCallback cb,
						  void *cb_cls);


/* ********************** high-level process functions *************** */


/**
 * Function called once the peers have been launched and
 * connected by #GNUNET_TRANSPORT_TESTING_connect_check().
 *
 * @param cls closure
 * @param num_peers size of the @a p array
 * @param p the peers that were launched
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_ConnectContinuation)(void *cls,
                                                unsigned int num_peers,
                                                struct GNUNET_TRANSPORT_TESTING_PeerContext *p[]);


/**
 * Internal data structure.
 */
struct GNUNET_TRANSPORT_TESTING_ConnectRequestList;

/**
 * Internal data structure.
 */
struct GNUNET_TRANSPORT_TESTING_InternalPeerContext;


GNUNET_NETWORK_STRUCT_BEGIN
struct GNUNET_TRANSPORT_TESTING_TestMessage
{
  /**
   * Type is (usually) #GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Monotonically increasing counter throughout the test.
   */
  uint32_t num GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END



/**
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param receiver receiver of the message
 * @param sender sender of the message
 * @param message the message
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_ReceiveCallback) (void *cls,
                                             struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
                                             const struct GNUNET_PeerIdentity *sender,
                                             const struct GNUNET_TRANSPORT_TESTING_TestMessage *message);


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param me peer experiencing the event
 * @param other peer that connected to @a me
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_NotifyConnect) (void *cls,
                                           struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                                           const struct GNUNET_PeerIdentity *other);


/**
 * Function called to notify transport users that another
 * peer disconnected from us.
 *
 * @param cls closure
 * @param me peer experiencing the event
 * @param other peer that disconnected from @a me
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_NotifyDisconnect) (void *cls,
                                              struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                                              const struct GNUNET_PeerIdentity *other);


/**
 * Closure that must be passed to
 * #GNUNET_TRANSPORT_TESTING_connect_check.
 */
struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext
{

  /**
   * How should we continue after the connect?
   */
  GNUNET_SCHEDULER_TaskCallback connect_continuation;

  /**
   * Closure for @e connect_continuation.
   */
  void *connect_continuation_cls;

  /**
   * Which configuration file should we pass to the
   * #GNUNET_PROGRAM_run() of the testcase?
   */
  const char *config_file;

  /**
   * Receiver argument to give for peers we start.
   */
  GNUNET_TRANSPORT_TESTING_ReceiveCallback rec;

  /**
   * Notify connect argument to give for peers we start.
   */
  GNUNET_TRANSPORT_TESTING_NotifyConnect nc;

  /**
   * Notify disconnect argument to give for peers we start.
   */
  GNUNET_TRANSPORT_TESTING_NotifyDisconnect nd;

  /**
   * Closure for @e rec, @e nc and @e nd.
   */
  void *cls;

  /**
   * Custom task to run on shutdown.
   */
  GNUNET_SCHEDULER_TaskCallback shutdown_task;

  /**
   * Closure for @e shutdown_task.
   */
  void *shutdown_task_cls;

  /**
   * Custom task to run after peers were started but before we try to
   * connect them.  If this function is set, we wait ONE second after
   * running this function until we continue with connecting the
   * peers.
   */
  GNUNET_SCHEDULER_TaskCallback pre_connect_task;

  /**
   * Closure for @e shutdown_task.
   */
  void *pre_connect_task_cls;

  /**
   * When should the testcase time out?
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Should we try to create connections in both directions?
   */
  int bi_directional;

  /* ******* fields set by #GNUNET_TRANSPORT_TESTING_connect_check **** */

  /**
   * Number of peers involved in the test.
   */
  unsigned int num_peers;

  /**
   * Configuration files we have, array with @e num_peers entries.
   */
  char **cfg_files;

  /**
   * Array with @e num_peers entries.
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext **p;

  /**
   * Name of the plugin.
   */
  const char *test_plugin;

  /**
   * Name of the testcase.
   */
  const char *test_name;

  /**
   * Configuration object for the testcase.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Main testing handle.
   */
  struct GNUNET_TRANSPORT_TESTING_Handle *tth;

  /**
   * Result from the main function, set to #GNUNET_OK on success.
   * Clients should set to #GNUNET_SYSERR to indicate test failure.
   */
  int global_ret;

  /**
   * Generator for the `num` field in test messages.  Incremented each
   * time #GNUNET_TRANSPORT_TESTING_simple_send or
   * #GNUNET_TRANSPORT_TESTING_large_send are used to transmit a
   * message.
   */
  uint32_t send_num_gen;
  
  /* ******* internal state, clients should not mess with this **** */

  /**
   * Task run on timeout.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Task run to connect peers.
   */
  struct GNUNET_SCHEDULER_Task *connect_task;

  /**
   * Number of peers that have been started.
   */
  unsigned int started;

  /**
   * DLL of active connect requests.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *crl_head;

  /**
   * DLL of active connect requests.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *crl_tail;

  /**
   * Array with @e num_peers entries.
   */
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ip;

};


/**
 * Find peer by peer ID.
 *
 * @param ccc context to search
 * @param peer peer to look for
 * @return NULL if @a peer was not found
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext *
GNUNET_TRANSPORT_TESTING_find_peer (struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc,
                                    const struct GNUNET_PeerIdentity *peer);


/**
 * Common implementation of the #GNUNET_TRANSPORT_TESTING_CheckCallback.
 * Starts and connects the two peers, then invokes the
 * `connect_continuation` from @a cls.  Sets up a timeout to
 * abort the test, and a shutdown handler to clean up properly
 * on exit.
 *
 * @param cls closure of type `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext`
 * @param tth_ initialized testing handle
 * @param test_plugin_ name of the plugin
 * @param test_name_ name of the test
 * @param num_peers number of entries in the @a cfg_file array
 * @param cfg_files array of names of configuration files for the peers
 * @return #GNUNET_SYSERR on error
 */
int
GNUNET_TRANSPORT_TESTING_connect_check (void *cls,
                                        struct GNUNET_TRANSPORT_TESTING_Handle *tth_,
                                        const char *test_plugin_,
                                        const char *test_name_,
                                        unsigned int num_peers,
                                        char *cfg_files[]);


/**
 * Main function of a testcase.  Called with the initial setup data
 * for the test as derived from the source name and the binary name.
 *
 * @param cls closure
 * @param tth_ initialized testing handle
 * @param test_plugin_ name of the plugin
 * @param test_name_ name of the test
 * @param num_peers number of entries in the @a cfg_file array
 * @param cfg_files array of names of configuration files for the peers
 * @return #GNUNET_SYSERR on error
 */
typedef int
(*GNUNET_TRANSPORT_TESTING_CheckCallback)(void *cls,
                                          struct GNUNET_TRANSPORT_TESTING_Handle *tth_,
                                          const char *test_plugin_,
                                          const char *test_name_,
                                          unsigned int num_peers,
                                          char *cfg_files[]);


/**
 * Setup testcase.  Calls @a check with the data the test needs.
 *
 * @param argv0 binary name (argv[0])
 * @param filename source file name (__FILE__)
 * @param num_peers number of peers to start
 * @param check main function to run
 * @param check_cls closure for @a check
 * @return #GNUNET_OK on success
 */
int
GNUNET_TRANSPORT_TESTING_main_ (const char *argv0,
                                const char *filename,
                                unsigned int num_peers,
                                GNUNET_TRANSPORT_TESTING_CheckCallback check,
                                void *check_cls);


/**
 * Setup testcase.  Calls @a check with the data the test needs.
 *
 * @param num_peers number of peers to start
 * @param check main function to run
 * @param check_cls closure for @a check
 * @return #GNUNET_OK on success
 */
#define GNUNET_TRANSPORT_TESTING_main(num_peers,check,check_cls) \
  GNUNET_TRANSPORT_TESTING_main_ (argv[0], __FILE__, num_peers, check, check_cls)

/* ***************** Convenience functions for sending ********* */

/**
 * Send a test message of type @a mtype and size @a msize from
 * peer @a sender to peer @a receiver.  The peers should be
 * connected when this function is called.
 *
 * @param sender the sending peer
 * @param receiver the receiving peer
 * @param mtype message type to use
 * @param msize size of the message, at least `sizeof (struct GNUNET_TRANSPORT_TESTING_TestMessage)`
 * @param num unique message number
 * @param cont continuation to call after transmission
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK if message was queued,
 *         #GNUNET_NO if peers are not connected
 *         #GNUNET_SYSERR if @a msize is illegal
 */
int
GNUNET_TRANSPORT_TESTING_send (struct GNUNET_TRANSPORT_TESTING_PeerContext *sender,
			       struct GNUNET_TRANSPORT_TESTING_PeerContext *receiver,
			       uint16_t mtype,
			       uint16_t msize,
			       uint32_t num,
			       GNUNET_SCHEDULER_TaskCallback cont,
			       void *cont_cls);


/**
 * Message type used by #GNUNET_TRANSPORT_TESTING_simple_send().
 */
#define GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE 12345

/**
 * Alternative message type for tests.
 */
#define GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE2 12346


/**
 * Type of the closure argument to pass to
 * #GNUNET_TRANSPORT_TESTING_simple_send() and
 * #GNUNET_TRANSPORT_TESTING_large_send().
 */
struct GNUNET_TRANSPORT_TESTING_SendClosure
{
  /**
   * Context for the transmission.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

  /**
   * Function that returns the desired message size. Overrides
   * the message size, can be NULL in which case the message
   * size is the default.
   */
  size_t (*get_size_cb)(unsigned int n);
  
  /**
   * Number of messages to be transmitted in a loop.
   * Use zero for "forever" (until external shutdown).
   */
  unsigned int num_messages;
  
  /**
   * Function to call after all transmissions, can be NULL.
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;
  
};


/**
 * Task that sends a minimalistic test message from the 
 * first peer to the second peer.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TESTING_SendClosure`
 *        which should contain at least two peers, the first two
 *        of which should be currently connected
 */
void
GNUNET_TRANSPORT_TESTING_simple_send (void *cls);

/**
 * Size of a message sent with 
 * #GNUNET_TRANSPORT_TESTING_large_send().  Big enough
 * to usually force defragmentation.
 */
#define GNUNET_TRANSPORT_TESTING_LARGE_MESSAGE_SIZE 2600

/**
 * Task that sends a large test message from the 
 * first peer to the second peer.
 *
 * @param cls the `struct GNUNET_TRANSPORT_TESTING_SendClosure`
 *        which should contain at least two peers, the first two
 *        of which should be currently connected
 */
void
GNUNET_TRANSPORT_TESTING_large_send (void *cls);


/* ********************** log-only convenience functions ************* */


/**
 * Log a connect event.
 *
 * @param cls NULL
 * @param me peer that had the event
 * @param other peer that connected.
 */
void
GNUNET_TRANSPORT_TESTING_log_connect (void *cls,
                                      struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                                      const struct GNUNET_PeerIdentity *other);


/**
 * Log a disconnect event.
 *
 * @param cls NULL
 * @param me peer that had the event
 * @param other peer that disconnected.
 */
void
GNUNET_TRANSPORT_TESTING_log_disconnect (void *cls,
                                         struct GNUNET_TRANSPORT_TESTING_PeerContext *me,
                                         const struct GNUNET_PeerIdentity *other);



/* ********************** low-level filename functions *************** */


/**
 * Extracts the test filename from an absolute file name and removes
 * the extension.
 *
 * @param file absolute file name
 * @return resulting test name
 */
char *
GNUNET_TRANSPORT_TESTING_get_test_name (const char *file);


/**
 * This function takes the filename (e.g. argv[0), removes a "lt-"-prefix and
 * if existing ".exe"-prefix and adds the peer-number
 *
 * @param file filename of the test, e.g. argv[0]
 * @param count peer number
 * @return configuration name to use
 */
char *
GNUNET_TRANSPORT_TESTING_get_config_name (const char *file,
                                          int count);


/**
 * Extracts the plugin anme from an absolute file name and the test name
 * @param file absolute file name
 * @param test test name
 * @return the plugin name
 */
char *
GNUNET_TRANSPORT_TESTING_get_test_plugin_name (const char *executable,
                                               const char *testname);


/**
 * Extracts the filename from an absolute file name and removes the
 * extenstion
 *
 * @param file absolute file name
 * @return the source name
 */
char *
GNUNET_TRANSPORT_TESTING_get_test_source_name (const char *file);

#endif
/* end of transport_testing.h */
