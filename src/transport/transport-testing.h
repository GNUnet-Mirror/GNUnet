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
#include "gnunet_testing_lib.h"


/**
 * Context for a single peer
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext;

/**
 * Definition for a transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_Handle;


/**
 * Callback when two peers are connected and both have called the connect callback
 * to notify clients about a new peer
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_StartCallback) (struct GNUNET_TRANSPORT_TESTING_PeerContext *p,
                                           void *cls);


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
  struct GNUNET_TRANSPORT_Handle *th;

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
  GNUNET_TRANSPORT_ReceiveCallback rec;

  /**
   * Notify connect callback
   */
  GNUNET_TRANSPORT_NotifyConnect nc;

  /**
   * Notify disconnect callback
   */
  GNUNET_TRANSPORT_NotifyDisconnect nd;

  /**
   * Startup completed callback
   */
  GNUNET_TRANSPORT_TESTING_StartCallback start_cb;

  /**
   * Peers HELLO Message
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Closure for the callbacks
   */
  void *cb_cls;

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
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *next;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *prev;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p1;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2;
  struct GNUNET_SCHEDULER_Task *tct;
  struct GNUNET_ATS_ConnectivitySuggestHandle *ats_sh;
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;
  GNUNET_SCHEDULER_TaskCallback cb;
  void *cb_cls;
  int p1_c;
  int p2_c;
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
 * @param rec receive callback
 * @param nc connect callback
 * @param nd disconnect callback
 * @param start_cb start callback
 * @param cb_cls closure for callback
 * @return the peer context
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (struct GNUNET_TRANSPORT_TESTING_Handle *tth,
                                     const char *cfgname,
                                     int peer_id,
                                     GNUNET_TRANSPORT_ReceiveCallback rec,
                                     GNUNET_TRANSPORT_NotifyConnect nc,
                                     GNUNET_TRANSPORT_NotifyDisconnect nd,
                                     GNUNET_TRANSPORT_TESTING_StartCallback start_cb,
                                     void *cb_cls);


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
 * @param cb_cls callback closure
 * @return #GNUNET_OK in success otherwise #GNUNET_SYSERR
 */
int
GNUNET_TRANSPORT_TESTING_restart_peer (struct GNUNET_TRANSPORT_TESTING_PeerContext *p,
                                       GNUNET_TRANSPORT_TESTING_StartCallback restart_cb,
                                       void *cb_cls);



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

/* ********************** high-level process functions *************** */


/**
 * Main function of a testcase.  Called with the initial setup data
 * for the test as derived from the source name and the binary name.
 *
 * @param cls closure
 * @param tth initialized testing handle
 * @param test_plugin name of the plugin (if available)
 * @param num_peers number of entries in the @a cfg_file array
 * @param cfg_files array of names of configuration files for the peers
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_CheckCallback)(void *cls,
                                          struct GNUNET_TRANSPORT_TESTING_Handle *tth,
                                          const char *test_plugin,
                                          unsigned int num_peers,
                                          const char *cfg_files[]);


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
