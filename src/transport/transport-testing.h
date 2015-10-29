/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2015 Christian Grothoff (and other contributing authors)

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
 *
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_testing_lib.h"


struct GNUNET_TRANSPORT_TESTING_ConnectRequest;


/**
 * Context for a single peer
 */
struct PeerContext;

/**
 * Callback when two peers are connected and both have called the connect callback
 * to notify clients about a new peer
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_start_cb) (struct PeerContext *p,
                                      void *cls);

/**
 * Callback when two peers are connected and both have called the connect callback
 * to notify clients about a new peer
 */
typedef void
(*GNUNET_TRANSPORT_TESTING_connect_cb) (struct PeerContext *p1,
                                        struct PeerContext *p2,
                                        void *cls);


/**
 * Definition for a transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_handle;

/**
 * Context for a single peer
 */
struct PeerContext
{
  /**
   * Next element in the DLL
   */
  struct PeerContext *next;

  /**
   * Previous element in the DLL
   */
  struct PeerContext *prev;

  /**
   * Transport testing handle this peer belongs to
   */
  struct GNUNET_TRANSPORT_TESTING_handle *tth;

  /**
   * Peer's configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Peer's transport service handle
   */
  struct GNUNET_TRANSPORT_Handle *th;

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
  GNUNET_TRANSPORT_TESTING_start_cb start_cb;

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


struct GNUNET_TRANSPORT_TESTING_ConnectRequest
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *next;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *prev;
  struct PeerContext *p1;
  struct PeerContext *p2;
  struct GNUNET_SCHEDULER_Task *tct;
  GNUNET_TRANSPORT_TESTING_connect_cb cb;
  void *cb_cls;
  struct GNUNET_TRANSPORT_Handle *th_p1;
  struct GNUNET_TRANSPORT_Handle *th_p2;
  int p1_c;
  int p2_c;
};

struct GNUNET_TRANSPORT_TESTING_handle
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
  struct PeerContext *p_head;

  /**
   * tail DLL of peers
   */
  struct PeerContext *p_tail;
};


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
struct PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                     const char *cfgname,
                                     int peer_id,
                                     GNUNET_TRANSPORT_ReceiveCallback rec,
                                     GNUNET_TRANSPORT_NotifyConnect nc,
                                     GNUNET_TRANSPORT_NotifyDisconnect nd,
                                     GNUNET_TRANSPORT_TESTING_start_cb start_cb,
                                     void *cb_cls);


/**
 * shutdown the given peer
 *
 * @param tth the testing handle
 * @param p the peer
 */
void
GNUNET_TRANSPORT_TESTING_stop_peer (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                    struct PeerContext *pc);


/**
 * Restart the given peer
 *
 * @param tth testing handle
 * @param p the peer
 * @param cfgname the cfg file used to restart
 * @param restart_cb restart callback
 * @param cb_cls callback closure
 * @return #GNUNET_OK in success otherwise #GNUNET_SYSERR
 */
int
GNUNET_TRANSPORT_TESTING_restart_peer (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                       struct PeerContext *p,
                                       const char *cfgname,
                                       GNUNET_TRANSPORT_TESTING_start_cb restart_cb,
                                       void *cb_cls);


/**
 * Connect the given peers and call the callback when both peers report the
 * inbound connection. Remarks: start_peer's notify_connect callback can be called
 * before.
 *
 * @param tth transport testing handle
 * @param p1 peer 1
 * @param p2 peer 2
 * @param cb the callback to call when both peers notified that they are connected
 * @param cls callback cls
 * @return a connect request handle
 */
struct GNUNET_TRANSPORT_TESTING_ConnectRequest *
GNUNET_TRANSPORT_TESTING_connect_peers (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                        struct PeerContext *p1,
                                        struct PeerContext *p2,
                                        GNUNET_TRANSPORT_TESTING_connect_cb cb,
                                        void *cls);


/**
 * Cancel the request to connect two peers
 * Tou MUST cancel the request if you stop the peers before the peers connected succesfully
 * @param tth testing
 * @param cc a connect request handle
 */
void
GNUNET_TRANSPORT_TESTING_connect_peers_cancel (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                               struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cc);

/**
 * Clean up the transport testing
 * @param tth transport testing handle
 */
void
GNUNET_TRANSPORT_TESTING_done (struct GNUNET_TRANSPORT_TESTING_handle *tth);

/**
 * Initialize the transport testing
 * @return transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_handle *
GNUNET_TRANSPORT_TESTING_init (void);

/*
 * Some utility functions
 */

/**
 * Extracts the test filename from an absolute file name and removes the extension
 * @param file absolute file name
 * @param dest where to store result
 */
void
GNUNET_TRANSPORT_TESTING_get_test_name (const char *file,
                                        char **dest);

/**
 * This function takes the filename (e.g. argv[0), removes a "lt-"-prefix and
 * if existing ".exe"-prefix and adds the peer-number
 *
 * @param file filename of the test, e.g. argv[0]
 * @param dest where to write the filename
 * @param count peer number
 */
void
GNUNET_TRANSPORT_TESTING_get_config_name (const char *file,
                                          char **dest,
                                          int count);


/**
 * Extracts the plugin anme from an absolute file name and the test name
 * @param file absolute file name
 * @param test test name
 * @param dest where to store result
 */
void
GNUNET_TRANSPORT_TESTING_get_test_plugin_name (const char *executable,
                                               const char *testname,
                                               char **pluginname);


/**
 * Extracts the filename from an absolute file name and removes the extenstion
 * @param file absolute file name
 * @param dest where to store result
 */
void
GNUNET_TRANSPORT_TESTING_get_test_source_name (const char *file,
                                               char **testname);

/* end of transport_testing.h */
