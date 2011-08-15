/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport_testing.h
 * @brief testing lib for transport service
 *
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_transport_service.h"


/**
 * Context for a single peer
 */
struct PeerContext
{
  struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_TRANSPORT_Handle *th;

  struct GNUNET_PeerIdentity id;

  struct GNUNET_OS_Process *arm_proc;

  GNUNET_TRANSPORT_ReceiveCallback rec;

  GNUNET_TRANSPORT_NotifyConnect nc;

  GNUNET_TRANSPORT_NotifyDisconnect nd;

  void *cb_cls;

  char *servicehome;
};

/**
 * Callback when two peers are connected and both have called the connect callback
 * to notify clients about a new peer
 */
typedef void (*GNUNET_TRANSPORT_TESTING_connect_cb) (struct PeerContext * p1,
                                                     struct PeerContext * p2,
                                                     void *cls);


/**
 * Start a peer with the given configuration
 * @param rec receive callback
 * @param nc connect callback
 * @param nd disconnect callback
 * @param cb_cls closure for callback
 *   if NULL passed the PeerContext * will be used!
 * @return the peer context
 */
struct PeerContext *GNUNET_TRANSPORT_TESTING_start_peer (const char *cfgname,
                                                         GNUNET_TRANSPORT_ReceiveCallback
                                                         rec,
                                                         GNUNET_TRANSPORT_NotifyConnect
                                                         nc,
                                                         GNUNET_TRANSPORT_NotifyDisconnect
                                                         nd, void *cb_cls);


/**
 * shutdown the given peer
 * @param p the peer
 */

void GNUNET_TRANSPORT_TESTING_stop_peer (struct PeerContext *pc);


/**
 * Connect the given peers and call the callback when both peers report the
 * inbound connection. Remarks: start_peer's notify_connect callback can be called
 * before.
 * @param p1 peer 1
 * @param p2 peer 2
 * @param cb the callback to call
 * @param cb_cls callback cls
 */
void GNUNET_TRANSPORT_TESTING_connect_peers (struct PeerContext *p1,
                                             struct PeerContext *p2,
                                             GNUNET_TRANSPORT_TESTING_connect_cb
                                             cb, void *cls);

/* end of transport_testing.h */
