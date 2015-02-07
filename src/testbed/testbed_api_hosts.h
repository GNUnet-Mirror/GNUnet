/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_hosts.h
 * @brief internal API to access the 'hosts' subsystem
 * @author Christian Grothoff
 */

#ifndef NEW_TESTING_API_HOSTS_H
#define NEW_TESTING_API_HOSTS_H

//#include "gnunet_testbed_service.h"
//#include "testbed_helper.h"
#include "testbed.h"


/**
 * Lookup a host by ID.
 *
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_lookup_by_id_ (uint32_t id);


/**
 * Create a host by ID; given this host handle, we could not
 * run peers at the host, but we can talk about the host
 * internally.
 *
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @param cfg the configuration to use as a template while starting a controller
 *          on this host.  Operation queue sizes specific to a host are also
 *          read from this configuration handle
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_by_id_ (uint32_t id,
                                   const struct GNUNET_CONFIGURATION_Handle
                                   *cfg);


/**
 * Obtain a host's unique global ID.
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return id global host ID assigned to the host (0 is
 *         'localhost', but then obviously not globally unique)
 */
uint32_t
GNUNET_TESTBED_host_get_id_ (const struct GNUNET_TESTBED_Host *host);


/**
 * Obtain the host's username
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return username to login to the host
 */
const char *
GNUNET_TESTBED_host_get_username_ (const struct GNUNET_TESTBED_Host *host);


/**
 * Obtain the host's ssh port
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return username to login to the host
 */
uint16_t
GNUNET_TESTBED_host_get_ssh_port_ (const struct GNUNET_TESTBED_Host *host);


/**
 * Obtain the host's configuration template
 *
 * @param host handle to the host
 * @return the host's configuration template
 */
const struct GNUNET_CONFIGURATION_Handle *
GNUNET_TESTBED_host_get_cfg_ (const struct GNUNET_TESTBED_Host *host);


/**
 * Function to replace host's configuration
 *
 * @param host the host handle
 * @param new_cfg the new configuration to replace the old one
 */
void
GNUNET_TESTBED_host_replace_cfg_ (struct GNUNET_TESTBED_Host *host,
                                  const struct GNUNET_CONFIGURATION_Handle *new_cfg);


/**
 * Marks a host as registered with a controller
 *
 * @param host the host to mark
 * @param controller the controller at which this host is registered
 */
void
GNUNET_TESTBED_mark_host_registered_at_ (struct GNUNET_TESTBED_Host *host,
                                         const struct GNUNET_TESTBED_Controller
                                         *controller);


/**
 * Unmarks a host registered at a controller
 *
 * @param host the host to unmark
 * @param controller the controller at which this host has to be unmarked
 */
void
GNUNET_TESTBED_deregister_host_at_ (struct GNUNET_TESTBED_Host *host,
                                    const struct GNUNET_TESTBED_Controller
                                    *const controller);


/**
 * Checks whether a host has been registered with the given controller
 *
 * @param host the host to check
 * @param controller the controller at which host's registration is checked
 * @return GNUNET_YES if registered; GNUNET_NO if not
 */
int
GNUNET_TESTBED_is_host_registered_ (const struct GNUNET_TESTBED_Host *host,
                                    const struct GNUNET_TESTBED_Controller
                                    *controller);


/**
 * Queues the given operation in the queue for parallel overlay connects of the
 * given host
 *
 * @param h the host handle
 * @param op the operation to queue in the given host's parally overlay connect
 *          queue
 */
void
GNUNET_TESTBED_host_queue_oc_ (struct GNUNET_TESTBED_Host *h,
                               struct GNUNET_TESTBED_Operation *op);


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
int
GNUNET_TESTBED_host_handle_addhostconfirm_ (struct GNUNET_TESTBED_Controller *c,
                                            const struct
                                            GNUNET_TESTBED_HostConfirmedMessage
                                            *msg);


/**
 * Sends termination signal to the controller's helper process
 *
 * @param cproc the handle to the controller's helper process
 */
void
GNUNET_TESTBED_controller_kill_ (struct GNUNET_TESTBED_ControllerProc *cproc);


/**
 * Cleans-up the controller's helper process handle
 *
 * @param cproc the handle to the controller's helper process
 */
void
GNUNET_TESTBED_controller_destroy_ (struct GNUNET_TESTBED_ControllerProc
                                    *cproc);


/**
 * Resolves the hostname of the host to an ip address
 *
 * @param host the host whose hostname is to be resolved
 */
void
GNUNET_TESTBED_host_resolve_ (struct GNUNET_TESTBED_Host *host);


#endif
/* end of testbed_api_hosts.h */
