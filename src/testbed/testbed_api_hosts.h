/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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

#include "gnunet_testbed_service.h"
#include "gnunet_helper_lib.h"


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
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_by_id_ (uint32_t id);


/**
 * Create a host to run peers and controllers on.  This function is used
 * if a peer learns about a host via IPC between controllers (and thus 
 * some higher-level controller has already determined the unique IDs).
 * 
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_with_id_ (uint32_t id,
				     const char *hostname,
				     const char *username,
				     uint16_t port);


/**
 * Obtain a host's unique global ID.
 * 
 * @param host handle to the host, NULL means 'localhost'
 * @return id global host ID assigned to the host (0 is
 *         'localhost', but then obviously not globally unique)
 */
uint32_t
GNUNET_TESTBED_host_get_id_ (struct GNUNET_TESTBED_Host *host);


/**
 * Run a given helper process at the given host.  Communication
 * with the helper will be via GNUnet messages on stdin/stdout.
 * Runs the process via 'ssh' at the specified host, or locally.
 * Essentially an SSH-wrapper around the 'gnunet_helper_lib.h' API.
 * 
 * @param host host to use, use "NULL" for localhost
 * @param binary_argv binary name and command-line arguments to give to the binary
 * @param cb function to call for messages received from the binary
 * @param cb_cls closure for cb
 * @return handle to terminate the command, NULL on error
 */
struct GNUNET_HELPER_Handle *
GNUNET_TESTBED_host_run_ (struct GNUNET_TESTBED_Host *host,
			  char *const binary_argv[],
			  GNUNET_SERVER_MessageTokenizerCallback cb, void *cb_cls);

#endif
/* end of testbed_api_hosts.h */
