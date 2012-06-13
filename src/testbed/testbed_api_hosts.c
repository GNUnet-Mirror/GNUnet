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
 * @file testbed/testbed_api_hosts.c
 * @brief API for manipulating 'hosts' controlled by the GNUnet testing service;
 *        allows parsing hosts files, starting, stopping and communicating (via
 *        SSH/stdin/stdout) with the remote (or local) processes
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_container_lib.h"



/**
 * Opaque handle to a host running experiments managed by the testing framework.
 * The master process must be able to SSH to this host without password (via
 * ssh-agent).
 */
struct GNUNET_TESTBED_Host
{

  /**
   * The next pointer for DLL
   */
  struct GNUNET_TESTBED_Host *next;

  /**
   * The prev pointer for DLL
   */
  struct GNUNET_TESTBED_Host *prev;

  /**
   * The hostname of the host; NULL for localhost
   */
  const char *hostname;

  /**
   * The username to be used for SSH login
   */
  const char *username;

  /**
   * Global ID we use to refer to a host on the network
   */
  uint32_t unique_id;

  /**
   * The port which is to be used for SSH
   */
  uint16_t port;
};


/**
 * Head element in the list of available hosts
 */
static struct GNUNET_TESTBED_Host *host_list_head;

/**
 * Tail element in the list of available hosts
 */
static struct GNUNET_TESTBED_Host *host_list_tail;


/**
 * Lookup a host by ID.
 * 
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @return handle to the host, NULL if host not found
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_lookup_by_id_ (uint32_t id)
{
  struct GNUNET_TESTBED_Host *host;

  for (host = host_list_head; NULL != host; host=host->next)
    if (id == host->unique_id)
      return host;
  return NULL;
}


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
GNUNET_TESTBED_host_create_by_id_ (uint32_t id)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Obtain a host's unique global ID.
 * 
 * @param host handle to the host, NULL means 'localhost'
 * @return id global host ID assigned to the host (0 is
 *         'localhost', but then obviously not globally unique)
 */
uint32_t
GNUNET_TESTBED_host_get_id_ (const struct GNUNET_TESTBED_Host *host)
{
    return host->unique_id;
}


/**
 * Create a host to run peers and controllers on.
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
				     uint16_t port)
{
  struct GNUNET_TESTBED_Host *host;

  host = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Host));
  host->hostname = hostname;
  host->username = username;
  host->unique_id = id;
  host->port = (0 == port) ? 22 : port;
  GNUNET_CONTAINER_DLL_insert_tail (host_list_head, host_list_tail, host);
  return host;
}


/**
 * Create a host to run peers and controllers on.
 * 
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create (const char *hostname,
			    const char *username,
			    uint16_t port)
{
  static uint32_t uid_generator;

  if (NULL == hostname)
    return GNUNET_TESTBED_host_create_with_id_ (0, hostname, username, port);
  return GNUNET_TESTBED_host_create_with_id_ (++uid_generator, 
					      hostname, username,
					      port);
}


/**
 * Load a set of hosts from a configuration file.
 *
 * @param filename file with the host specification
 * @param hosts set to the hosts found in the file
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
GNUNET_TESTBED_hosts_load_from_file (const char *filename,
				     struct GNUNET_TESTBED_Host **hosts)
{
  GNUNET_break (0);
  return 0;
}


/**
 * Destroy a host handle.  Must only be called once everything
 * running on that host has been stopped.
 *
 * @param host handle to destroy
 */
void
GNUNET_TESTBED_host_destroy (struct GNUNET_TESTBED_Host *host)
{  
  GNUNET_CONTAINER_DLL_remove (host_list_head, host_list_tail, host);
  GNUNET_free (host);  
}


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
			  GNUNET_SERVER_MessageTokenizerCallback cb, void *cb_cls)
{
  /* FIXME: decide on the SSH command line, prepend it and
     run GNUNET_HELPER_start with the modified binary_name and binary_argv! */
  struct GNUNET_HELPER_Handle *h;
  char *const local_args[] = {NULL};
  char *port;
  char *dst;
  char *remote_args[] = {"ssh", "-p", port, "-q", dst,
                         "gnunet-service-testbed", NULL};

  if (0 == host->unique_id)
    return GNUNET_HELPER_start ("gnunet-service-testbed", local_args,
                                cb, cb_cls);
  else
  {
    GNUNET_asprintf (&port, "%d", host->port);
    GNUNET_asprintf (&dst, "%s@%s", host->hostname, host->username);
    h = GNUNET_HELPER_start ("ssh", remote_args, cb, cb_cls);
    GNUNET_free (port);         /* FIXME: Can we free them? */
    GNUNET_free (dst);
    return h;
  }
}


/* end of testbed_api_hosts.c */
