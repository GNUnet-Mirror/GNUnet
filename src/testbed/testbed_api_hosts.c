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
GNUNET_TESTBED_host_create_with_id (uint32_t id,
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
    return GNUNET_TESTBED_host_create_with_id (0, hostname, username, port);
  return GNUNET_TESTBED_host_create_with_id (++uid_generator, 
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
  // see testing_group.c, GNUNET_TESTING_hosts_load
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
 * Wrapper around GNUNET_HELPER_Handle
 */
struct GNUNET_TESTBED_HelperHandle
{
  /**
   * The process handle
   */
  struct GNUNET_OS_Process *process;

  /**
   * Pipe connecting to stdin of the process.
   */
  struct GNUNET_DISK_PipeHandle *cpipe;

  /**
   * The port number for ssh; used for helpers starting ssh
   */
  char *port;

  /**
   * The ssh destination string; used for helpers starting ssh
   */
  char *dst; 
};


/**
 * Run a given helper process at the given host.  Communication
 * with the helper will be via GNUnet messages on stdin/stdout.
 * Runs the process via 'ssh' at the specified host, or locally.
 * Essentially an SSH-wrapper around the 'gnunet_helper_lib.h' API.
 * 
 * @param host host to use, use "NULL" for localhost
 * @param binary_argv binary name and command-line arguments to give to the binary
 * @return handle to terminate the command, NULL on error
 */
struct GNUNET_TESTBED_HelperHandle *
GNUNET_TESTBED_host_run_ (const struct GNUNET_TESTBED_Host *host,
			  char *const binary_argv[])
{
  struct GNUNET_TESTBED_HelperHandle *h;
  unsigned int argc;

  argc = 0;
  while (NULL != binary_argv[argc]) 
    argc++;
  h = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_HelperHandle));
  h->cpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_YES, GNUNET_NO);
  if (0 == host->unique_id)
  {
    h->process = GNUNET_OS_start_process_vap (GNUNET_YES,
					      h->cpipe, NULL,
					      "gnunet-service-testbed", 
					      binary_argv);
  }
  else
  {    
    char *remote_args[argc + 6 + 1];
    unsigned int argp;

    GNUNET_asprintf (&h->port, "%d", host->port);
    GNUNET_asprintf (&h->dst, "%s@%s", host->hostname, host->username);
    argp = 0;
    remote_args[argp++] = "ssh";
    remote_args[argp++] = "-p";
    remote_args[argp++] = h->port;
    remote_args[argp++] = "-q";
    remote_args[argp++] = h->dst;
    remote_args[argp++] = "gnunet-service-testbed";
    while (NULL != binary_argv[argp-6])
    {
      remote_args[argp] = binary_argv[argp - 6];
      argp++;
    } 
    remote_args[argp++] = NULL;
    GNUNET_assert (argp == argc + 6 + 1);
    h->process = GNUNET_OS_start_process_vap (GNUNET_YES,
					      h->cpipe, NULL,
					      "ssh", 
					      remote_args);
  }
  if (NULL == h->process)
  {
    GNUNET_break (GNUNET_OK == GNUNET_DISK_pipe_close (h->cpipe));
    GNUNET_free_non_null (h->port);
    GNUNET_free_non_null (h->dst);
    GNUNET_free (h);
    return NULL;
  } 
  GNUNET_break (GNUNET_OK == GNUNET_DISK_pipe_close_end (h->cpipe, GNUNET_DISK_PIPE_END_READ));
  return h;
}


/**
 * Stops a helper in the HelperHandle using GNUNET_HELPER_stop
 *
 * @param handle the handle returned from GNUNET_TESTBED_host_start_
 */
void
GNUNET_TESTBED_host_stop_ (struct GNUNET_TESTBED_HelperHandle *handle)
{
  GNUNET_break (GNUNET_OK == GNUNET_DISK_pipe_close (handle->cpipe));
  GNUNET_break (0 == GNUNET_OS_process_kill (handle->process, SIGTERM));
  GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (handle->process));
  GNUNET_OS_process_destroy (handle->process);
  GNUNET_free_non_null (handle->port);
  GNUNET_free_non_null (handle->dst);
  GNUNET_free (handle);
}

/* end of testbed_api_hosts.c */
