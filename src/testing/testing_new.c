/*
      This file is part of GNUnet
      (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file testing/testing_new.c
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop a peer/service
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases (or internal use of the testbed).
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_network_lib.h"
#include "gnunet_testing_lib-new.h"

#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "gnunettestingnew", __VA_ARGS__)

/**
 * AI_NUMERICSERV not defined in windows. A hack to keep on going.
 */
#if !defined (AI_NUMERICSERV)
#define AI_NUMERICSERV 0
#endif

/**
 * Handle for a system on which GNUnet peers are executed;
 * a system is used for reserving unique paths and ports.
 */
struct GNUNET_TESTING_System
{
  /**
   * Prefix (i.e. "/tmp/gnunet-testing/") we prepend to each
   * SERVICEHOME. 
   */
  char *tmppath;

  /**
   * The hostname of the controller
   */
  char *controller;

  /**
   * Bitmap where each TCP port that has already been reserved for
   * some GNUnet peer is recorded.  Note that we additionally need to
   * test if a port is already in use by non-GNUnet components before
   * assigning it to a peer/service.  If we detect that a port is
   * already in use, we also mark it in this bitmap.  So all the bits
   * that are zero merely indicate ports that MIGHT be available for
   * peers.
   */
  uint32_t reserved_tcp_ports[65536 / 32];

  /**
   * Bitmap where each UDP port that has already been reserved for
   * some GNUnet peer is recorded.  Note that we additionally need to
   * test if a port is already in use by non-GNUnet components before
   * assigning it to a peer/service.  If we detect that a port is
   * already in use, we also mark it in this bitmap.  So all the bits
   * that are zero merely indicate ports that MIGHT be available for
   * peers.
   */
  uint32_t reserved_udp_ports[65536 / 32];

  /**
   * Counter we use to make service home paths unique on this system;
   * the full path consists of the tmppath and this number.  Each
   * UNIXPATH for a peer is also modified to include the respective
   * path counter to ensure uniqueness.  This field is incremented
   * by one for each configured peer.  Even if peers are destroyed,
   * we never re-use path counters.
   */
  uint32_t path_counter;

  /**
   * Last used port number
   */
  
};


/**
 * Handle for a GNUnet peer controlled by testing.
 */
struct GNUNET_TESTING_Peer
{

  /**
   * Path to the configuration file for this peer.
   */
  char *cfgfile;

  /**
   * Binary to be executed during 'GNUNET_TESTING_peer_start'.
   * Typically 'gnunet-service-arm' (but can be set to a 
   * specific service by 'GNUNET_TESTING_service_run' if
   * necessary).
   */ 
  char *main_binary;
  
  /**
   * Handle to the running binary of the service, NULL if the
   * peer/service is currently not running.
   */
  struct GNUNET_OS_Process *main_process;

};


/**
 * Lowest port used for GNUnet testing.  Should be high enough to not
 * conflict with other applications running on the hosts but be low
 * enough to not conflict with client-ports (typically starting around
 * 32k).
 */
#define LOW_PORT 12000


/**
 * Highest port used for GNUnet testing.  Should be low enough to not
 * conflict with the port range for "local" ports (client apps; see
 * /proc/sys/net/ipv4/ip_local_port_range on Linux for example).
 */
#define HIGH_PORT 56000


/**
 * Create a system handle.  There must only be one system
 * handle per operating system.
 *
 * @param tmppath prefix path to use for all service homes
 * @param controller hostname of the controlling host, 
 *        service configurations are modified to allow 
 *        control connections from this host; can be NULL
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTING_System *
GNUNET_TESTING_system_create (const char *tmppath,
			      const char *controller)
{
  struct GNUNET_TESTING_System *system;

  if (NULL == tmppath)
    return NULL;
  system = GNUNET_malloc (sizeof (struct GNUNET_TESTING_System));
  system->tmppath = GNUNET_strdup (tmppath);
  if (NULL != controller)
    system->controller = GNUNET_strdup (controller);
  return system;
}


/**
 * Free system resources.
 *
 * @param system system to be freed
 * @param remove_paths should the 'tmppath' and all subdirectories
 *        be removed (clean up on shutdown)?
 */
void
GNUNET_TESTING_system_destroy (struct GNUNET_TESTING_System *system,
			       int remove_paths)
{
  GNUNET_assert (NULL != system);
  if (GNUNET_YES == remove_paths)
    GNUNET_DISK_directory_remove (system->tmppath);
  GNUNET_free (system->tmppath);
  GNUNET_free_non_null (system->controller);
  GNUNET_free (system);
}


/**
 * Reserve a TCP or UDP port for a peer.
 *
 * @param system system to use for reservation tracking
 * @param is_tcp GNUNET_YES for TCP ports, GNUNET_NO for UDP
 * @return 0 if no free port was available
 */
// static 
uint16_t 
reserve_port (struct GNUNET_TESTING_System *system,
	      int is_tcp)
{
  struct GNUNET_NETWORK_Handle *socket;
  struct addrinfo hint;
  struct addrinfo *ret;
  uint32_t *port_buckets;
  char *open_port_str;
  int bind_status;
  uint32_t xor_image;
  uint16_t index;
  uint16_t open_port;
  uint16_t pos;

  hint.ai_family = AF_UNSPEC;	/* IPv4 and IPv6 */
  hint.ai_socktype = (GNUNET_YES == is_tcp)? SOCK_STREAM : SOCK_DGRAM;
  hint.ai_protocol = 0;
  hint.ai_addrlen = 0;
  hint.ai_addr = NULL;
  hint.ai_canonname = NULL;
  hint.ai_next = NULL;
  hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;	/* Wild card address */
  port_buckets = (GNUNET_YES == is_tcp) ?
    system->reserved_tcp_ports : system->reserved_udp_ports;
  for (index = (LOW_PORT / 32) + 1; index < (HIGH_PORT / 32); index++)
  {
    xor_image = (UINT32_MAX ^ port_buckets[index]);
    if (0 == xor_image)        /* Ports in the bucket are full */
      continue;
    pos = 0;
    while (pos < 32)
    {
      if (0 == ((xor_image >> pos) & 1U))
      {
        pos++;
        continue;
      }
      open_port = (index * 32) + pos;
      GNUNET_asprintf (&open_port_str, "%u", open_port);
      ret = NULL;
      GNUNET_assert (0 == getaddrinfo (NULL, open_port_str, &hint, &ret));
      GNUNET_free (open_port_str);  
      socket = GNUNET_NETWORK_socket_create (ret->ai_family,
                                             (GNUNET_YES == is_tcp) ?
                                             SOCK_STREAM : SOCK_DGRAM,
                                             0);
      GNUNET_assert (NULL != socket);
      bind_status = GNUNET_NETWORK_socket_bind (socket,
                                                ret->ai_addr,
                                                ret->ai_addrlen);
      freeaddrinfo (ret);
      GNUNET_NETWORK_socket_close (socket);
      socket = NULL;
      port_buckets[index] |= (1U << pos); /* Set the port bit */
      if (GNUNET_OK == bind_status)
	return open_port;
      pos++;
    }
  }
  return 0;
}


/**
 * Release reservation of a TCP or UDP port for a peer
 * (used during GNUNET_TESTING_peer_destroy).
 *
 * @param system system to use for reservation tracking
 * @param is_tcp GNUNET_YES for TCP ports, GNUNET_NO for UDP
 * @param port reserved port to release
 */
// static 
void
release_port (struct GNUNET_TESTING_System *system,
	      int is_tcp,
	      uint16_t port)
{
  uint32_t *port_buckets;
  uint16_t bucket;
  uint16_t pos;

  GNUNET_assert (NULL != system);
  port_buckets = (GNUNET_YES == is_tcp) ?
    system->reserved_tcp_ports : system->reserved_udp_ports;
  bucket = port / 32;
  pos = port % 32;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Releasing port %u\n", port);
  if (0 == (port_buckets[bucket] & (1U << pos)))
  {
    GNUNET_break(0); /* Port was not reserved by us using reserve_port() */
    return;
  }
  port_buckets[bucket] &= ~(1U << pos);
}


/**
 * Reserve a SERVICEHOME path for a peer.
 *
 * @param system system to use for reservation tracking
 * @return NULL on error, otherwise fresh unique path to use
 *         as the servicehome for the peer
 */
// static 
char *
reserve_path (struct GNUNET_TESTING_System *system)
{
  GNUNET_break (0);
  return NULL;
}	      


/**
 * Testing includes a number of pre-created hostkeys for
 * faster peer startup.  This function can be used to
 * access the n-th key of those pre-created hostkeys; note
 * that these keys are ONLY useful for testing and not
 * secure as the private keys are part of the public 
 * GNUnet source code.
 *
 * This is primarily a helper function used internally
 * by 'GNUNET_TESTING_peer_configure'.
 *
 * @param key_number desired pre-created hostkey to obtain
 * @param filename where to store the hostkey (file will
 *        be created, or overwritten if it already exists)
 * @param id set to the peer's identity (hash of the public
 *        key; can be NULL
 * @return GNUNET_SYSERR on error (not enough keys)
 */
int
GNUNET_TESTING_hostkey_get (uint32_t key_number,
			    const char *filename,
			    struct GNUNET_PeerIdentity *id)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Create a new configuration using the given configuration
 * as a template; ports and paths will be modified to select
 * available ports on the local system.  If we run
 * out of "*port" numbers, return SYSERR.
 *
 * This is primarily a helper function used internally
 * by 'GNUNET_TESTING_peer_configure'.
 *
 * @param system system to use to coordinate resource usage
 * @param cfg template configuration to update
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_TESTING_configuration_create (struct GNUNET_TESTING_System *system,
				     struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Configure a GNUnet peer.  GNUnet must be installed on the local
 * system and available in the PATH. 
 *
 * @param system system to use to coordinate resource usage
 * @param cfg configuration to use; will be UPDATED (to reflect needed
 *            changes in port numbers and paths)
 * @param key_number number of the hostkey to use for the peer
 * @param id identifier for the daemon, will be set, can be NULL
 * @param emsg set to error message (set to NULL on success), can be NULL
 * @return handle to the peer, NULL on error
 */
struct GNUNET_TESTING_Peer *
GNUNET_TESTING_peer_configure (struct GNUNET_TESTING_System *system,
			       struct GNUNET_CONFIGURATION_Handle *cfg,
			       uint32_t key_number,
			       struct GNUNET_PeerIdentity *id,
			       char **emsg)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Start the peer. 
 *
 * @param peer peer to start
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (i.e. peer already running)
 */
int
GNUNET_TESTING_peer_start (struct GNUNET_TESTING_Peer *peer)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Stop the peer. 
 *
 * @param peer peer to stop
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (i.e. peer not running)
 */
int
GNUNET_TESTING_peer_stop (struct GNUNET_TESTING_Peer *peer)
{
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Destroy the peer.  Releases resources locked during peer configuration.
 * If the peer is still running, it will be stopped AND a warning will be
 * printed (users of the API should stop the peer explicitly first).
 *
 * @param peer peer to destroy
 */
void
GNUNET_TESTING_peer_destroy (struct GNUNET_TESTING_Peer *peer)
{
  GNUNET_break (0);
}



/**
 * Start a single peer and run a test using the testing library.
 * Starts a peer using the given configuration and then invokes the
 * given callback.  This function ALSO initializes the scheduler loop
 * and should thus be called directly from "main".  The testcase
 * should self-terminate by invoking 'GNUNET_SCHEDULER_shutdown'.
 *
 * @param tmppath path for storing temporary data for the test
 * @param cfgfilename name of the configuration file to use;
 *         use NULL to only run with defaults
 * @param tm main function of the testcase
 * @param tm_cls closure for 'tm'
 * @return 0 on success, 1 on error
 */
int
GNUNET_TESTING_peer_run (const char *tmppath,
			 const char *cfgfilename,
			 GNUNET_TESTING_TestMain tm,
			 void *tm_cls)
{
  return GNUNET_TESTING_service_run (tmppath, "arm",
				     cfgfilename, tm, tm_cls);
}



/**
 * Start a single service (no ARM, except of course if the given
 * service name is 'arm') and run a test using the testing library.
 * Starts a service using the given configuration and then invokes the
 * given callback.  This function ALSO initializes the scheduler loop
 * and should thus be called directly from "main".  The testcase
 * should self-terminate by invoking 'GNUNET_SCHEDULER_shutdown'.
 *
 * This function is useful if the testcase is for a single service
 * and if that service doesn't itself depend on other services.
 *
 * @param tmppath path for storing temporary data for the test
 * @param service_name name of the service to run
 * @param cfgfilename name of the configuration file to use;
 *         use NULL to only run with defaults
 * @param tm main function of the testcase
 * @param tm_cls closure for 'tm'
 * @return 0 on success, 1 on error
 */
int
GNUNET_TESTING_service_run (const char *tmppath,
			    const char *service_name,
			    const char *cfgfilename,
			    GNUNET_TESTING_TestMain tm,
			    void *tm_cls)
{
  GNUNET_break (0);
  return 1;
}



/* end of testing_new.c */
