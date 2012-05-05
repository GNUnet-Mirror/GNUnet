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
#include "gnunet_testing_lib-new.h"


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
  GNUNET_break (0);
  return NULL;
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
  GNUNET_break (0);
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
  GNUNET_break (0);
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
  GNUNET_break (0);
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
