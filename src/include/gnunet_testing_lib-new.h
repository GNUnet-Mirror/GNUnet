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
 * @file include/gnunet_testing_lib-new.h
 * @brief convenience API for writing testcases for GNUnet;
 *        can start/stop one or more peers on a system;
 *        testing is responsible for managing private keys,
 *        ports and paths; it is a low-level library that
 *        does not support higher-level functions such as
 *        P2P connection, topology management or distributed
 *        testbed maintenance (those are in gnunet_testbed_service.h)
 * @author Christian Grothoff
 */

#ifndef GNUNET_TESTING_LIB_NEW_H
#define GNUNET_TESTING_LIB_NEW_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Handle for a system on which GNUnet peers are executed;
 * a system is used for reserving unique paths and ports.
 */
struct GNUNET_TESTING_System;


/**
 * Handle for a GNUnet peer controlled by testing.
 */
struct GNUNET_TESTING_Peer;


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
			      const char *controller);



/**
 * Free system resources.
 *
 * @param system system to be freed
 * @param remove_paths should the 'tmppath' and all subdirectories
 *        be removed (clean up on shutdown)?
 */
void
GNUNET_TESTING_system_destroy (struct GNUNET_TESTING_System *system,
			       int remove_paths);


/**
 * Testing includes a number of pre-created hostkeys for faster peer
 * startup. This function loads such keys into memory from a file.
 *
 * @param system the testing system handle
 * @param filename the path of the hostkeys file
 * @return GNUNET_OK on success; GNUNET_SYSERR on error
 */
int
GNUNET_TESTING_hostkeys_load (struct GNUNET_TESTING_System *system,
                              const char *filename);


/**
 * Function to remove the loaded hostkeys
 *
 * @param system the testing system handle
 */
void
GNUNET_TESTING_hostkeys_unload (struct GNUNET_TESTING_System *system);


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
 * @param system the testing system handle
 * @param key_number desired pre-created hostkey to obtain
 * @param id set to the peer's identity (hash of the public
 *        key; if NULL, GNUNET_SYSERR is returned immediately
 * @return GNUNET_SYSERR on error (not enough keys)
 */
int
GNUNET_TESTING_hostkey_get (const struct GNUNET_TESTING_System *system,
			    uint32_t key_number,
			    struct GNUNET_PeerIdentity *id);


/**
 * Reserve a TCP or UDP port for a peer.
 *
 * @param system system to use for reservation tracking
 * @param is_tcp GNUNET_YES for TCP ports, GNUNET_NO for UDP
 * @return 0 if no free port was available
 */
uint16_t 
GNUNET_TESTING_reserve_port (struct GNUNET_TESTING_System *system,
			     int is_tcp);


/**
 * Release reservation of a TCP or UDP port for a peer
 * (used during GNUNET_TESTING_peer_destroy).
 *
 * @param system system to use for reservation tracking
 * @param is_tcp GNUNET_YES for TCP ports, GNUNET_NO for UDP
 * @param port reserved port to release
 */
void
GNUNET_TESTING_release_port (struct GNUNET_TESTING_System *system,
			     int is_tcp,
			     uint16_t port);


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
 * @return GNUNET_OK on success, GNUNET_SYSERR on error - the configuration will
 *           be incomplete and should not be used there upon
 */
int
GNUNET_TESTING_configuration_create (struct GNUNET_TESTING_System *system,
				     struct GNUNET_CONFIGURATION_Handle *cfg);
// FIXME: add dual to 'release' ports again...


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
			       char **emsg);


/**
 * Start the peer. 
 *
 * @param peer peer to start
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (i.e. peer already running)
 */
int
GNUNET_TESTING_peer_start (struct GNUNET_TESTING_Peer *peer);


/**
 * Stop the peer. 
 *
 * @param peer peer to stop
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (i.e. peer not running)
 */
int
GNUNET_TESTING_peer_stop (struct GNUNET_TESTING_Peer *peer);


/**
 * Destroy the peer.  Releases resources locked during peer configuration.
 * If the peer is still running, it will be stopped AND a warning will be
 * printed (users of the API should stop the peer explicitly first).
 *
 * @param peer peer to destroy
 */
void
GNUNET_TESTING_peer_destroy (struct GNUNET_TESTING_Peer *peer);


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using 'GNUNET_TESTING_peer_run'.
 * 
 * @param cls closure
 * @param cfg configuration of the peer that was started
 */
typedef void (*GNUNET_TESTING_TestMain)(void *cls,
					const struct GNUNET_CONFIGURATION_Handle *cfg);


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
			 void *tm_cls);



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
			    void *tm_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
