/*
      This file is part of GNUnet
      Copyright (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_testing_lib.h
 * @brief convenience API for writing testcases for GNUnet;
 *        can start/stop one or more peers on a system;
 *        testing is responsible for managing private keys,
 *        ports and paths; it is a low-level library that
 *        does not support higher-level functions such as
 *        P2P connection, topology management or distributed
 *        testbed maintenance (those are in gnunet_testbed_service.h)
 * @author Christian Grothoff
 */

#ifndef GNUNET_TESTING_LIB_H
#define GNUNET_TESTING_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_arm_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Size of each hostkey in the hostkey file (in BYTES).
 */
#define GNUNET_TESTING_HOSTKEYFILESIZE sizeof (struct GNUNET_CRYPTO_EddsaPrivateKey)

/**
 * The environmental variable, if set, that dictates where testing should place
 * generated peer configurations
 */
#define GNUNET_TESTING_PREFIX "GNUNET_TESTING_PREFIX"


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
 * Specification of a service that is to be shared among peers
 */
struct GNUNET_TESTING_SharedService
{
  /**
   * The name of the service.
   */
  const char *service;

  /**
   * The configuration template for the service.  Cannot be NULL
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The number of peers which share an instance of the service.  0 for sharing
   * among all peers
   */
  unsigned int share;
};


/**
 * Create a system handle.  There must only be one system handle per operating
 * system.  Uses a default range for allowed ports.  Ports are still tested for
 * availability.
 *
 * @param testdir only the directory name without any path. This is used for all
 *          service homes; the directory will be created in a temporary location
 *          depending on the underlying OS.  This variable will be
 *          overridden with the value of the environmental variable
 *          GNUNET_TESTING_PREFIX, if it exists.
 * @param trusted_ip the ip address which will be set as TRUSTED HOST in all
 *          service configurations generated to allow control connections from
 *          this ip. This can either be a single ip address or a network address
 *          in CIDR notation.
 * @param hostname the hostname of the system we are using for testing; NULL for
 *          localhost
 * @param shared_services NULL terminated array describing services that are to
 *          be shared among peers
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTING_System *
GNUNET_TESTING_system_create (const char *testdir,
			      const char *trusted_ip,
			      const char *hostname,
                              const struct GNUNET_TESTING_SharedService *
                              shared_services);


/**
 * Create a system handle.  There must only be one system
 * handle per operating system.  Use this function directly
 * if multiple system objects are created for the same host
 * (only really useful when testing --- or to make the port
 * range configureable).
 *
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS.  This variable will be
 *          overridden with the value of the environmental variable
 *          GNUNET_TESTING_PREFIX, if it exists.
 * @param trusted_ip the ip address which will be set as TRUSTED HOST in all
 *          service configurations generated to allow control connections from
 *          this ip. This can either be a single ip address or a network address
 *          in CIDR notation.
 * @param hostname the hostname of the system we are using for testing; NULL for
 *          localhost
 * @param shared_services NULL terminated array describing services that are to
 *          be shared among peers
 * @param lowport lowest port number this system is allowed to allocate (inclusive)
 * @param highport highest port number this system is allowed to allocate (exclusive)
 * @return handle to this system, NULL on error
 */
struct GNUNET_TESTING_System *
GNUNET_TESTING_system_create_with_portrange (const char *testdir,
					     const char *trusted_ip,
					     const char *hostname,
                                             const struct
                                             GNUNET_TESTING_SharedService *
                                             shared_services,
					     uint16_t lowport,
					     uint16_t highport);


/**
 * Free system resources.
 *
 * @param system system to be freed
 * @param remove_paths should the 'testdir' and all subdirectories
 *        be removed (clean up on shutdown)?
 */
void
GNUNET_TESTING_system_destroy (struct GNUNET_TESTING_System *system,
			       int remove_paths);


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
 * @return NULL on error (not enough keys)
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_TESTING_hostkey_get (const struct GNUNET_TESTING_System *system,
			    uint32_t key_number,
			    struct GNUNET_PeerIdentity *id);


/**
 * Reserve a port for a peer.
 *
 * @param system system to use for reservation tracking
 * @return 0 if no free port was available
 */
uint16_t
GNUNET_TESTING_reserve_port (struct GNUNET_TESTING_System *system);


/**
 * Release reservation of a TCP or UDP port for a peer
 * (used during GNUNET_TESTING_peer_destroy).
 *
 * @param system system to use for reservation tracking
 * @param port reserved port to release
 */
void
GNUNET_TESTING_release_port (struct GNUNET_TESTING_System *system,
			     uint16_t port);


/**
 * Create a new configuration using the given configuration as a template;
 * ports and paths will be modified to select available ports on the local
 * system. The default configuration will be available in PATHS section under
 * the option DEFAULTCONFIG after the call. SERVICE_HOME is also set in PATHS
 * section to the temporary directory specific to this configuration. If we run
 * out of "*port" numbers, return SYSERR.
 *
 * This is primarily a helper function used internally
 * by 'GNUNET_TESTING_peer_configure'.
 *
 * @param system system to use to coordinate resource usage
 * @param cfg template configuration to update
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error - the configuration will
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
 * @param emsg set to freshly allocated error message (set to NULL on success),
 *          can be NULL
 * @return handle to the peer, NULL on error
 */
struct GNUNET_TESTING_Peer *
GNUNET_TESTING_peer_configure (struct GNUNET_TESTING_System *system,
			       struct GNUNET_CONFIGURATION_Handle *cfg,
			       uint32_t key_number,
			       struct GNUNET_PeerIdentity *id,
			       char **emsg);


/**
 * Obtain the peer identity from a peer handle.
 *
 * @param peer peer handle for which we want the peer's identity
 * @param id identifier for the daemon, will be set
 */
void
GNUNET_TESTING_peer_get_identity (struct GNUNET_TESTING_Peer *peer,
				  struct GNUNET_PeerIdentity *id);


/**
 * Start the peer.
 *
 * @param peer peer to start
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error (i.e. peer already running)
 */
int
GNUNET_TESTING_peer_start (struct GNUNET_TESTING_Peer *peer);


/**
 * Stop the peer. This call is blocking as it kills the peer's main ARM process
 * by sending a SIGTERM and waits on it.  For asynchronous shutdown of peer, see
 * GNUNET_TESTING_peer_stop_async().
 *
 * @param peer peer to stop
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error (i.e. peer not running)
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
 * Sends SIGTERM to the peer's main process
 *
 * @param peer the handle to the peer
 * @return #GNUNET_OK if successful; #GNUNET_SYSERR if the main process is NULL
 *           or upon any error while sending SIGTERM
 */
int
GNUNET_TESTING_peer_kill (struct GNUNET_TESTING_Peer *peer);


/**
 * Waits for a peer to terminate. The peer's main process will also be destroyed.
 *
 * @param peer the handle to the peer
 * @return #GNUNET_OK if successful; #GNUNET_SYSERR if the main process is NULL
 *           or upon any error while waiting
 */
int
GNUNET_TESTING_peer_wait (struct GNUNET_TESTING_Peer *peer);


/**
 * Callback to inform whether the peer is running or stopped.
 *
 * @param cls the closure given to GNUNET_TESTING_peer_stop_async()
 * @param peer the respective peer whose status is being reported
 * @param success #GNUNET_YES if the peer is stopped; #GNUNET_SYSERR upon any
 *          error
 */
typedef void
(*GNUNET_TESTING_PeerStopCallback) (void *cls,
                                    struct GNUNET_TESTING_Peer *peer,
                                    int success);


/**
 * Stop a peer asynchronously using ARM API.  Peer's shutdown is signaled
 * through the GNUNET_TESTING_PeerStopCallback().
 *
 * @param peer the peer to stop
 * @param cb the callback to signal peer shutdown
 * @param cb_cls closure for the above callback
 * @return GNUNET_OK upon successfully giving the request to the ARM API (this
 *           does not mean that the peer is successfully stopped); GNUNET_SYSERR
 *           upon any error.
 */
int
GNUNET_TESTING_peer_stop_async (struct GNUNET_TESTING_Peer *peer,
                                GNUNET_TESTING_PeerStopCallback cb,
                                void *cb_cls);


/**
 * Cancel a previous asynchronous peer stop request.
 * GNUNET_TESTING_peer_stop_async() should have been called before on the given
 * peer.  It is an error to call this function if the peer stop callback was
 * already called
 *
 * @param peer the peer on which GNUNET_TESTING_peer_stop_async() was called
 *          before.
 */
void
GNUNET_TESTING_peer_stop_async_cancel (struct GNUNET_TESTING_Peer *peer);


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using #GNUNET_TESTING_peer_run().
 *
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
typedef void
(*GNUNET_TESTING_TestMain) (void *cls,
                            const struct GNUNET_CONFIGURATION_Handle *cfg,
                            struct GNUNET_TESTING_Peer *peer);


/**
 * Start a single peer and run a test using the testing library.
 * Starts a peer using the given configuration and then invokes the
 * given callback.  This function ALSO initializes the scheduler loop
 * and should thus be called directly from "main".  The testcase
 * should self-terminate by invoking 'GNUNET_SCHEDULER_shutdown'.
 *
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS
 * @param cfgfilename name of the configuration file to use;
 *         use NULL to only run with defaults
 * @param tm main function of the testcase
 * @param tm_cls closure for 'tm'
 * @return 0 on success, 1 on error
 */
int
GNUNET_TESTING_peer_run (const char *testdir,
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
 * @param testdir only the directory name without any path. This is used for
 *          all service homes; the directory will be created in a temporary
 *          location depending on the underlying OS
 * @param service_name name of the service to run
 * @param cfgfilename name of the configuration file to use;
 *         use NULL to only run with defaults
 * @param tm main function of the testcase
 * @param tm_cls closure for @a tm
 * @return 0 on success, 1 on error
 */
int
GNUNET_TESTING_service_run (const char *testdir,
			    const char *service_name,
			    const char *cfgfilename,
			    GNUNET_TESTING_TestMain tm,
			    void *tm_cls);


/**
 * Sometimes we use the binary name to determine which specific
 * test to run.  In those cases, the string after the last "_"
 * in 'argv[0]' specifies a string that determines the configuration
 * file or plugin to use.
 *
 * This function returns the respective substring, taking care
 * of issues such as binaries ending in '.exe' on W32.
 *
 * @param argv0 the name of the binary
 * @return string between the last '_' and the '.exe' (or the end of the string),
 *         NULL if argv0 has no '_'
 */
char *
GNUNET_TESTING_get_testname_from_underscore (const char *argv0);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
