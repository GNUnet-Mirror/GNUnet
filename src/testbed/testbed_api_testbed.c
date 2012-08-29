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
 * @file testbed/testbed_api_testbed.c
 * @brief high-level testbed management
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_testbed_service.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)					\
  GNUNET_log_from (kind, "testbed-api", __VA_ARGS__)

/**
 * Opaque handle to an abstract operation to be executed by the testing framework.
 */
struct GNUNET_TESTBED_Testbed
{
  // FIXME!
};


/**
 * DLL of operations
 */
struct DLLOperation
{
  /**
   * The testbed operation handle
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Context information for GNUNET_TESTBED_run()
   */
  struct RunContext *rc;  
  
  /**
   * The next pointer for DLL
   */
  struct DLLOperation *next;
  
  /**
   * The prev pointer for DLL
   */
  struct DLLOperation *prev;
};


/**
 * DLL of peers
 */
struct DLLPeer
{
  /**
   * Handle to testbed peer
   */
  struct GNUNET_TESTBED_Peer *peer;
  
  /**
   * The next pointer for DLL
   */
  struct DLLPeer *next;
  
  /**
   * The pre pointer for DLL
   */
  struct DLLPeer *prev;  
};


/**
 * Context information for GNUNET_TESTBED_run()
 */
struct RunContext
{
  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *c;

  /**
   * Handle to the host on which the controller runs
   */
  struct GNUNET_TESTBED_Host *h;

  /**
   * The handle to the controller process
   */
  struct GNUNET_TESTBED_ControllerProc *cproc;

  /**
   * The callback to use as controller callback
   */
  GNUNET_TESTBED_ControllerCallback cc;
  
  /**
   * The pointer to the controller callback
   */
  void *cc_cls;
  
  /**
   * Master task to call when testbed initialization is done
   */
  GNUNET_SCHEDULER_Task master;
  
  /**
   * The closure for the master task
   */
  void *master_cls;

  /**
   * The head element of DLL operations
   */
  struct DLLOperation *dll_op_head;
  
  /**
   * The tail element of DLL operations
   */
  struct DLLOperation *dll_op_tail;

  /**
   * The head element of DLL peers
   */
  struct DLLPeer *dll_peer_head;
  
  /**
   * The tail element of DLL peers
   */
  struct DLLPeer *dll_peer_tail;  
  
  /**
   * The event mask for the controller
   */
  uint64_t event_mask;
  
  /**
   * number of peers to start
   */
  unsigned int num_peers;  

};




/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param peer_cfg peer configuration template to use
 * @param underlay_topology underlay topology to create
 * @param va topology-specific options
 * @return handle to the testbed
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create_va (struct GNUNET_TESTBED_Controller *controller,
				  unsigned int num_hosts,
				  struct GNUNET_TESTBED_Host **hosts,
				  unsigned int num_peers,
				  const struct GNUNET_CONFIGURATION_Handle *peer_cfg,
				  enum GNUNET_TESTBED_TopologyOption underlay_topology,
				  va_list va)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param peer_cfg peer configuration template to use
 * @param underlay_topology underlay topology to create
 * @param ... topology-specific options
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create (struct GNUNET_TESTBED_Controller *controller,
		       unsigned int num_hosts,
		       struct GNUNET_TESTBED_Host **hosts,
		       unsigned int num_peers,
		       const struct GNUNET_CONFIGURATION_Handle *peer_cfg,
		       enum GNUNET_TESTBED_TopologyOption underlay_topology,
		       ...)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Destroy a testbed.  Stops all running peers and then
 * destroys all peers.  Does NOT destroy the master controller.
 *
 * @param testbed testbed to destroy
 */
void
GNUNET_TESTBED_destroy (struct GNUNET_TESTBED_Testbed *testbed)
{
  GNUNET_break (0);
}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
static void 
peer_create_cb (void *cls, struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{ 
  struct DLLOperation *dll_op = cls;
  struct RunContext *rc;
  struct DLLPeer *dll_peer;
  
  GNUNET_assert (NULL != dll_op);  
  rc = dll_op->rc;
  GNUNET_assert (NULL != rc);
  GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op); 
  GNUNET_free (dll_op);
  if (NULL == peer)
  {
    if (NULL != emsg)
      LOG (GNUNET_ERROR_TYPE_WARNING, "Error while creating a peer: %s\n", emsg);
    return;    
  }  
  dll_peer = GNUNET_malloc (sizeof (struct DLLPeer));
  dll_peer->peer = peer;
  GNUNET_CONTAINER_DLL_insert_tail (rc->dll_peer_head, rc->dll_peer_tail,
				    dll_peer);
}



/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void 
controller_status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
		      int status)
{  
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  unsigned int peer;
  
  if (status != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Testbed startup failed\n");
    return;
  }
  rc->c = GNUNET_TESTBED_controller_connect (cfg, rc->h, rc->event_mask, rc->cc,
					     rc->cc_cls);
  GNUNET_assert (NULL != rc->c);  
  for (peer = 0; peer < rc->num_peers; peer++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->rc = rc;    
    dll_op->op = GNUNET_TESTBED_peer_create (rc->c, rc->h, cfg, peer_create_cb,
					     dll_op);
    GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail, dll_op);    
  }  
}


/**
 * Convenience method for running a testbed with
 * a single call.  Underlay and overlay topology
 * are configured using the "UNDERLAY" and "OVERLAY"
 * options in the "[testbed]" section of the configuration\
 * (with possible options given in "UNDERLAY_XXX" and/or
 * "OVERLAY_XXX").
 *
 * The testbed is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".
 *
 * @param host_filename name of the file with the 'hosts', NULL
 *        to run everything on 'localhost'
 * @param cfg configuration to use (for testbed, controller and peers)
 * @param num_peers number of peers to start; FIXME: maybe put that ALSO into cfg?
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) || ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @param master task to run once the testbed is ready
 * @param master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_run (const char *host_filename,
		    const struct GNUNET_CONFIGURATION_Handle *cfg,
		    unsigned int num_peers,
		    uint64_t event_mask,
		    GNUNET_TESTBED_ControllerCallback cc,
		    void *cc_cls,
		    GNUNET_SCHEDULER_Task master,
		    void *master_cls)
{
  struct RunContext *rc;

  rc = GNUNET_malloc (sizeof (struct RunContext));  
  GNUNET_break (NULL != host_filename); /* Currently we do not support host
					   files */
  host_filename = NULL;
  rc->h = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  GNUNET_assert (NULL != rc->h);
  rc->cproc = GNUNET_TESTBED_controller_start ("127.0.0.1", rc->h, cfg,
					       &controller_status_cb, rc);
  GNUNET_assert (NULL != rc->cproc);  
  rc->num_peers = num_peers;
  rc->event_mask = event_mask;
  rc->cc = cc;
  rc->cc_cls = cc_cls;
  rc->master = master;
  rc->master_cls = master_cls;  
}



/* end of testbed_api_testbed.c */
