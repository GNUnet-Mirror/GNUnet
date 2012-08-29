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
  GNUNET_log_from (kind, "testbed-api-testbed", __VA_ARGS__)

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
  struct GNUNET_TESTBED_RunHandle *rh;

  /**
   * Closure
   */
  void *cls;  
  
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
 * Testbed Run Handle
 */
struct GNUNET_TESTBED_RunHandle
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
   * Array of peers which we create
   */
  struct GNUNET_TESTBED_Peer **peers;
  
  /**
   * The event mask for the controller
   */
  uint64_t event_mask;

  /**
   * Current peer count for an operation; Set this to 0 and increment for each
   * successful operation on a peer
   */
  unsigned int peer_count;
  
  /**
   * number of peers to start
   */
  unsigned int num_peers;

  /**
   * Are we cleaning up?
   */
  int in_shutdown;  

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
 * Task for starting peers
 *
 * @param cls the RunHandle
 * @param tc the task context from scheduler
 */
static void
start_peers_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTBED_RunHandle *rh = cls;
  struct DLLOperation *dll_op;  
  unsigned int peer;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting Peers\n");  
  for (peer = 0; peer < rh->num_peers; peer++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->op = GNUNET_TESTBED_peer_start (rh->peers[peer]);
    dll_op->cls = rh->peers[peer];    
    GNUNET_CONTAINER_DLL_insert_tail (rh->dll_op_head, rh->dll_op_tail, dll_op);
  }
  rh->peer_count = 0;  
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
  struct GNUNET_TESTBED_RunHandle *rh;
  
  GNUNET_assert (NULL != dll_op);  
  rh = dll_op->rh;
  GNUNET_assert (NULL != rh);
  GNUNET_CONTAINER_DLL_remove (rh->dll_op_head, rh->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op); 
  GNUNET_free (dll_op);
  if (NULL == peer)
  {
    if (NULL != emsg)
      LOG (GNUNET_ERROR_TYPE_WARNING, "Error while creating a peer: %s\n",
           emsg);
    /* FIXME: GNUNET_TESTBED_shutdown_run()? */
    return;
  }
  rh->peers[rh->peer_count] = peer;
  rh->peer_count++;
  if (rh->peer_count < rh->num_peers)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Required peers created successfully\n");  
  GNUNET_SCHEDULER_add_now (&start_peers_task, rh);
}


/**
 * Assuming all peers have been destroyed cleanup run handle
 *
 * @param cls the run handle
 * @param tc the task context from scheduler
 */
static void
shutdown_run_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTBED_RunHandle *rh = cls;
  struct DLLOperation *dll_op;  
  
  GNUNET_assert (NULL == rh->peers);
  if (NULL != rh->c)
    GNUNET_TESTBED_controller_disconnect (rh->c);
  if (NULL != rh->cproc)
    GNUNET_TESTBED_controller_stop (rh->cproc);
  if (NULL != rh->h)
    GNUNET_TESTBED_host_destroy (rh->h);
  if (NULL != rh->dll_op_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Some operations are still pending. Cancelling them\n"));
    while (NULL != (dll_op = rh->dll_op_head))
    {
      GNUNET_TESTBED_operation_cancel (dll_op->op);
      GNUNET_CONTAINER_DLL_remove (rh->dll_op_head, rh->dll_op_tail, dll_op);
      GNUNET_free (dll_op);
    }
  }
  GNUNET_free (rh);
}


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void 
event_cb (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  struct GNUNET_TESTBED_RunHandle *rh = cls;
  struct DLLOperation *dll_op;
  
  if ((GNUNET_YES == rh->in_shutdown) && 
      (GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type))
  {
    for (dll_op = rh->dll_op_head; NULL != dll_op; dll_op = dll_op->next)
    {
      if (event->details.operation_finished.operation == dll_op->op)
        break;
    }
    if (NULL == dll_op)
      goto call_cc;
    GNUNET_CONTAINER_DLL_remove (rh->dll_op_head, rh->dll_op_tail, dll_op);
    GNUNET_TESTBED_operation_done (dll_op->op);
    GNUNET_free (dll_op);
    rh->peer_count++;
    if (rh->peer_count < rh->num_peers)
      return;
    GNUNET_free (rh->peers);
    rh->peers = NULL;    
    LOG (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully destroyed\n");
    GNUNET_SCHEDULER_add_now (&shutdown_run_task, rh);
    return;    
  }

 call_cc:
  rh->cc (rh->cc_cls, event);
  if (GNUNET_TESTBED_ET_PEER_START != event->type)
    return;
  for (dll_op = rh->dll_op_head; NULL != dll_op; dll_op = dll_op->next)
    if ((NULL != dll_op->cls) && 
        (event->details.peer_start.peer == dll_op->cls))
      break;
  GNUNET_assert (NULL != dll_op);
  GNUNET_CONTAINER_DLL_remove (rh->dll_op_head, rh->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_free (dll_op);
  rh->peer_count++;
  if (rh->peer_count < rh->num_peers)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers started successfully\n");  
  GNUNET_SCHEDULER_add_continuation (rh->master, rh->master_cls,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);  
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
  struct GNUNET_TESTBED_RunHandle *rh = cls;
  struct DLLOperation *dll_op;
  unsigned int peer;
  
  if (status != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Testbed startup failed\n");
    return;
  }
  rh->c = GNUNET_TESTBED_controller_connect (cfg, rh->h, rh->event_mask,
                                             &event_cb, rh);
  rh->peers = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer *)
                             * rh->num_peers);
  GNUNET_assert (NULL != rh->c);
  rh->peer_count = 0; 
  for (peer = 0; peer < rh->num_peers; peer++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->rh = rh;    
    dll_op->op = GNUNET_TESTBED_peer_create (rh->c, rh->h, cfg, peer_create_cb,
					     dll_op);
    GNUNET_CONTAINER_DLL_insert_tail (rh->dll_op_head, rh->dll_op_tail, dll_op);    
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
 * @return the handle for this testbed run
 */
struct GNUNET_TESTBED_RunHandle *
GNUNET_TESTBED_run (const char *host_filename,
		    const struct GNUNET_CONFIGURATION_Handle *cfg,
		    unsigned int num_peers,
		    uint64_t event_mask,
		    GNUNET_TESTBED_ControllerCallback cc,
		    void *cc_cls,
		    GNUNET_SCHEDULER_Task master,
		    void *master_cls)
{
  struct GNUNET_TESTBED_RunHandle *rh;

  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);  
  rh = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_RunHandle));
  GNUNET_break (NULL == host_filename); /* Currently we do not support host
					   files */
  host_filename = NULL;
  rh->h = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  GNUNET_assert (NULL != rh->h);
  rh->cproc = GNUNET_TESTBED_controller_start ("127.0.0.1", rh->h, cfg,
					       &controller_status_cb, rh);
  GNUNET_assert (NULL != rh->cproc);  
  rh->num_peers = num_peers;
  rh->event_mask = event_mask;
  rh->cc = cc;
  rh->cc_cls = cc_cls;
  rh->master = master;
  rh->master_cls = master_cls;
  rh->in_shutdown = GNUNET_NO;  
  return rh;  
}


/**
 * Stops the testbed run and releases any used resources
 *
 * @param rh the tesbed run handle
 */
void
GNUNET_TESTBED_shutdown_run (struct GNUNET_TESTBED_RunHandle *rh)
{  
  struct DLLOperation *dll_op;  
  unsigned int peer;
  
  rh->in_shutdown = GNUNET_YES;
  if (NULL != rh->c)
  {
    if (NULL != rh->peers)
    {
      rh->peer_count = 0;      
      for (peer = 0; peer < rh->num_peers; peer++)
      {
        dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
        dll_op->op = GNUNET_TESTBED_peer_destroy (rh->peers[peer]);
        GNUNET_CONTAINER_DLL_insert_tail (rh->dll_op_head, rh->dll_op_tail,
                                          dll_op);        
      }      
      return;
    }
  }
  GNUNET_SCHEDULER_add_now (&shutdown_run_task, rh);  
}

/* end of testbed_api_testbed.c */
