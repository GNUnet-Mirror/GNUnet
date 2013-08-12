/*
     This file is part of GNUnet.
     (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file ats/perf_ats.c
 * @brief ats benchmark: start peers and modify preferences, monitor change over time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define TESTNAME_PREFIX "perf_ats_"
#define DEFAULT_NUM 5

/**
 * Information we track for a peer in the testbed.
 */
struct BenchmarkPeer
{
  /**
   * Handle with testbed.
   */
  struct GNUNET_TESTBED_Peer *peer;

  int no;

  struct GNUNET_PeerIdentity id;

  struct GNUNET_CORE_Handle *ch;

  /**
   * Testbed operation to connect to ATS performance service
   */
  struct GNUNET_TESTBED_Operation *ats_perf_op;

  /**
   * Testbed operation to get peer information
   */
  struct GNUNET_TESTBED_Operation *info_op;

  /**
   * Testbed operation to connect peers
   */
  struct GNUNET_TESTBED_Operation *connect_op;

  /**
   * Testbed operation to connect to core
   */
  struct GNUNET_TESTBED_Operation *core_op;

  /**
   * ATS performance handle
   */
  struct GNUNET_ATS_PerformanceHandle *p_handle;

  int core_connections;
};

struct BenchmarkPeer *ph;

struct BenchmarkState
{
	int connected_ATS_SRV;
	int connected_CORE_SRV;
	int connected_PEERS;
	int connected_CORE;

	int *core_connections;
};

static struct BenchmarkState state;

/**
 * Shutdown task
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

static int result;
static char *solver;
static char *preference;

static int peers;

static void
core_connect_completion_cb (void *cls,
			    struct GNUNET_TESTBED_Operation *op,
			    void *ca_result,
			    const char *emsg );

/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int c_p;
  shutdown_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Benchmarking done\n"));
  for (c_p = 0; c_p < peers; c_p++)
  {
  	if (NULL != ph[c_p].ats_perf_op)
  	{
  		GNUNET_TESTBED_operation_done (ph[c_p].ats_perf_op);
  		ph[c_p].ats_perf_op = NULL;
  	}

  	if (NULL != ph[c_p].core_op)
  	{
  		GNUNET_TESTBED_operation_done (ph[c_p].core_op);
  		ph[c_p].core_op = NULL;
  	}

  	if (NULL != ph[c_p].info_op)
  	{
  		GNUNET_break (0);
  		GNUNET_TESTBED_operation_done (ph[c_p].info_op);
  		ph[c_p].info_op = NULL;
  	}
  	if (NULL != ph[c_p].connect_op)
  	{
  		GNUNET_break (0);
  		GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Failed to connect peer 0 and %u\n"), c_p);
  		GNUNET_TESTBED_operation_done (ph[c_p].connect_op);
    	ph[c_p].connect_op = NULL;
    	result = 1;
  	}
  }

	GNUNET_SCHEDULER_shutdown();
}


static void
ats_performance_info_cb (void *cls,
			 const struct GNUNET_HELLO_Address *address,
			 int address_active,
			 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
			 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
			 const struct GNUNET_ATS_Information *ats,
			 uint32_t ats_count)
{
	struct BenchmarkPeer *p = cls;
	int c_a;
	char *peer_id;
	if (p != &ph[0])
		return; /* print only master peer */
	peer_id = GNUNET_strdup (GNUNET_i2s (&p->id));
	for (c_a = 0; c_a < ats_count; c_a++)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("%s: %s %s %u\n"), 
			    peer_id, 
			    GNUNET_i2s (&address->peer),
			    GNUNET_ATS_print_property_type(ntohl(ats[c_a].type)),
			    ntohl(ats[c_a].value));
	}
	GNUNET_free (peer_id);
}


static void 
do_benchmark ()
{
	if ((state.connected_ATS_SRV == GNUNET_NO) ||
			(state.connected_CORE_SRV == GNUNET_NO) ||
			(state.connected_PEERS == GNUNET_NO) ||
			(state.connected_CORE == GNUNET_NO))
		return;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
			_("BENCHMARKING\n"));
}


static void 
connect_completion_callback (void *cls,
			     struct GNUNET_TESTBED_Operation *op,
			     const char *emsg)
{
	static int connections = 0;
	struct BenchmarkPeer *p = cls;

	if (NULL == emsg)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				_("Connected peer 0 with peer %p\n"), p->peer);
	}
	else
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
				_("Failed to connect peer 0 with peer %p\n"), p->peer);
		GNUNET_break (0);
		if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
			GNUNET_SCHEDULER_cancel(shutdown_task);
		shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
	}
	GNUNET_TESTBED_operation_done(op);
	p->connect_op = NULL;
	connections++;
	if (connections == peers -1)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				"All peers connected, start benchmarking \n");
		 GNUNET_SCHEDULER_add_now (&do_benchmark, NULL);
		 state.connected_PEERS = GNUNET_YES;
	}
}


static void
do_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	int c_p;

	if ((state.connected_ATS_SRV == GNUNET_NO) ||
			(state.connected_CORE_SRV == GNUNET_NO))
		return;

	for (c_p = 1; c_p < peers; c_p ++)
	{
		ph[c_p].connect_op = GNUNET_TESTBED_overlay_connect( NULL,
				&connect_completion_callback, &ph[c_p], ph[0].peer, ph[c_p].peer);
		if (NULL == ph[c_p].connect_op)
		{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
					_("Could not connect peer 0 and peer %u\n"), c_p);
			GNUNET_break (0);
			if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
				GNUNET_SCHEDULER_cancel(shutdown_task);
			shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
			return;
		}
	}
}


/**
 * Controller event callback
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
                     const struct GNUNET_TESTBED_EventInformation *event)
{
	//struct BenchmarkPeer *p = cls;
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_CONNECT:
    break;
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    break;
  default:
    GNUNET_break (0);
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
}


/**
 * Called to open a connection to the peer's ATS performance
 *
 * @param cls peer context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
ats_perf_connect_adapter (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *peer = cls;

  peer->p_handle = GNUNET_ATS_performance_init (cfg, &ats_performance_info_cb, peer);
  if (NULL == peer->p_handle)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create ATS performance handle \n");
  return peer->p_handle;
}


/**
 * Called to disconnect from peer's statistics service
 *
 * @param cls peer context
 * @param op_result service handle returned from the connect adapter
 */
static void
ats_perf_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *peer = cls;

  GNUNET_ATS_performance_done(peer->p_handle);
  peer->p_handle = NULL;
}


/**
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void 
ats_connect_completion_cb (void *cls,
			   struct GNUNET_TESTBED_Operation *op,
			   void *ca_result,
			   const char *emsg )
{
	static int op_done = 0;
	if ((NULL != emsg) || (NULL == ca_result))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				_("Initialization failed, shutdown\n"));
		GNUNET_break (0);
		if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
			GNUNET_SCHEDULER_cancel(shutdown_task);
		shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
		return;
	}

	op_done ++;
	if (op_done ==  peers)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				_("Initialization done, connecting peers\n"));
		state.connected_ATS_SRV = GNUNET_YES;
		GNUNET_SCHEDULER_add_now (&do_connect, NULL);
	}
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_connect_cb (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  struct BenchmarkPeer *p = cls;
  char *id;

  p->core_connections ++;
  id = GNUNET_strdup (GNUNET_i2s (&p->id));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "%s connected to %s \n",
	      id, GNUNET_i2s (peer));
  if (p->core_connections == peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"%s connected all peers\n", 
		id);
  }
  if ((p->core_connections == peers) && (p == &ph[0]))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Master peer %s connected all peers on CORE level\n", id, GNUNET_i2s (peer));
    state.connected_CORE = GNUNET_YES;
    GNUNET_SCHEDULER_add_now (&do_benchmark, NULL);
  }
  GNUNET_free (id);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  struct BenchmarkPeer *p = cls;
  char *id;

  id = GNUNET_strdup (GNUNET_i2s (&p->id));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "%s disconnected from %s \n", id, GNUNET_i2s (peer));
  GNUNET_free (id);
}


/**
 * Called to open a connection to the peer's ATS performance
 *
 * @param cls peer context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
core_connect_adapter (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *peer = cls;

  peer->ch = GNUNET_CORE_connect(cfg, peer, NULL,
				 core_connect_cb,
				 core_disconnect_cb,
				 NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);
  if (NULL == peer->ch)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to create core connection \n");
  return peer->ch;
}


/**
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
core_connect_completion_cb (void *cls,
			    struct GNUNET_TESTBED_Operation *op,
			    void *ca_result,
			    const char *emsg )
{
	static int core_done = 0;
	if ((NULL != emsg) || (NULL == ca_result))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				_("Initialization failed, shutdown\n"));
		GNUNET_break (0);
		if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
			GNUNET_SCHEDULER_cancel(shutdown_task);
		shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL);
		return;
	}
	core_done ++;
	if (core_done == peers)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO,
				"Connected to all CORE services\n");
		state.connected_CORE_SRV = GNUNET_YES;
		GNUNET_SCHEDULER_add_now (&do_connect, NULL);
	}
}


/**
 * Called to disconnect from peer's statistics service
 *
 * @param cls peer context
 * @param op_result service handle returned from the connect adapter
 */
static void
core_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *peer = cls;

  GNUNET_CORE_disconnect (peer->ch);
  peer->ch = NULL;
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void
peerinformation_cb (void *cb_cls,
		    struct GNUNET_TESTBED_Operation *op,
		    const struct GNUNET_TESTBED_PeerInformation*pinfo,
		    const char *emsg)
{
  struct BenchmarkPeer *p = cb_cls;

  if (pinfo->pit == GNUNET_TESTBED_PIT_IDENTITY)
  {
    p->id = *pinfo->result.id;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"[%3u] Peers %s\n", 
		p->no, GNUNET_i2s (&p->id));
  }
  else
  {
    GNUNET_assert (0);
  }
  GNUNET_TESTBED_operation_done (op);
  p->info_op = NULL;
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers_ handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_main (void *cls, unsigned int num_peers,
	   struct GNUNET_TESTBED_Peer **peers_,
	   unsigned int links_succeeded,
	   unsigned int links_failed)
{
  int c_p;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Benchmarking solver `%s' on preference `%s' with %u peers\n"),
	      solver, preference, peers);

  shutdown_task = GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &do_shutdown, NULL);

  GNUNET_assert (NULL == cls);
  GNUNET_assert (peers == num_peers);
  GNUNET_assert (NULL != peers_);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Initializing... \n"));

  for (c_p = 0; c_p < num_peers; c_p++)
  {
    GNUNET_assert (NULL != peers_[c_p]);
    ph[c_p].no = c_p;
    /* Connect to ATS performance service */
    ph[c_p].peer = peers_[c_p];

    ph[c_p].info_op = GNUNET_TESTBED_peer_get_information (ph[c_p].peer,
							   GNUNET_TESTBED_PIT_IDENTITY, 
							   &peerinformation_cb, &ph[c_p]);

    ph[c_p].core_op = GNUNET_TESTBED_service_connect (NULL,
						      peers_[c_p], "ats",
						      core_connect_completion_cb, NULL,
						      &core_connect_adapter,
						      &core_disconnect_adapter,
						      &ph[c_p]);

    ph[c_p].ats_perf_op = GNUNET_TESTBED_service_connect (NULL,
							  peers_[c_p], "ats",
							  ats_connect_completion_cb, NULL,
							  &ats_perf_connect_adapter,
							  &ats_perf_disconnect_adapter,
							  &ph[c_p]);
  }
}


int
main (int argc, char *argv[])
{
  char *tmp;
  char *tmp_sep;
  char *test_name;
  char *conf_name;
  int c;
  
  peers = 0;
  result = 1;

  /* figure out testname */
  tmp = strstr (argv[0], TESTNAME_PREFIX);
  if (NULL == tmp)
  {
  	fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
  	return GNUNET_SYSERR;
  }
  tmp += strlen(TESTNAME_PREFIX);
  solver = GNUNET_strdup (tmp);
  tmp_sep = strchr (solver, '_');
  if (NULL == tmp_sep)
  {
  	fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
  	GNUNET_free (solver);
  	return GNUNET_SYSERR;
  }
  tmp_sep[0] = '\0';
  preference = GNUNET_strdup(tmp_sep + 1);

  GNUNET_asprintf(&conf_name, "%s%s_%s.conf", TESTNAME_PREFIX, solver, preference);
  GNUNET_asprintf(&test_name, "%s%s_%s", TESTNAME_PREFIX, solver, preference);

  for (c = 0; c < (argc -1); c++)
  {
  	if (0 == strcmp(argv[c], "-c"))
  		break;
  }
  if (c < argc-1)
  {
    if ((0L != (peers = strtol (argv[c + 1], NULL, 10))) && (peers >= 2))
      fprintf (stderr, "Starting %u peers\n", peers);
    else
    	peers = DEFAULT_NUM;
  }
  else
  	peers = DEFAULT_NUM;

  ph = GNUNET_malloc (peers * sizeof (struct BenchmarkPeer));
  state.connected_ATS_SRV = GNUNET_NO;
  state.connected_CORE_SRV = GNUNET_NO;
  state.connected_PEERS = GNUNET_NO;
  /* Start topology */
  uint64_t event_mask;
  result = GNUNET_SYSERR;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run (test_name,
                                  conf_name, peers,
                                  event_mask, &controller_event_cb, NULL,
                                  &test_main, NULL);

  GNUNET_free (solver);
  GNUNET_free (preference);
  GNUNET_free (conf_name);
  GNUNET_free (test_name);
  GNUNET_free (ph);

  return result;
}

/* end of file perf_ats.c */
