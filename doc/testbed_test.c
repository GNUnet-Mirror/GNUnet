#include <unistd.h>
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_testbed_service.h>
#include <gnunet/gnunet_dht_service.h>

/* Number of peers we want to start */
#define NUM_PEERS 20

static struct GNUNET_TESTBED_Operation *dht_op;

static struct GNUNET_DHT_Handle *dht_handle;

static struct GNUNET_SCHEDULER_Task * shutdown_tid;


/**
 * Closure to 'dht_ca' and 'dht_da' DHT adapters.
 */
struct MyContext
{
  /**
   * Argument we pass to GNUNET_DHT_connect.
   */
  int ht_len;
} ctxt;


/**
 * Global result for testcase.
 */
static int result;


/**
 * Function run on CTRL-C or shutdown (i.e. success/timeout/etc.).
 * Cleans up.
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_tid = NULL;
  if (NULL != dht_op)
  {
    GNUNET_TESTBED_operation_done (dht_op); /* indirectly calls the dht_da() for closing
                                               down the connection to the DHT */
    dht_op = NULL;
    dht_handle = NULL;
  }
  result = GNUNET_OK;
  GNUNET_SCHEDULER_shutdown (); /* Also kills the testbed */
}


/**
 * This is where the test logic should be, at least that
 * part of it that uses the DHT of peer "0".
 *
 * @param cls closure, for the example: NULL
 * @param op should be equal to "dht_op"
 * @param ca_result result of the connect operation, the
 *        connection to the DHT service
 * @param emsg error message, if testbed somehow failed to
 *        connect to the DHT.
 */
static void
service_connect_comp (void *cls,
                      struct GNUNET_TESTBED_Operation *op,
                      void *ca_result,
                      const char *emsg)
{
  GNUNET_assert (op == dht_op);
  dht_handle = ca_result;
  /* Service to DHT successful; here we'd usually do something
     with the DHT (ok, if successful) */

  /* for now, just indiscriminately terminate after 10s */
  GNUNET_SCHEDULER_cancel (shutdown_tid);
  shutdown_tid = GNUNET_SCHEDULER_add_delayed
      (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
       &shutdown_task, NULL);
}


/**
 * Testbed has provided us with the configuration to access one
 * of the peers and it is time to do "some" connect operation to
 * "some" subsystem of the peer.  For this example, we connect
 * to the DHT subsystem.  Testbed doesn't know which subsystem,
 * so we need these adapters to do the actual connecting (and
 * possibly pass additional options to the subsystem connect
 * function, such as the "ht_len" argument for the DHT).
 *
 * @param cls closure
 * @param cfg peer configuration (here: peer[0]
 * @return NULL on error, otherwise some handle to access the
 *         subsystem
 */
static void *
dht_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct MyContext *ctxt = cls;

  /* Use the provided configuration to connect to service */
  dht_handle = GNUNET_DHT_connect (cfg, ctxt->ht_len);
  return dht_handle;
}


/**
 * Dual of 'dht_ca' to perform the 'disconnect'/cleanup operation
 * once we no longer need to access this subsystem.
 *
 * @param cls closure
 * @param op_result whatever we returned from 'dht_ca'
 */
static void
dht_da (void *cls, void *op_result)
{
  struct MyContext *ctxt = cls;

  /* Disconnect from DHT service */
  GNUNET_DHT_disconnect ((struct GNUNET_DHT_Handle *) op_result);
  dht_handle = NULL;
}


/**
 * Main function inovked from TESTBED once all of the
 * peers are up and running.  This one then connects
 * just to the DHT service of peer 0.
 *
 * @param cls closure
 * @param h the run handle
 * @param peers started peers for the test
 * @param num_peers size of the 'peers' array
 * @param links_succeeded number of links between peers that were created
 * @param links_failed number of links testbed was unable to establish
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  /* Testbed is ready with peers running and connected in a pre-defined overlay
     topology  */

  /* do something */
  ctxt.ht_len = 10;

  /* connect to a peers service */
  dht_op = GNUNET_TESTBED_service_connect
      (NULL,                    /* Closure for operation */
       peers[0],                /* The peer whose service to connect to */
       "dht",                   /* The name of the service */
       service_connect_comp,    /* callback to call after a handle to service
                                   is opened */
       NULL,                    /* closure for the above callback */
       dht_ca,                  /* callback to call with peer's configuration;
                                   this should open the needed service connection */
       dht_da,                  /* callback to be called when closing the
                                   opened service connection */
       &ctxt);                  /* closure for the above two callbacks */
  shutdown_tid = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                               &shutdown_task, NULL);
}


int
main (int argc, char **argv)
{
  int ret;

  result = GNUNET_SYSERR;
  ret = GNUNET_TESTBED_test_run
      ("awesome-test",  /* test case name */
       "template.conf", /* template configuration */
       NUM_PEERS,       /* number of peers to start */
       0LL, /* Event mask - set to 0 for no event notifications */
       NULL, /* Controller event callback */
       NULL, /* Closure for controller event callback */
       &test_master, /* continuation callback to be called when testbed setup is
                        complete */
       NULL); /* Closure for the test_master callback */
  if ( (GNUNET_OK != ret) || (GNUNET_OK != result) )
    return 1;
  return 0;
}
