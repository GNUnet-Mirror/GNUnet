#include <unistd.h>
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_testbed_service.h>
#include <gnunet/gnunet_dht_service.h>

/* Number of peers we want to start */
#define NUM_PEERS 20

struct GNUNET_TESTBED_Operation *dht_op;

struct GNUNET_DHT_Handle *dht_handle;

GNUNET_SCHEDULER_TaskIdentifier shutdown_tid;

struct MyContext
{
  int ht_len;
} ctxt;

static int result;

static void 
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_tid = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != dht_op)
  {  
    GNUNET_TESTBED_operation_done (dht_op); /* calls the dht_da() for closing
                                               down the connection */
    dht_op = NULL;
  }
  result = GNUNET_OK;
  GNUNET_SCHEDULER_shutdown (); /* Also kills the testbed */
}


static void
service_connect_comp (void *cls,
                      struct GNUNET_TESTBED_Operation *op,
                      void *ca_result,
                      const char *emsg)
{  
  /* Service to DHT successful; do something */

  GNUNET_SCHEDULER_cancel (shutdown_tid);
  GNUNET_SCHEDULER_add_delayed 
      (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10),
       &shutdown_task, NULL);
}


static void *
dht_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct MyContext *ctxt = cls;

  /* Use the provided configuration to connect to service */
  dht_handle = GNUNET_DHT_connect (cfg, ctxt->ht_len);  
  return dht_handle;
}


static void 
dht_da (void *cls, void *op_result)
{
  struct MyContext *ctxt = cls;
  
  /* Disconnect from DHT service */  
  GNUNET_DHT_disconnect ((struct GNUNET_DHT_Handle *) op_result);
  ctxt->ht_len = 0;
  dht_handle = NULL;
}

static void
test_master (void *cls, unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeeded,
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
