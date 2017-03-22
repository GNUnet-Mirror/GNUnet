#include <unistd.h>
#include <gnunet/platform.h>
#include <gnunet/gnunet_util_lib.h>
#include <gnunet/gnunet_testbed_service.h>
#include <gnunet/gnunet_dht_service.h>

#define NUM_PEERS 20

static struct GNUNET_TESTBED_Operation *dht_op;

static struct GNUNET_DHT_Handle *dht_handle;


struct MyContext
{
  int ht_len;
} ctxt;


static int result;


static void
shutdown_task (void *cls)
{
  if (NULL != dht_op)
  {
    GNUNET_TESTBED_operation_done (dht_op);
    dht_op = NULL;
    dht_handle = NULL;
  }
  result = GNUNET_OK;
}


static void
service_connect_comp (void *cls,
                      struct GNUNET_TESTBED_Operation *op,
                      void *ca_result,
                      const char *emsg)
{
  GNUNET_assert (op == dht_op);
  dht_handle = ca_result;
  // Do work here...
  GNUNET_SCHEDULER_shutdown ();
}


static void *
dht_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct MyContext *ctxt = cls;

  dht_handle = GNUNET_DHT_connect (cfg, ctxt->ht_len);
  return dht_handle;
}


static void
dht_da (void *cls, void *op_result)
{
  struct MyContext *ctxt = cls;

  GNUNET_DHT_disconnect ((struct GNUNET_DHT_Handle *) op_result);
  dht_handle = NULL;
}


static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  ctxt.ht_len = 10;
  dht_op = GNUNET_TESTBED_service_connect
      (NULL, peers[0], "dht",
       &service_connect_comp, NULL,
       &dht_ca, &dht_da, &ctxt);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


int
main (int argc, char **argv)
{
  int ret;

  result = GNUNET_SYSERR;
  ret = GNUNET_TESTBED_test_run
      ("awesome-test", "template.conf",
       NUM_PEERS, 0LL,
       NULL, NULL, &test_master, NULL);
  if ( (GNUNET_OK != ret) || (GNUNET_OK != result) )
    return 1;
  return 0;
}
