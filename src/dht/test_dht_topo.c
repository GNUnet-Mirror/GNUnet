/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dht/test_dht_topo.c
 * @author Christian Grothoff
 * @brief Test for the dht service: store and retrieve in various topologies.
 * Each peer stores a value from the DHT and then each peer tries to get each
 * value from each other peer.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dht_service.h"
#include "dht_test_lib.h"

/**
 * Number of peers to run.
 */
#define NUM_PEERS 5

/**
 * How long until we give up on fetching the data?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * How frequently do we execute the PUTs?
 */
#define PUT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Information we keep for each GET operation.
 */
struct GetOperation 
{
  /**
   * DLL.
   */
  struct GetOperation *next;

  /**
   * DLL.
   */
  struct GetOperation *prev;

  /**
   * Handle for the operation.
   */
  struct GNUNET_DHT_GetHandle *get;

};


/**
 * Result of the test.
 */
static int ok = 1;

/**
 * Task to do DHT_puts
 */
static GNUNET_SCHEDULER_TaskIdentifier put_task;

/**
 * Task to time out / regular shutdown.
 */
static GNUNET_SCHEDULER_TaskIdentifier timeout_task;

/**
 * Head of list of active GET operations.
 */
static struct GetOperation *get_head;

/**
 * Tail of list of active GET operations.
 */
static struct GetOperation *get_tail;


/**
 * Task run on success or timeout to clean up.
 * Terminates active get operations and shuts down
 * the testbed.
 *
 * @param cls the 'struct GNUNET_DHT_TestContext'
 * @param tc scheduler context
 */ 
static void
shutdown_task (void *cls, 
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DHT_TEST_Context *ctx = cls;
  struct GetOperation *get_op;

  while (NULL != (get_op = get_tail))
  {
    GNUNET_DHT_get_stop (get_op->get);
    GNUNET_CONTAINER_DLL_remove (get_head,
				 get_tail,
				 get_op);
    GNUNET_free (get_op);
  }
  GNUNET_SCHEDULER_cancel (put_task);
  GNUNET_DHT_TEST_cleanup (ctx);
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure with our 'struct GetOperation'
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 * @param get_path_length number of entries in get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 * @param put_path_length number of entries in get_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
dht_get_handler (void *cls, struct GNUNET_TIME_Absolute exp,
		 const struct GNUNET_HashCode * key,
		 const struct GNUNET_PeerIdentity *get_path,
		 unsigned int get_path_length,
		 const struct GNUNET_PeerIdentity *put_path,
		 unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
		 size_t size, const void *data)
{
  struct GetOperation *get_op = cls;
  struct GNUNET_HashCode want;
  struct GNUNET_DHT_TestContext *ctx;

  if (sizeof (struct GNUNET_HashCode) != size)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CRYPTO_hash (key, sizeof (*key), &want);
  if (0 != memcmp (&want, data, sizeof (want)))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Get successful\n");
#if 0
  {
    int i;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "PATH: (get %u, put %u)\n",
		get_path_length, put_path_length);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  LOCAL\n");
    for (i = get_path_length - 1; i >= 0; i--)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
		  GNUNET_i2s (&get_path[i]));
    for (i = put_path_length - 1; i >= 0; i--)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
		  GNUNET_i2s (&put_path[i]));
  }
#endif
  GNUNET_DHT_get_stop (get_op->get);
  GNUNET_CONTAINER_DLL_remove (get_head,
			       get_tail,
			       get_op);
  GNUNET_free (get_op);
  if (NULL != get_head)
    return;
  /* all DHT GET operations successful; terminate! */
  ok = 0;
  ctx = GNUNET_SCHEDULER_cancel (timeout_task);
  timeout_task = GNUNET_SCHEDULER_add_now (&shutdown_task, ctx);
}


/**
 * Task to put the id of each peer into the DHT.
 * 
 * @param cls array with NUM_PEERS DHT handles
 * @param tc Task context
 */
static void
do_puts (void *cls,
	 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DHT_Handle **hs = cls;
  struct GNUNET_HashCode key;
  struct GNUNET_HashCode value;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Putting values into DHT\n");
  for (i = 0; i < NUM_PEERS; i++)
  {
    GNUNET_CRYPTO_hash (&i, sizeof (i), &key);
    GNUNET_CRYPTO_hash (&key, sizeof (key), &value);
    GNUNET_DHT_put (hs[i], &key, 10U,
                    GNUNET_DHT_RO_RECORD_ROUTE |
                    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                    GNUNET_BLOCK_TYPE_TEST, 
		    sizeof (value), &value, 
		    GNUNET_TIME_UNIT_FOREVER_ABS,
                    GNUNET_TIME_UNIT_FOREVER_REL, 
		    NULL, NULL);
  }
  put_task = GNUNET_SCHEDULER_add_delayed (PUT_FREQUENCY, 
					   &do_puts, hs);
}


/**
 * Main function of the test.
 *
 * @param cls closure (NULL)
 * @param ctx argument to give to GNUNET_DHT_TEST_cleanup on test end
 * @param num_peers number of peers that are running
 * @param peers array of peers
 * @param dhts handle to each of the DHTs of the peers
 */
static void
run (void *cls,
     struct GNUNET_DHT_TEST_Context *ctx,
     unsigned int num_peers,
     struct GNUNET_TESTBED_Peer **peers,
     struct GNUNET_DHT_Handle **dhts)
{
  unsigned int i;
  unsigned int j;
  struct GNUNET_HashCode key;
  struct GetOperation *get_op;

  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Peers setup, starting test\n");
  /* FIXME: once testbed is finished, this call should
     no longer be needed */
  GNUNET_TESTBED_overlay_configure_topology (NULL, 
					     num_peers,
					     peers,
					     GNUNET_TESTBED_TOPOLOGY_LINE,
					     GNUNET_TESTBED_TOPOLOGY_OPTION_END);

  put_task = GNUNET_SCHEDULER_add_now (&do_puts, dhts);
  for (i=0;i<num_peers;i++)
  {
    GNUNET_CRYPTO_hash (&i, sizeof (i), &key);
    for (j=0;j<num_peers;j++)
    {
      get_op = GNUNET_malloc (sizeof (struct GetOperation));
      GNUNET_CONTAINER_DLL_insert (get_head,
				   get_tail,
				   get_op);
      get_op->get = GNUNET_DHT_get_start (dhts[j], 
					  GNUNET_BLOCK_TYPE_TEST, /* type */
					  &key,      /*key to search */
					  4U,     /* replication level */
					  GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
					  NULL,        /* xquery */
					  0,      /* xquery bits */
					  &dht_get_handler, get_op);
    }
  }
  timeout_task = GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, 
					       &shutdown_task, ctx);
}


/**
 * Main: start test
 */
int
main (int xargc, char *xargv[])
{
  const char *cfg_filename;
  const char *test_name;
  
  if (NULL != strstr (xargv[0], "test_dht_2dtorus"))
  {
    cfg_filename = "test_dht_2dtorus.conf";
    test_name = "test-dht-2dtorus";
  }
  else if (NULL != strstr (xargv[0], "test_dht_line"))
  {
    cfg_filename = "test_dht_line.conf"; 
    test_name = "test-dht-line";
  }
  else
  {
    GNUNET_break (0);
    return 1;
  }
  GNUNET_DHT_TEST_run (test_name,
		       cfg_filename,
		       NUM_PEERS,
		       &run, NULL);
  return ok;
}

/* end of test_dht_topo.c */
