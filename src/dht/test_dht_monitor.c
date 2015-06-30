/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file dht/test_dht_monitor.c
 * @brief Test for the dht monitoring API; checks that we receive "some" monitor events
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_dht_service.h"
#include "dht_test_lib.h"


/**
 * How long do we run the test at most?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

/**
 * How often do we run the PUTs?
 */
#define PUT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


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
 * Return value from 'main'.
 */
static int ok;

/**
 * Head of list of active GET operations.
 */
static struct GetOperation *get_head;

/**
 * Tail of list of active GET operations.
 */
static struct GetOperation *get_tail;

/**
 * Array of the testbed's peers.
 */
static struct GNUNET_TESTBED_Peer **my_peers;

/**
 * Number of peers to run.
 */
static unsigned int NUM_PEERS = 3;

/**
 * Task called to disconnect peers.
 */
static struct GNUNET_SCHEDULER_Task * timeout_task;

/**
 * Task to do DHT_puts
 */
static struct GNUNET_SCHEDULER_Task * put_task;

static struct GNUNET_DHT_MonitorHandle **monitors;

static unsigned int monitor_counter;


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
  unsigned int i;
  struct GetOperation *get_op;

  ok = (monitor_counter > NUM_PEERS) ? 0 : 2;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Received %u monitor events\n",
	      monitor_counter);
  while (NULL != (get_op = get_tail))
  {
    GNUNET_DHT_get_stop (get_op->get);
    GNUNET_CONTAINER_DLL_remove (get_head,
				 get_tail,
				 get_op);
    GNUNET_free (get_op);
  }
  for (i=0;i<NUM_PEERS;i++)
    GNUNET_DHT_monitor_stop (monitors[i]);
  GNUNET_free (monitors);
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
 * Callback called on each GET request going through the DHT.
 * Prints the info about the intercepted packet and increments a counter.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
static void
monitor_get_cb (void *cls,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                uint32_t hop_count,
                uint32_t desired_replication_level,
                unsigned int path_length,
                const struct GNUNET_PeerIdentity *path,
                const struct GNUNET_HashCode * key)
{
  unsigned int i;

  i = (unsigned int) (long) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%u got a GET message for key %s\n",
              i,
	      GNUNET_h2s (key));
  monitor_counter++;
}


/**
 * Callback called on each PUT request going through the DHT.
 * Prints the info about the intercepted packet and increments a counter.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in data.
 */
static void
monitor_put_cb (void *cls,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                uint32_t hop_count,
                uint32_t desired_replication_level,
                unsigned int path_length,
                const struct GNUNET_PeerIdentity *path,
                struct GNUNET_TIME_Absolute exp,
                const struct GNUNET_HashCode * key,
                const void *data,
                size_t size)
{
  unsigned int i;

  i = (unsigned int) (long) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%u got a PUT message for key %s with %u bytes\n",
              i,
	      GNUNET_h2s (key), size);
  monitor_counter++;
}


/**
 * Callback called on each GET reply going through the DHT.
 * Prints the info about the intercepted packet and increments a counter.
 *
 * @param cls Closure.
 * @param type The type of data in the result.
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in data.
 */
static void
monitor_res_cb (void *cls,
                enum GNUNET_BLOCK_Type type,
                const struct GNUNET_PeerIdentity *get_path,
                unsigned int get_path_length,
                const struct GNUNET_PeerIdentity *put_path,
                unsigned int put_path_length,
                struct GNUNET_TIME_Absolute exp,
                const struct GNUNET_HashCode * key,
                const void *data,
                size_t size)
{
  unsigned int i;

  i = (unsigned int) (long) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%u got a REPLY message for key %s with %u bytes\n",
              i,
	      GNUNET_h2s (key), size);
  monitor_counter++;
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
  my_peers = peers;
  monitors = GNUNET_malloc (num_peers * sizeof (struct GNUNET_DHT_MonitorHandle *));
  for (i = 0; i < num_peers; i++)
    monitors[i] = GNUNET_DHT_monitor_start (dhts[i],
					    GNUNET_BLOCK_TYPE_ANY,
					    NULL,
					    &monitor_get_cb,
					    &monitor_res_cb,
					    &monitor_put_cb,
					    (void *)(long)i);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Peers setup, starting test\n");
  put_task = GNUNET_SCHEDULER_add_now (&do_puts, dhts);
  for (i=0;i<num_peers;i++)
  {
    GNUNET_CRYPTO_hash (&i, sizeof (i), &key);
    for (j=0;j<num_peers;j++)
    {
      get_op = GNUNET_new (struct GetOperation);
      GNUNET_CONTAINER_DLL_insert (get_head,
				   get_tail,
				   get_op);
      get_op->get = GNUNET_DHT_get_start (dhts[j],
					  GNUNET_BLOCK_TYPE_TEST, /* type */
					  &key,      /*key to search */
					  4U,     /* replication level */
					  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
					  NULL,        /* xquery */
					  0,      /* xquery bits */
					  &dht_get_handler, get_op);
    }
  }
  timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
					       &shutdown_task, ctx);
}


/**
 * Main: start test
 */
int
main (int xargc, char *xargv[])
{
  GNUNET_DHT_TEST_run ("test-dht-monitor",
		       "test_dht_monitor.conf",
		       NUM_PEERS,
		       &run, NULL);
  return ok;
}


/* end of test_dht_monitor.c */
