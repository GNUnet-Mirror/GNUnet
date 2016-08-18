/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * @file transport-testing-main.c
 * @brief convenience main function for tests
 * @author Christian Grothoff
 */
#include "transport-testing.h"


/**
 * Closure for #connect_cb.
 */
struct GNUNET_TRANSPORT_TESTING_ConnectRequestList
{
  /**
   * Stored in a DLL.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *next;

  /**
   * Stored in a DLL.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *prev;

  /**
   * Overall context we are in.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

  /**
   * Connect request this is about.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectRequest *cr;

  /**
   * Peer being connected.
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p1;

  /**
   * Peer being connected.
   */
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p2;

};


/**
 * Shutdown function for the test. Stops all peers.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *`
 */
static void
do_shutdown (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = cls;
  struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *crl;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testcase shutting down\n");
  if (NULL != ccc->shutdown_task)
    ccc->shutdown_task (ccc->shutdown_task_cls);
  if (NULL != ccc->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ccc->timeout_task);
    ccc->timeout_task = NULL;
  }
  if (NULL != ccc->connect_task)
  {
    GNUNET_SCHEDULER_cancel (ccc->connect_task);
    ccc->connect_task = NULL;
  }
  while (NULL != (crl = ccc->crl_head))
  {
    GNUNET_CONTAINER_DLL_remove (ccc->crl_head,
                                 ccc->crl_tail,
                                 crl);
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (crl->cr);
    GNUNET_free (crl);
  }
  for (unsigned int i=0;i<ccc->num_peers;i++)
  {
    if (NULL != ccc->p[i])
    {
      GNUNET_TRANSPORT_TESTING_stop_peer (ccc->p[i]);
      ccc->p[i] = NULL;
    }
  }
}


/**
 * Testcase hit timeout, shut it down with error.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *`
 */
static void
do_timeout (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = cls;

  ccc->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Testcase timed out\n");
  ccc->global_ret = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Internal data structure.   Closure for
 * #connect_cb, #disconnect_cb, #my_nc and #start_cb.
 * Allows us to identify which peer this is about.
 */
struct GNUNET_TRANSPORT_TESTING_InternalPeerContext
{
  /**
   * Overall context of the callback.
   */
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc;

  /**
   * Offset of the peer this is about.
   */
  unsigned int off;
};


/**
 * Information tracked per connected peer.
 */ 
struct ConnectPairInfo
{
  /**
   * Peer this is about.
   */
  const struct GNUNET_PeerIdentity *sender;

  /**
   * Information about the receiving peer.
   */
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ipi;
};


/**
 * Function called when we connected two peers.  Once we have gotten
 * to the clique, launch test-specific logic.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *`
 */
static void
connect_cb (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *crl = cls;
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = crl->ccc;

  GNUNET_CONTAINER_DLL_remove (ccc->crl_head,
                               ccc->crl_tail,
                               crl);
  {
    char *p1_c = GNUNET_strdup (GNUNET_i2s (&crl->p1->id));

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Peers connected: %u (%s) <-> %u (%s)\n",
                crl->p1->no,
                p1_c,
                crl->p2->no,
                GNUNET_i2s (&crl->p2->id));
    GNUNET_free (p1_c);
    GNUNET_free (crl);
  }
  if (NULL == ccc->crl_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All connections UP, launching custom test logic.\n");
    GNUNET_SCHEDULER_add_now (ccc->connect_continuation,
                              ccc->connect_continuation_cls);
  }
}


/**
 * Find peer by peer ID.
 *
 * @param ccc context to search
 * @param peer peer to look for
 * @return NULL if @a peer was not found
 */
struct GNUNET_TRANSPORT_TESTING_PeerContext *
GNUNET_TRANSPORT_TESTING_find_peer (struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc,
                                    const struct GNUNET_PeerIdentity *peer)
{
  for (unsigned int i=0;i<ccc->num_peers;i++)
    if ( (NULL != ccc->p[i]) &&
         (0 == memcmp (peer,
                       &ccc->p[i]->id,
                       sizeof (*peer))) )
      return ccc->p[i];
  return NULL;
}


/**
 * Wrapper around peers connecting.  Calls client's nc function.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *`
 * @param peer peer we got connected to
 * @param mq message queue for transmissions to @a peer
 * @return closure for message handlers
 */
static void *
my_nc (void *cls,
       const struct GNUNET_PeerIdentity *peer,
       struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ipi = cls;
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = ipi->ccc;
  struct ConnectPairInfo *cpi;
  
  if (NULL != ccc->nc)
    ccc->nc (ccc->cls,
             ccc->p[ipi->off],
             peer);
  cpi = GNUNET_new (struct ConnectPairInfo);
  cpi->ipi = ipi;
  cpi->sender = peer; /* valid until disconnect */
  return cpi;
}


/**
 * Wrapper around peers disconnecting.  Calls client's nd function.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *`
 * @param peer peer we got disconnected from
 * @param custom_cls return value from @my_nc
 */
static void
my_nd (void *cls,
       const struct GNUNET_PeerIdentity *peer,
       void *custom_cls)
{
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ipi = cls;
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = ipi->ccc;
  struct ConnectPairInfo *cpi = custom_cls;
  
  if (NULL != ccc->nd)
    ccc->nd (ccc->cls,
             ccc->p[ipi->off],
             peer);
  GNUNET_free (cpi);
}


/**
 * Wrapper around receiving data.  Calls client's rec function.
 *
 * @param cls our `struct ConnectPairInfo *`
 * @param message message we received
 * @return #GNUNET_OK (all messages are fine)
 */
static int
check_test (void *cls,
	    const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  return GNUNET_OK;
}


/**
 * Wrapper around receiving data.  Calls client's rec function.
 *
 * @param cls our `struct ConnectPairInfo *`
 * @param message message we received
 */
static void
handle_test (void *cls,
	     const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  struct ConnectPairInfo *cpi = cls;
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ipi = cpi->ipi;
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = ipi->ccc;

  if (NULL != ccc->rec)
    ccc->rec (ccc->cls,
              ccc->p[ipi->off],
              cpi->sender,
              message);
}


/**
 * Wrapper around receiving data.  Calls client's rec function.
 *
 * @param cls our `struct ConnectPairInfo *`
 * @param message message we received
 * @return #GNUNET_OK (all messages are fine)
 */
static int
check_test2 (void *cls,
	     const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  return GNUNET_OK;
}


/**
 * Wrapper around receiving data.  Calls client's rec function.
 *
 * @param cls our `struct ConnectPairInfo *`
 * @param message message we received
 */
static void
handle_test2 (void *cls,
	      const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  struct ConnectPairInfo *cpi = cls;
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ipi = cpi->ipi;
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = ipi->ccc;

  if (NULL != ccc->rec)
    ccc->rec (ccc->cls,
              ccc->p[ipi->off],
              cpi->sender,
              message);
}


/**
 * Connect the peers as a clique.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext`
 */
static void
do_connect (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = cls;

  ccc->connect_task = NULL;
  for (unsigned int i=0;i<ccc->num_peers;i++)
    for (unsigned int j=(ccc->bi_directional ? 0 : i+1);j<ccc->num_peers;j++)
    {
      struct GNUNET_TRANSPORT_TESTING_ConnectRequestList *crl;

      if (i == j)
        continue;
      crl = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_ConnectRequestList);
      GNUNET_CONTAINER_DLL_insert (ccc->crl_head,
                                   ccc->crl_tail,
                                   crl);
      crl->ccc = ccc;
      crl->p1 = ccc->p[i];
      crl->p2 = ccc->p[j];
      {
        char *sender_c = GNUNET_strdup (GNUNET_i2s (&ccc->p[0]->id));

        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Test tries to connect peer %u (`%s') -> peer %u (`%s')\n",
                    ccc->p[0]->no,
                    sender_c,
                    ccc->p[1]->no,
                    GNUNET_i2s (&ccc->p[1]->id));
        GNUNET_free (sender_c);
      }
      crl->cr = GNUNET_TRANSPORT_TESTING_connect_peers (ccc->p[i],
                                                        ccc->p[j],
                                                        &connect_cb,
                                                        crl);
    }
}


/**
 * Function called once we have successfully launched a peer.
 * Once all peers have been launched, we connect all of them
 * in a clique.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *`
 */
static void
start_cb (void *cls)
{
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext *ipi = cls;
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = ipi->ccc;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p = ccc->p[ipi->off];

  ccc->started++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer %u (`%s') started\n",
              p->no,
              GNUNET_i2s (&p->id));
  if (ccc->started != ccc->num_peers)
    return;
  if (NULL != ccc->pre_connect_task)
  {
    /* Run the custom per-connect job, then give it a second to
       go into effect before we continue connecting peers. */
    ccc->pre_connect_task (ccc->pre_connect_task_cls);
    ccc->connect_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                      &do_connect,
                                                      ccc);
  }
  else
  {
    do_connect (ccc);
  }
}


/**
 * Function run from #GNUNET_TRANSPORT_TESTING_connect_check
 * once the scheduler is up.  Should launch the peers and
 * then in the continuations try to connect them.
 *
 * @param cls our `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *`
 * @param args ignored
 * @param cfgfile ignored
 * @param cfg configuration
 */
static void
connect_check_run (void *cls,
                   char *const *args,
                   const char *cfgfile,
                   const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = cls;
  int ok;

  ccc->cfg = cfg;
  ccc->timeout_task = GNUNET_SCHEDULER_add_delayed (ccc->timeout,
                                                    &do_timeout,
                                                    ccc);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 ccc);
  ok = GNUNET_OK;
  for (unsigned int i=0;i<ccc->num_peers;i++)
  {
    struct GNUNET_MQ_MessageHandler handlers[] = {
      GNUNET_MQ_hd_var_size (test,
                             GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
                             struct GNUNET_TRANSPORT_TESTING_TestMessage,
                             NULL),
      GNUNET_MQ_hd_var_size (test2,
                             GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE2,
                             struct GNUNET_TRANSPORT_TESTING_TestMessage,
                             NULL),
      GNUNET_MQ_handler_end()
    };
    ccc->p[i] = GNUNET_TRANSPORT_TESTING_start_peer (ccc->tth,
                                                     ccc->cfg_files[i],
                                                     i + 1,
                                                     handlers,
                                                     &my_nc,
                                                     &my_nd,
						     &ccc->ip[i],
                                                     &start_cb,
                                                     &ccc->ip[i]);
    if (NULL == ccc->p[i])
      ok = GNUNET_SYSERR;
  }
  if (GNUNET_OK != ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Fail! Could not start peers!\n");
    GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Common implementation of the #GNUNET_TRANSPORT_TESTING_CheckCallback.
 * Starts and connects the two peers, then invokes the
 * `connect_continuation` from @a cls.  Sets up a timeout to
 * abort the test, and a shutdown handler to clean up properly
 * on exit.
 *
 * @param cls closure of type `struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext`
 * @param tth_ initialized testing handle
 * @param test_plugin_ name of the plugin
 * @param test_name_ name of the test
 * @param num_peers number of entries in the @a cfg_file array
 * @param cfg_files array of names of configuration files for the peers
 * @return #GNUNET_SYSERR on error
 */
int
GNUNET_TRANSPORT_TESTING_connect_check (void *cls,
                                        struct GNUNET_TRANSPORT_TESTING_Handle *tth_,
                                        const char *test_plugin_,
                                        const char *test_name_,
                                        unsigned int num_peers,
                                        char *cfg_files[])
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_TRANSPORT_TESTING_ConnectCheckContext *ccc = cls;
  struct GNUNET_TRANSPORT_TESTING_PeerContext *p[num_peers];
  struct GNUNET_TRANSPORT_TESTING_InternalPeerContext ip[num_peers];
  char * argv[] = {
    (char *) test_name_,
    "-c",
    (char *) ccc->config_file,
    NULL
  };

  ccc->num_peers = num_peers;
  ccc->cfg_files = cfg_files;
  ccc->test_plugin = test_plugin_;
  ccc->test_name = test_name_;
  ccc->tth = tth_;
  ccc->global_ret = GNUNET_OK;
  ccc->p = p;
  ccc->ip = ip;
  for (unsigned int i=0;i<num_peers;i++)
  {
    ip[i].off = i;
    ip[i].ccc = ccc;
  }
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv,
                      test_name_,
                      "nohelp",
                      options,
                      &connect_check_run,
                      ccc);
  return ccc->global_ret;
}


/**
 * Setup testcase.  Calls @a check with the data the test needs.
 *
 * @param argv0 binary name (argv[0])
 * @param filename source file name (__FILE__)
 * @param num_peers number of peers to start
 * @param check main function to run
 * @param check_cls closure for @a check
 * @return #GNUNET_OK on success
 */
int
GNUNET_TRANSPORT_TESTING_main_ (const char *argv0,
                                const char *filename,
                                unsigned int num_peers,
                                GNUNET_TRANSPORT_TESTING_CheckCallback check,
                                void *check_cls)
{
  struct GNUNET_TRANSPORT_TESTING_Handle *tth;
  char *test_name;
  char *test_source;
  char *test_plugin;
  char *cfg_names[num_peers];
  int ret;

  ret = GNUNET_OK;
  test_name = GNUNET_TRANSPORT_TESTING_get_test_name (argv0);
  GNUNET_log_setup (test_name,
                    "WARNING",
                    NULL);
  test_source = GNUNET_TRANSPORT_TESTING_get_test_source_name (filename);
  test_plugin = GNUNET_TRANSPORT_TESTING_get_test_plugin_name (argv0,
                                                               test_source);
  for (unsigned int i=0;i<num_peers;i++)
    cfg_names[i] = GNUNET_TRANSPORT_TESTING_get_config_name (argv0,
                                                             i+1);
  tth = GNUNET_TRANSPORT_TESTING_init ();
  if (NULL == tth)
  {
    ret = GNUNET_SYSERR;
  }
  else
  {
    ret = check (check_cls,
                 tth,
                 test_plugin,
                 test_name,
                 num_peers,
                 cfg_names);
    GNUNET_TRANSPORT_TESTING_done (tth);
  }
  for (unsigned int i=0;i<num_peers;i++)
    GNUNET_free (cfg_names[i]);
  GNUNET_free (test_source);
  GNUNET_free_non_null (test_plugin);
  GNUNET_free (test_name);
  return ret;
}

/* end of transport-testing-main.c */
