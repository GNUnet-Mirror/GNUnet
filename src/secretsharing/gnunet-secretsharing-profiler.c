/*
      This file is part of GNUnet
      Copyright (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/gnunet-secretsharing-profiler.c
 * @brief profiling tool for distributed key generation and decryption
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_secretsharing_service.h"
#include "gnunet_testbed_service.h"

/**
 * How many peers should participate in the key generation?
 */
static unsigned int num_peers = 3;

/**
 * What should the threshold for then key be?
 */
static unsigned int threshold = 2;

/**
 * Should we try to decrypt a value after the key generation?
 */
static unsigned int decrypt = GNUNET_NO;

/**
 * When would we like to see the operation finished?
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * When should dkg communication start?
 */
static struct GNUNET_TIME_Relative delay;

/**
 * Handles for secretsharing sessions.
 */
static struct GNUNET_SECRETSHARING_Session **session_handles;

static struct GNUNET_SECRETSHARING_DecryptionHandle **decrypt_handles;

/**
 * Shares we got from the distributed key generation.
 */
static struct GNUNET_SECRETSHARING_Share **shares;

static struct GNUNET_SECRETSHARING_PublicKey common_pubkey;


static unsigned int num_connected_sessions;

static unsigned int num_connected_decrypt;

/**
 * Handles to the running peers.
 * When peers[i] is NULL, the i-th peer has stopped.
 */
static struct GNUNET_TESTBED_Peer **peers;

static struct GNUNET_PeerIdentity *peer_ids;

static unsigned int num_retrieved_peer_ids;

static unsigned int num_generated;

static unsigned int num_decrypted;

static struct GNUNET_HashCode session_id;

static int verbose;

static struct GNUNET_SECRETSHARING_Plaintext reference_plaintext;

static struct GNUNET_SECRETSHARING_Ciphertext ciphertext;

static struct GNUNET_TIME_Absolute dkg_start;

static struct GNUNET_TIME_Absolute dkg_deadline;


static struct GNUNET_TIME_Absolute decrypt_start;

static struct GNUNET_TIME_Absolute decrypt_deadline;

/**
 * Connect operations, one for every peer.
 */
static struct GNUNET_TESTBED_Operation **connect_ops;

/**
 * Are we performing a shutdown right now?
 */
static int in_shutdown;


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb (void *cls,
               const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_assert (0);
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
session_connect_complete (void *cls,
                          struct GNUNET_TESTBED_Operation *op,
                          void *ca_result,
                          const char *emsg)
{

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "testbed connect emsg: %s\n",
                emsg);
    GNUNET_assert (0);
  }

  num_connected_sessions++;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "dkg: session connect complete\n");

  if (num_connected_sessions == num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "dkg: all peers connected\n");
  }
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
decrypt_connect_complete (void *cls,
                          struct GNUNET_TESTBED_Operation *op,
                          void *ca_result,
                          const char *emsg)
{

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "testbed connect emsg: %s\n",
                emsg);
    GNUNET_assert (0);
  }

  num_connected_decrypt++;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "decrypt: session connect complete\n");

  if (num_connected_decrypt == num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "decrypt: all peers connected\n");
  }
}


/**
 * Called when a decryption has succeeded.
 *
 * @param cls Plaintext
 * @param plaintext Plaintext
 */
static void decrypt_cb (void *cls,
                        const struct GNUNET_SECRETSHARING_Plaintext *plaintext)
{
  struct GNUNET_SECRETSHARING_DecryptionHandle **dhp = cls;
  unsigned int n = dhp - decrypt_handles;
  num_decrypted++;

  *dhp = NULL;

  // we should still be connected if this is called
  GNUNET_assert (NULL != connect_ops[n]);

  GNUNET_TESTBED_operation_done (connect_ops[n]);

  if (NULL == plaintext)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "decrypt failed for peer %u\n", n);
    return;
  }
  else if (0 == memcmp (&reference_plaintext, plaintext, sizeof (struct GNUNET_SECRETSHARING_Plaintext)))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "decrypt got correct result for peer %u\n", n);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "decrypt got wrong result for peer %u\n", n);

  if (num_decrypted == num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "every peer decrypted\n");
    GNUNET_SCHEDULER_shutdown ();
  }

  *dhp = NULL;
}



/**
 * Adapter function called to establish a connection to
 * a service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
decrypt_connect_adapter (void *cls,
                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SECRETSHARING_DecryptionHandle **hp = cls;
  unsigned int n = hp - decrypt_handles;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "decrypt connect adapter, %d peers\n",
              num_peers);
  *hp = GNUNET_SECRETSHARING_decrypt (cfg, shares[n], &ciphertext,
                                      decrypt_start, decrypt_deadline,
                                      decrypt_cb,
                                      hp);

  return *hp;
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
decrypt_disconnect_adapter(void *cls, void *op_result)
{
  struct GNUNET_SECRETSHARING_DecryptionHandle **dh = cls;
  unsigned int n = dh - decrypt_handles;

  GNUNET_assert (*dh == decrypt_handles[n]);

  if (NULL != *dh)
  {
    GNUNET_SECRETSHARING_decrypt_cancel (*dh);
    *dh = NULL;
  }

  GNUNET_assert (NULL != connect_ops[n]);
  connect_ops[n] = NULL;
}


static void
secret_ready_cb (void *cls,
                 struct GNUNET_SECRETSHARING_Share *my_share,
                 struct GNUNET_SECRETSHARING_PublicKey *public_key,
                 unsigned int num_ready_peers,
                 struct GNUNET_PeerIdentity *ready_peers)
{
  struct GNUNET_SECRETSHARING_Session **sp = cls;
  unsigned int n = sp - session_handles;
  char pubkey_str[1024];
  char *ret;

  num_generated++;
  *sp = NULL;
  shares[n] = my_share;
  if (NULL == my_share)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "key generation failed for peer #%u\n", n);
  }
  else
  {
    ret = GNUNET_STRINGS_data_to_string (public_key, sizeof *public_key, pubkey_str, 1024);
    GNUNET_assert (NULL != ret);
    *ret = '\0';
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "key generation successful for peer #%u, pubkey %s\n", n,
                pubkey_str);

    /* we're the first to get the key -> store it */
    if (num_generated == 1)
    {
      common_pubkey = *public_key;
    }
    else if (0 != memcmp (public_key, &common_pubkey, sizeof (struct GNUNET_SECRETSHARING_PublicKey)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "generated public keys do not match\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }

  // we should still be connected
  GNUNET_assert (NULL != connect_ops[n]);

  // disconnect from the service, will call the disconnect callback
  GNUNET_TESTBED_operation_done (connect_ops[n]);

}


/**
 * Adapter function called to establish a connection to
 * a service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
session_connect_adapter (void *cls,
                         const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_SECRETSHARING_Session **sp = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "connect adapter, %d peers\n",
              num_peers);
  *sp = GNUNET_SECRETSHARING_create_session (cfg,
                                             num_peers,
                                             peer_ids,
                                             &session_id,
                                             dkg_start,
                                             dkg_deadline,
                                             threshold,
                                             &secret_ready_cb, sp);
  return *sp;
}



/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
session_disconnect_adapter (void *cls, void *op_result)
{
  struct GNUNET_SECRETSHARING_Session **sp = cls;
  unsigned int n = (sp - session_handles);

  GNUNET_assert (*sp == session_handles[n]);

  if (NULL != *sp)
  {
    GNUNET_SECRETSHARING_session_destroy (*sp);
    *sp = NULL;
  }

  GNUNET_assert (NULL != connect_ops[n]);
  connect_ops[n] = NULL;

  if (GNUNET_YES == in_shutdown)
    return;

  // all peers received their secret
  if (num_generated == num_peers)
  {
    int i;

    // only do decryption if requested by the user
    if (GNUNET_NO == decrypt)
    {
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    decrypt_start = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);
    decrypt_deadline = GNUNET_TIME_absolute_add (decrypt_start, timeout);

    // compute g^42 as the plaintext which we will decrypt and then
    // cooperatively decrypt
    GNUNET_SECRETSHARING_plaintext_generate_i (&reference_plaintext, 42);
    GNUNET_SECRETSHARING_encrypt (&common_pubkey, &reference_plaintext, &ciphertext);

    for (i = 0; i < num_peers; i++)
      connect_ops[i] =
          GNUNET_TESTBED_service_connect (NULL, peers[i], "secretsharing", &decrypt_connect_complete, NULL,
                                          &decrypt_connect_adapter, &decrypt_disconnect_adapter, &decrypt_handles[i]);
  }
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
peer_info_cb (void *cb_cls,
              struct GNUNET_TESTBED_Operation *op,
              const struct GNUNET_TESTBED_PeerInformation *pinfo,
              const char *emsg)
{
  struct GNUNET_PeerIdentity *p;
  int i;

  GNUNET_assert (NULL == emsg);

  p = (struct GNUNET_PeerIdentity *) cb_cls;

  if (pinfo->pit == GNUNET_TESTBED_PIT_IDENTITY)
  {
    *p = *pinfo->result.id;
    num_retrieved_peer_ids++;
    if (num_retrieved_peer_ids == num_peers)
      for (i = 0; i < num_peers; i++)
        connect_ops[i] =
            GNUNET_TESTBED_service_connect (NULL, peers[i], "secretsharing", session_connect_complete, NULL,
                                            session_connect_adapter, session_disconnect_adapter, &session_handles[i]);
  }
  else
  {
    GNUNET_assert (0);
  }

  GNUNET_TESTBED_operation_done (op);
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
handle_shutdown (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  in_shutdown = GNUNET_YES;

  if (NULL != connect_ops)
  {
    unsigned int i;
    for (i = 0; i < num_peers; i++)
      if (NULL != connect_ops[i])
      {
        // the disconnect callback will set the op to NULL
        GNUNET_TESTBED_operation_done (connect_ops[i]);
      }
    GNUNET_free (connect_ops);
  }

  // killing the testbed operation will take care of remaining
  // service handles in the disconnect callback
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param started_peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **started_peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  int i;

  GNUNET_log_setup ("gnunet-secretsharing-profiler", "INFO", NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "test master\n");

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &handle_shutdown, NULL);

  peers = started_peers;

  peer_ids = GNUNET_malloc (num_peers * sizeof (struct GNUNET_PeerIdentity));

  session_handles = GNUNET_new_array (num_peers, struct GNUNET_SECRETSHARING_Session *);
  decrypt_handles = GNUNET_new_array (num_peers, struct GNUNET_SECRETSHARING_DecryptionHandle *);
  connect_ops = GNUNET_new_array (num_peers, struct GNUNET_TESTBED_Operation *);
  shares = GNUNET_new_array (num_peers, struct GNUNET_SECRETSHARING_Share *);

  for (i = 0; i < num_peers; i++)
  {
    // we do not store the returned operation, as peer_info_cb
    // will receive it as a parameter and call GNUNET_TESTBED_operation_done.
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_IDENTITY,
                                         peer_info_cb,
                                         &peer_ids[i]);
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static char *session_str = "gnunet-secretsharing/test";
  char *topology;
  int topology_cmp_result;

  dkg_start = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);
  dkg_deadline = GNUNET_TIME_absolute_add (dkg_start, timeout);

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "testbed", "OVERLAY_TOPOLOGY", &topology))
  {
    fprintf (stderr,
             "'OVERLAY_TOPOLOGY' not found in 'testbed' config section, "
             "seems like you passed the wrong configuration file\n");
    return;
  }

  topology_cmp_result = strcasecmp (topology, "NONE");
  GNUNET_free (topology);

  if (0 == topology_cmp_result)
  {
    fprintf (stderr,
             "'OVERLAY_TOPOLOGY' set to 'NONE', "
             "seems like you passed the wrong configuration file\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "running gnunet-secretsharing-profiler\n");

  GNUNET_CRYPTO_hash (session_str, strlen (session_str), &session_id);

  (void) GNUNET_TESTBED_test_run ("gnunet-secretsharing-profiler",
                                  cfgfile,
                                  num_peers,
                                  0,
                                  controller_cb,
                                  NULL,
                                  test_master,
                                  NULL);
}


int
main (int argc, char **argv)
{
   static const struct GNUNET_GETOPT_CommandLineOption options[] = {
      { 'n', "num-peers", NULL,
        gettext_noop ("number of peers in consensus"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers },
      { 'D', "delay", NULL,
        gettext_noop ("dkg start delay"),
        GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &delay },
      { 't', "timeout", NULL,
        gettext_noop ("dkg timeout"),
        GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &timeout },
      { 'k', "threshold", NULL,
        gettext_noop ("threshold"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &threshold },
      { 'd', "decrypt", NULL,
        gettext_noop ("also profile decryption"),
        GNUNET_NO, &GNUNET_GETOPT_set_one, &decrypt },
      { 'V', "verbose", NULL,
        gettext_noop ("be more verbose (print received values)"),
        GNUNET_NO, &GNUNET_GETOPT_set_one, &verbose },
      GNUNET_GETOPT_OPTION_END
  };
  delay = GNUNET_TIME_UNIT_ZERO;
  timeout = GNUNET_TIME_UNIT_MINUTES;
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-secretsharing-profiler",
		      "help",
		      options, &run, NULL, GNUNET_YES);
  return 0;
}

