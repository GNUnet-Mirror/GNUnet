
/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file consensus/gnunet-consensus-start-peers.c
 * @brief Starts peers with testebed on localhost,
 *        prints their configuration files and waits for ^C.
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"


static char *config_template_file;
static unsigned int num_peers_requested = 2;
static struct GNUNET_TESTBED_Peer **peers;


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
              struct GNUNET_TESTBED_Operation
              *op,
              const struct
              GNUNET_TESTBED_PeerInformation
              *pinfo,
              const char *emsg)
{
  GNUNET_assert (NULL == emsg);
  if (pinfo->pit == GNUNET_TESTBED_PIT_IDENTITY)
  {
    struct GNUNET_CRYPTO_HashAsciiEncoded enc;
    GNUNET_CRYPTO_hash_to_enc (&pinfo->result.id->hashPubKey, &enc);
    printf("peer %td identity:\n", ((struct GNUNET_TESTBED_Peer **) cb_cls) - &peers[0]);
    printf("%s\n", (char *)&enc);
  }
  else if (pinfo->pit == GNUNET_TESTBED_PIT_CONFIGURATION)
  {
    char *tmpfilename;
    if (NULL == (tmpfilename = GNUNET_DISK_mktemp ("gnunet-consensus")))
    {
      GNUNET_break (0);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    if (GNUNET_SYSERR == 
        GNUNET_CONFIGURATION_write (pinfo->result.cfg,
                                    tmpfilename))
    {
      GNUNET_break (0);
      return;
    }
    printf("peer %td config file:\n", ((struct GNUNET_TESTBED_Peer **) cb_cls) - &peers[0]);
    printf("%s\n", tmpfilename);
  }
  else
  {
    GNUNET_assert (0);
  }
}



/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb(void *cls,
              const struct GNUNET_TESTBED_EventInformation *event)
{
  GNUNET_assert (0);
}




static void
test_master (void *cls,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **started_peers)
{
  int i;

  printf("started %d peers\n", num_peers);
  peers = started_peers;

  for (i = 0; i < num_peers; i++)
  {
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_IDENTITY,
                                         peer_info_cb,
                                         &peers[i]);
    GNUNET_TESTBED_peer_get_information (peers[i],
                                         GNUNET_TESTBED_PIT_CONFIGURATION,
                                         peer_info_cb,
                                         &peers[i]);
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  if (NULL == config_template_file)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "no template file specified\n");
    return;
  }

  (void) GNUNET_TESTBED_test_run ("gnunet-consensus-start-peers",
                                  config_template_file,
                                  num_peers_requested,
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
      { 't', "config-template", "TEMPLATE",
        gettext_noop ("start peers with the given template configuration"),
        GNUNET_YES, &GNUNET_GETOPT_set_string, &config_template_file },
      { 'n', "num-peers", "NUM",
        gettext_noop ("number of peers to start"),
        GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers_requested },
      GNUNET_GETOPT_OPTION_END
   };

  /* run without scheduler, as test_run already does this */
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-consensus-start-peers",
		      "help",
		      options, &run, NULL, GNUNET_YES);
  return 0;
}

