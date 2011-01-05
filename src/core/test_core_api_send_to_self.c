/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file core/test_core_api_send_to_self.c
 * @brief
 * @author Philipp Toelke
 */
#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_program_lib.h>
#include <gnunet_protocols.h>
#include <gnunet_core_service.h>
#include <gnunet_constants.h>

/**
 * Final status code.
 */
static int ret;

/**
 * The handle to core
 */
static struct GNUNET_CORE_Handle *core_handle;

/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

  if (core_handle != NULL)
    {
      GNUNET_CORE_disconnect (core_handle);
      core_handle = NULL;
    }
}

static struct GNUNET_PeerIdentity myself;

struct GNUNET_CORE_Handle *core;

static int
receive(void* cls, const struct GNUNET_PeerIdentity* other, const struct GNUNET_MessageHeader* message, const struct GNUNET_TRANSPORT_ATS_Information* atsi)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received message from peer %s\n", GNUNET_i2s(other));
  return GNUNET_OK;
}

static size_t
send_message (void* cls, size_t size, void* buf)
{
  if (size == 0 || buf == NULL)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Could not send; got 0 buffer\n");
      return 0;
    }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending!\n");
  struct GNUNET_MessageHeader *hdr = buf;
  hdr->size = htons(sizeof(struct GNUNET_MessageHeader));
  hdr->type = htons(GNUNET_MESSAGE_TYPE_SERVICE_UDP);
  return ntohs(hdr->size);
}

static void
init (void *cls, struct GNUNET_CORE_Handle *core,
      const struct GNUNET_PeerIdentity *my_identity,
      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pk)
{
  if (core == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Could NOT connect to CORE;\n");
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Correctly connected to CORE; we are the peer %s.\n",
	      GNUNET_i2s (my_identity));
  memcpy (&myself, my_identity, sizeof (struct GNUNET_PeerIdentity));
}

static void
connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
	    const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %s.\n",
	      GNUNET_i2s (peer));
  if (0 == memcmp (peer, &myself, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connected to myself; sending message!\n");
      GNUNET_CORE_notify_transmit_ready (core,
					 0, GNUNET_TIME_UNIT_FOREVER_REL,
					 peer,
					 sizeof (struct GNUNET_MessageHeader),
					 send_message, NULL);
    }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  const static struct GNUNET_CORE_MessageHandler handlers[] = {
    {receive, GNUNET_MESSAGE_TYPE_SERVICE_UDP, 0},
    {NULL, 0, 0}
  };
  core = GNUNET_CORE_connect (cfg_,
			      42,
			      NULL,
			      init,
			      connect_cb,
			      NULL, NULL, NULL, 0, NULL, 0, handlers);
  GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
}

/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
	  GNUNET_PROGRAM_run (argc,
			      argv,
			      "test_core_api_send_to_self",
			      gettext_noop ("help text"),
			      options, &run, NULL)) ? ret : 1;
}

/* end of test_core_api_send_to_self.c */
