/*
     This file is part of GNUnet.
     Copyright (C) 2015, 2016 GNUnet e.V.

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
 * @file src/nat/gnunet-nat.c
 * @brief Daemon to auto configure nat
 * @author Christian Grothoff
 * @author Bruno Cabral
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_service.h"

/**
 * Value to return from #main().
 */
static int global_ret;

/**
 * Handle to ongoing autoconfiguration.
 */
static struct GNUNET_NAT_AutoHandle *ah;

/**
 * Port we use.
 */ 
static unsigned int port;

/**
 * Flag set to 1 if we use IPPROTO_UDP.
 */
static int use_udp;

/**
 * Flag set to 1 if we are to listen for connection reversal requests.
 */
static int listen_reversal;

/**
 * Flag set to 1 if we use IPPROTO_TCP.
 */
static int use_tcp;

/**
 * Protocol to use.
 */
static uint8_t proto;

/**
 * Address we are bound to (in test), or should bind to
 * (if #do_stun is set).
 */
static char *bind_addr;

/**
 * External IP address and port to use for the test.
 * If not set, use #bind_addr.
 */
static char *extern_addr;

/**
 * Local address to use for connection reversal request.
 */
static char *local_addr;

/**
 * Remote address to use for connection reversal request.
 */
static char *remote_addr;

/**
 * Should we actually bind to #bind_addr and receive and process STUN requests?
 */
static unsigned int do_stun;

/**
 * Should we run autoconfiguration?
 */
static unsigned int do_auto;

/**
 * Handle to a NAT test operation.
 */
static struct GNUNET_NAT_Test *nt;

/**
 * Handle to NAT operation.
 */
static struct GNUNET_NAT_Handle *nh;


/**
 * Test if all activities have finished, and if so,
 * terminate.
 */
static void
test_finished ()
{
  if (NULL != ah)
    return;
  if (NULL != nt)
    return;
  if (NULL != nh)
    return;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function to iterate over sugested changes options
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
auto_conf_iter (void *cls,
                const char *section,
                const char *option,
                const char *value)
{
  PRINTF ("%s: %s\n",
	  option,
	  value);
}


/**
 * Function called with the result from the autoconfiguration.
 *
 * @param cls closure
 * @param diff minimal suggested changes to the original configuration
 *             to make it work (as best as we can)
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 * @param type what the situation of the NAT
 */
static void
auto_config_cb (void *cls,
		const struct GNUNET_CONFIGURATION_Handle *diff,
		enum GNUNET_NAT_StatusCode result,
		enum GNUNET_NAT_Type type)
{
  const char *nat_type;
  char unknown_type[64];

  ah = NULL;
  switch (type)
  {
    case GNUNET_NAT_TYPE_NO_NAT:
      nat_type = "NO NAT";
      break;
    case GNUNET_NAT_TYPE_UNREACHABLE_NAT:
      nat_type = "NAT but we can traverse";
      break;
    case GNUNET_NAT_TYPE_STUN_PUNCHED_NAT:
      nat_type = "NAT but STUN is able to identify the correct information";
      break;
    case GNUNET_NAT_TYPE_UPNP_NAT:
      nat_type = "NAT but UPNP opened the ports";
      break;
    default:
      SPRINTF (unknown_type,
	       "NAT unknown, type %u",
	       type);
      nat_type = unknown_type;
  }

  PRINTF ("NAT status: %s/%s\n",
	  GNUNET_NAT_status2string (result),
	  nat_type);
  
  PRINTF ("SUGGESTED CHANGES:\n");
  GNUNET_CONFIGURATION_iterate_section_values (diff,
                                               "nat",
                                               &auto_conf_iter,
                                               NULL);
  // Have option to save config
  test_finished ();
}


/**
 * Task run on shutdown.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  if (NULL != ah)
  {
    GNUNET_NAT_autoconfig_cancel (ah);
    ah = NULL;
  }
  if (NULL != nt)
  {
    GNUNET_NAT_test_stop (nt);
    nt = NULL;
  }
  if (NULL != nh)
  {
    GNUNET_NAT_unregister (nh);
    nh = NULL;
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  if (use_tcp && use_udp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Cannot use TCP and UDP\n");
    global_ret = 1;
    return;
  }
  proto = 0;
  if (use_tcp)
    proto = IPPROTO_TCP;
  if (use_udp)
    proto = IPPROTO_UDP;
  if (0 == proto)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Must specify either TCP or UDP\n");
    global_ret = 1;
    return;
  }
  if (do_auto)
  {
    ah = GNUNET_NAT_autoconfig_start (c,
				      &auto_config_cb,
				      NULL);
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
  test_finished ();
}


/**
 * Main function of gnunet-nat
 *
 * @param argc number of command-line arguments
 * @param argv command line
 * @return 0 on success, -1 on error
 */
int
main (int argc,
      char *const argv[])
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "auto", NULL,
     gettext_noop ("run autoconfiguration"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &do_auto },
    {'b', "bind", "ADDRESS",
     gettext_noop ("which IP and port are we bound to"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &bind_addr},
    {'e', "external", "ADDRESS",
     gettext_noop ("which external IP and port should be used to test"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &extern_addr},
    {'l', "local", "ADDRESS",
     gettext_noop ("which IP and port are we locally using to listen to for connection reversals"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &local_addr},
    {'r', "remote", "ADDRESS",
     gettext_noop ("which remote IP and port should be asked for connection reversal"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &remote_addr},
    {'L', "listen", NULL,
     gettext_noop ("listen for connection reversal requests"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &listen_reversal },
    {'p', "port", NULL,
     gettext_noop ("port to use"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &port},
    {'s', "stun", NULL,
     gettext_noop ("enable STUN processing"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &do_stun },
    {'t', "tcp", NULL,
     gettext_noop ("use TCP"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &use_tcp },
    {'u', "udp", NULL,
     gettext_noop ("use UDP"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &use_udp },
   GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
			  "gnunet-nat [options]",
                          _("GNUnet NAT traversal autoconfigure daemon"),
			  options,
                          &run,
			  NULL))
  {
    global_ret = 1;
  }
  GNUNET_free ((void*) argv);
  return global_ret;
}


/* end of gnunet-nat.c */
