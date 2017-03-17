/*
     This file is part of GNUnet.
     Copyright (C) 2015, 2016, 2017 GNUnet e.V.

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
 * @file src/nat/gnunet-nat-auto.c
 * @brief Command-line tool for testing and autoconfiguration of NAT traversal
 * @author Christian Grothoff
 * @author Bruno Cabral
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_nat_service.h"
#include "gnunet_nat_auto_service.h"

/**
 * Value to return from #main().
 */
static int global_ret;

/**
 * Handle to ongoing autoconfiguration.
 */
static struct GNUNET_NAT_AUTO_AutoHandle *ah;

/**
 * If we do auto-configuration, should we write the result
 * to a file?
 */
static int write_cfg;

/**
 * Configuration filename.
 */
static const char *cfg_file;

/**
 * Original configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Adapter we are supposed to test.
 */
static char *section_name;

/**
 * Should we run autoconfiguration?
 */
static int do_auto;

/**
 * Handle to a NAT test operation.
 */
static struct GNUNET_NAT_AUTO_Test *nt;

/**
 * Flag set to 1 if we use IPPROTO_UDP.
 */
static int use_udp;

/**
 * Flag set to 1 if we use IPPROTO_TCP.
 */
static int use_tcp;

/**
 * Protocol to use.
 */
static uint8_t proto;

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
  struct GNUNET_CONFIGURATION_Handle *new_cfg = cls;

  PRINTF ("%s: %s\n",
	  option,
	  value);
  if (NULL != new_cfg)
    GNUNET_CONFIGURATION_set_value_string (new_cfg,
					   section,
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
  struct GNUNET_CONFIGURATION_Handle *new_cfg;

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
    break;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
	      "NAT status: %s/%s\n",
	      GNUNET_NAT_AUTO_status2string (result),
	      nat_type);

  if (NULL == diff)
    return;

  /* Shortcut: if there are no changes suggested, bail out early. */
  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_is_dirty (diff))
  {
    test_finished ();
    return;
  }

  /* Apply diff to original configuration and show changes
     to the user */
  new_cfg = write_cfg ? GNUNET_CONFIGURATION_dup (cfg) : NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
              _("Suggested configuration changes:\n"));
  GNUNET_CONFIGURATION_iterate_section_values (diff,
                                               "nat",
                                               &auto_conf_iter,
                                               new_cfg);

  /* If desired, write configuration to file; we write only the
     changes to the defaults to keep things compact. */
  if (write_cfg)
  {
    struct GNUNET_CONFIGURATION_Handle *def_cfg;

    GNUNET_CONFIGURATION_set_value_string (new_cfg,
					   "ARM",
					   "CONFIG",
					   NULL);
    def_cfg = GNUNET_CONFIGURATION_create ();
    GNUNET_break (GNUNET_OK ==
		  GNUNET_CONFIGURATION_load (def_cfg,
					     NULL));
    if (GNUNET_OK !=
	GNUNET_CONFIGURATION_write_diffs (def_cfg,
					  new_cfg,
					  cfg_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  _("Failed to write configuration to `%s'\n"),
		  cfg_file);
      global_ret = 1;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		  _("Wrote updated configuration to `%s'\n"),
		  cfg_file);
    }
    GNUNET_CONFIGURATION_destroy (def_cfg);
  }

  if (NULL != new_cfg)
    GNUNET_CONFIGURATION_destroy (new_cfg);
  test_finished ();
}


/**
 * Function called to report success or failure for
 * NAT configuration test.
 *
 * @param cls closure
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
static void
test_report_cb (void *cls,
		enum GNUNET_NAT_StatusCode result)
{
  nt = NULL;
  PRINTF ("NAT test result: %s\n",
	  GNUNET_NAT_AUTO_status2string (result));
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
    GNUNET_NAT_AUTO_autoconfig_cancel (ah);
    ah = NULL;
  }
  if (NULL != nt)
  {
    GNUNET_NAT_AUTO_test_stop (nt);
    nt = NULL;
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
  cfg_file = cfgfile;
  cfg = c;

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);

  if (do_auto)
  {
    ah = GNUNET_NAT_AUTO_autoconfig_start (c,
                                           &auto_config_cb,
                                           NULL);
  }

  if (use_tcp && use_udp)
  {
    if (do_auto)
      return;
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

  if (NULL != section_name)
  {
    nt = GNUNET_NAT_AUTO_test_start (c,
				     proto,
				     section_name,
				     &test_report_cb,
				     NULL);
  }
  test_finished ();
}


/**
 * Main function of gnunet-nat-auto
 *
 * @param argc number of command-line arguments
 * @param argv command line
 * @return 0 on success, -1 on error
 */
int
main (int argc,
      char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_SET_ONE ('a',
                                  "auto",
                                  gettext_noop ("run autoconfiguration"),
                                  &do_auto),

    GNUNET_GETOPT_OPTION_STRING ('S',
                                 "section",
                                 "NAME",
                                 gettext_noop ("section name providing the configuration for the adapter"),
                                 &section_name),

    GNUNET_GETOPT_OPTION_SET_ONE ('t',
                                   "tcp",
                                   gettext_noop ("use TCP"),
                                   &use_tcp),

    GNUNET_GETOPT_OPTION_SET_ONE ('u',
                                   "udp",
                                   gettext_noop ("use UDP"),
                                   &use_udp),

    GNUNET_GETOPT_OPTION_SET_ONE ('w',
                                   "write",
                                   gettext_noop ("write configuration file (for autoconfiguration)"),
                                   &write_cfg),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
			  "gnunet-nat-auto [options]",
                          _("GNUnet NAT traversal autoconfiguration"),
			  options,
                          &run,
			  NULL))
  {
    global_ret = 1;
  }
  GNUNET_free ((void*) argv);
  return global_ret;
}


/* end of gnunet-nat-auto.c */
