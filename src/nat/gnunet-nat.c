/*
     This file is part of GNUnet.
     Copyright (C) 2015 Christian Grothoff (and other contributing authors)

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
#include "gnunet_nat_lib.h"
#include "gnunet_protocols.h"
#include "nat.h"


struct GNUNET_CONFIGURATION_Handle *cfg;



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

  PRINTF ( "%s: %s \n", option, value);
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

void
auto_config_cb(void *cls,
               const struct GNUNET_CONFIGURATION_Handle *diff,
               enum GNUNET_NAT_StatusCode result, enum GNUNET_NAT_Type type)
{
  char* nat_type;
  char unknown_type[64];

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
      SPRINTF (unknown_type, "NAT unknown, type %u", type);
      nat_type = unknown_type;
  }

  PRINTF ("NAT status: %s \n", nat_type );
  PRINTF ("SUGGESTED CHANGES: \n" );

  GNUNET_CONFIGURATION_iterate_section_values (diff,
                                               "nat",
                                               &auto_conf_iter,
                                               NULL);

  //TODO: Save config

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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_NAT_autoconfig_start (c, auto_config_cb, NULL);
}


/**
 * Main function of gnunet-nat
 *
 * @param argc number of command-line arguments
 * @param argv command line
 * @return 0 on success, -1 on error
 */
int
main (int argc, char *const argv[])
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  int ret = 0;
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  /* Lets start resolver */
  char *fn;
  struct GNUNET_OS_Process *proc;

  fn = GNUNET_OS_get_libexec_binary_path ("gnunet-service-resolver");
  proc = GNUNET_OS_start_process (GNUNET_YES,
                                  GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                  NULL, NULL, NULL,
                                  fn,
                                  "gnunet-service-resolver");
  GNUNET_assert (NULL != proc);

  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "gnunet-nat [options]",
                          _("GNUnet NAT traversal autoconfigure daemon"), options,
                          &run, NULL))
  {
      ret = 1;
  }

  /* Now kill the resolver */
  if (0 != GNUNET_OS_process_kill (proc, GNUNET_TERM_SIG))
  {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  proc = NULL;


  GNUNET_free ((void*) argv);
  return ret;
}


/* end of gnunet-nat-server.c */
