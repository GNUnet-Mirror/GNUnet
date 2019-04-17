/*
     This file is part of GNUnet.
     Copyright (C) 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file transport/test_communicator_unix.c
 * @brief test the unix communicator
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "transport-testing2.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_signatures.h"
#include "transport.h"

/**
 * TODO
 * - start two communicators
 * - act like transport services
 *   - get_server_addresses (service.c)
 *   - open_listen_socket (service.c)
 *   - GNUNET_MQ_queue_for_callbacks (service.c)
 * - let them communicate
 *
 */



#define LOG(kind,...) GNUNET_log_from (kind, "test_transport_communicator_unix", __VA_ARGS__)

static void
communicator_available (void *cls,
    const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *msg)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "communicator_available()\n");
}

static void
run (void *cls)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
      "transport",
      cfg,
      &communicator_available,
      NULL); /* cls */
}

int
main (int argc,
      char *const *argv)
{
  char *cfg_filename;
  char *opt_cfg_filename;
  const char *xdg;
  char *loglev;
  char *logfile;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_GETOPT_CommandLineOption service_options[] = {
    GNUNET_GETOPT_option_cfgfile (&opt_cfg_filename),
    GNUNET_GETOPT_option_help (NULL),
    GNUNET_GETOPT_option_loglevel (&loglev),
    GNUNET_GETOPT_option_logfile (&logfile),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_log_setup ("test_communicator_unix",
                                     loglev,
                                     logfile))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  xdg = getenv ("XDG_CONFIG_HOME");
  if (NULL != xdg)
    GNUNET_asprintf (&cfg_filename,
                     "%s%s%s",
                     xdg,
                     DIR_SEPARATOR_STR,
                     GNUNET_OS_project_data_get ()->config_file);
  else
    cfg_filename = GNUNET_strdup (GNUNET_OS_project_data_get ()->user_config_file);
  cfg = GNUNET_CONFIGURATION_create ();
  if (NULL != opt_cfg_filename)
  {
    if ( (GNUNET_YES !=
          GNUNET_DISK_file_test (opt_cfg_filename)) ||
       (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg,
                                     opt_cfg_filename)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration file `%s', exit ...\n"),
                    opt_cfg_filename);
      return GNUNET_SYSERR;
    }
  }
  else
  {
    if (GNUNET_YES ==
        GNUNET_DISK_file_test (cfg_filename))
    {
      if (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg,
                                     cfg_filename))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Malformed configuration file `%s', exit ...\n"),
                    cfg_filename);
        return GNUNET_SYSERR;
      }
    }
    else
    {
      if (GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_load (cfg,
                                     NULL))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("Malformed configuration, exit ...\n"));
        return GNUNET_SYSERR;
      }
    }
  }
  GNUNET_SCHEDULER_run (&run,
                        cfg);
}

