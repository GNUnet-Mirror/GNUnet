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

#include <inttypes.h>

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

#define NUM_PEERS 2

static struct GNUNET_PeerIdentity peer_id[NUM_PEERS];

static struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_hs[NUM_PEERS];

//static char *addresses[NUM_PEERS];

static void
communicator_available_cb (void *cls,
                           struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
                           enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc,
                           char *address_prefix)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Communicator available. (cc: %u, prefix: %s)\n",
      cc,
      address_prefix);
}


static void
add_address_cb (void *cls,
                struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
                const char *address,
                struct GNUNET_TIME_Relative expiration,
                uint32_t aid,
                enum GNUNET_NetworkType nt)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "New address. (addr: %s, expir: %" PRIu32 ", ID: %" PRIu32 ", nt: %u\n",
      address,
      expiration.rel_value_us,
      aid,
      nt);
  //addresses[1] = GNUNET_strdup (address);
  GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (tc_hs[0],
                                                              &peer_id[1],
                                                              address);
}


static void
queue_create_reply_cb (void *cls,
                       struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
                       int success)
{
  if (GNUNET_YES == success)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Got Queue!\n");
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Failed getting queue!\n");
}


static void
add_queue_cb (void *cls,
              struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
              struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Got Queue!\n");
}


static void
run (void *cls)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  tc_hs[0] = GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
      "transport",
      "test_communicator_1.conf",
      &communicator_available_cb,
      NULL,
      &queue_create_reply_cb,
      &add_queue_cb,
      NULL); /* cls */
  tc_hs[1] = GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
      "transport",
      "test_communicator_2.conf",
      &communicator_available_cb,
      &add_address_cb,
      NULL,
      &add_queue_cb,
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

