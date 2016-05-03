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
 * CLI tool to interact with the social service.
 *
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_social_service.h"

/* operations corresponding to API calls */

/** --host-enter */
static int op_host_enter;

/** --host-leave */
static int op_host_leave;

/** --host-announce */
static int op_host_announce;

/** --guest-enter */
static int op_guest_enter;

/** --guest-leave */
static int op_guest_leave;

/** --guest-talk */
static int op_guest_talk;

/** --history-replay */
static char *op_history_replay;

/** --history-replay-latest */
static char *op_history_replay_latest;

/* options */

/** --place */
static char *place;

/** --listen */
static int listen;

/** --method */
static char *method;

/** --data */
static char *data;

/** --prefix */
static char *prefix;

/** --start */
static uint64_t start;

/** --end */
static uint64_t end;

/** --limit */
static int limit;


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "TODO\n");
}


/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
     {'p', "place", "PUBKEY",
      gettext_noop ("public key of place"),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &place},

     {'l', "listen", NULL,
     gettext_noop ("listen for incoming messages"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &listen},

     {'m', "method", "METHOD_NAME",
      gettext_noop ("method name to transmit"),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &method},

     {'d', "data", "DATA",
      gettext_noop ("message body to transmit"),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &method},

     {'p', "prefix", "METHOD_PREFIX",
      gettext_noop ("method prefix filter for history replay"),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &method},

     {'s', "start", NULL,
     gettext_noop ("start message ID for history replay"),
     GNUNET_NO, &GNUNET_GETOPT_set_ulong, &start},

     {'e', "end", NULL,
     gettext_noop ("end message ID for history replay"),
     GNUNET_NO, &GNUNET_GETOPT_set_ulong, &end},

     {'n', "limit", NULL,
     gettext_noop ("number of messages to replay from history"),
     GNUNET_NO, &GNUNET_GETOPT_set_ulong, &end},

    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  const char *help =
    "enter/leave and send/receive messages in places of the social service";
  const char *usage =
    "gnunet-social --place <pubkey> --host-enter [--listen]\n"
    "gnunet-social --place <pubkey> --host-leave\n"
    "gnunet-social --place <pubkey> --host-announce --method <method_name> --data <message_body>\n"
    "\n"
    "gnunet-social --place <pubkey> --guest-enter [--listen]\n"
    "gnunet-social --place <pubkey> --guest-leave\n"
    "gnunet-social --place <pubkey> --guest-talk --method <method_nmae> --data <data>\n"
    "\n"
    "gnunet-social --place <pubkey> --history-replay --start <msgid> --end <msgid>  [--prefix <method_prefix>]\n"
    "gnunet-social --place <pubkey> --history-replay-latest --limit <msg_limit> [--prefix <method_prefix>]\n"
    "\n"
    "gnunet-social --place <pubkey> --look-at <full_name>\n"
    "gnunet-social --place <pubkey> --look-for <name_prefix>\n";

  res = GNUNET_PROGRAM_run (argc, argv, usage,
                            gettext_noop (help),
                            options, &run, NULL);

  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return 0;
  else
    return 1;
}
