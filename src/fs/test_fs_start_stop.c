/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/fs/fsui/fsui_start_stop_test.c
 * @brief testcase for fsui (start-stop only)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_fsui_lib.h"

#define CHECK(a) if (!(a)) { ok = GNUNET_NO; GNUNET_GE_BREAK(NULL, 0); goto FAILURE; }


static struct GNUNET_FSUI_Context *ctx;

static void *
eventCallback (void *cls, const GNUNET_FSUI_Event * event)
{
  return NULL;
}

#define START_DAEMON 1

int
main (int argc, char *argv[])
{
#if START_DAEMON
  pid_t daemon;
#endif
  int ok;
  struct GNUNET_GC_Configuration *cfg;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
#if START_DAEMON
  daemon = GNUNET_daemon_start (NULL, cfg, "peer.conf", GNUNET_NO);
  GNUNET_GE_ASSERT (NULL, daemon > 0);
  CHECK (GNUNET_OK ==
         GNUNET_wait_for_daemon_running (NULL, cfg,
                                         60 * GNUNET_CRON_SECONDS));
#endif
  ok = GNUNET_YES;
  GNUNET_thread_sleep (5 * GNUNET_CRON_SECONDS);        /* give apps time to start */

  /* ACTUAL TEST CODE */
  ctx = GNUNET_FSUI_start (NULL, cfg, "fsui_start_stop_test", 32, GNUNET_YES,   /* do resume! */
                           &eventCallback, NULL);
  CHECK (ctx != NULL);
  GNUNET_FSUI_stop (ctx);
  ctx =
    GNUNET_FSUI_start (NULL, cfg, "fsui_start_stop_test", 32, GNUNET_YES,
                       &eventCallback, NULL);
  CHECK (ctx != NULL);
FAILURE:
  if (ctx != NULL)
    GNUNET_FSUI_stop (ctx);
#if START_DAEMON
  GNUNET_GE_ASSERT (NULL, GNUNET_OK == GNUNET_daemon_stop (NULL, daemon));
#endif
  GNUNET_GC_free (cfg);

  return (ok == GNUNET_YES) ? 0 : 1;
}

/* end of fsui_start_stop_test.c */
