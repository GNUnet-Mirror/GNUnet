/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api.c
 * @brief automatic transport selection API
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - write test case
 * - extend API to get performance data
 * - implement simplistic strategy based on say 'lowest latency' or strict ordering
 * - extend API to get peer preferences, implement proportional bandwidth assignment
 * - re-implement API against a real ATS service (!)
 */
#include "platform.h"
#include "gnunet_ats_service.h"

#define VERBOSE GNUNET_EXTRA_LOGGING

#define VERBOSE_ARM GNUNET_EXTRA_LOGGING

#define START_ARM GNUNET_YES


static struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_ATS_Handle *ats;

static void
alloc_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
          const char *plugin_name, struct Session *session,
          const void *plugin_addr, size_t plugin_addr_len,
          struct GNUNET_BANDWIDTH_Value32NBO bandwidth)
{

}

static int
check ()
{
  int ret = 0;

  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg, "test_ats_api.conf"))
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    return -1;
  }

  ats = GNUNET_ATS_init (cfg, alloc_cb, NULL);
  GNUNET_assert (ats != NULL);
  GNUNET_ATS_shutdown (ats);

  GNUNET_CONFIGURATION_destroy (cfg);
  return ret;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-ats-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  ret = check ();

  return ret;
}
