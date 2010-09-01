/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
/*
 * @file src/dht/test_dhtlog.c
 * @brief Test of the dhtlog service
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "dhtlog.h"

#define VERBOSE GNUNET_YES

static int ok;

#define CHECK(a) if (a != GNUNET_OK) return a
/**
 * Actual test of the service operations
 */
static int
test (struct GNUNET_DHTLOG_Handle * api)
{
  struct GNUNET_PeerIdentity p1;
  struct GNUNET_PeerIdentity p2;
  struct GNUNET_PeerIdentity p3;
  struct GNUNET_PeerIdentity p4;

  GNUNET_HashCode k1;
  GNUNET_HashCode k2;

  int ret;
  unsigned int i = 42;
  unsigned long long trialuid;
  unsigned long long sqlqueryuid;
  unsigned long long sqlrouteuid = 0;
  unsigned long long nodeuid = 0;
  unsigned long long internaluid = 1010223344LL;
  unsigned long long dhtkeyuid = 0;
  memset (&p1.hashPubKey, 3, sizeof (GNUNET_HashCode));
  memset (&p2.hashPubKey, 4, sizeof (GNUNET_HashCode));
  memset (&p3.hashPubKey, 5, sizeof (GNUNET_HashCode));
  memset (&p4.hashPubKey, 6, sizeof (GNUNET_HashCode));

  memset (&k1, 0, sizeof (GNUNET_HashCode));
  memset (&k2, 1, sizeof (GNUNET_HashCode));

  ret =
    api->insert_trial (&trialuid, i, 5, 4, 3, 2,
                       .75, .25, .5, 42, 14,
                       5, 1, 12, 0, 0, 0, 1, 0, 1,
                       0, 1, 0, "TEST INSERT TRIAL");
  CHECK(ret);
  ret = api->insert_topology(500);
  CHECK(ret);
  ret = api->insert_node (&nodeuid, &p1);
  CHECK(ret);
  ret = api->insert_node (&nodeuid, &p2);
  CHECK(ret);
  ret = api->insert_node (&nodeuid, &p3);
  CHECK(ret);
  ret = api->insert_node (&nodeuid, &p4);
  CHECK(ret);
  ret = api->set_malicious(&p1);
  CHECK(ret);
  ret = api->insert_topology(0);
  CHECK(ret);
  ret = api->insert_extended_topology(&p1, &p2);
  CHECK(ret);
  ret = api->insert_extended_topology(&p3, &p4);
  CHECK(ret);
  ret = api->update_topology(101);
  CHECK(ret);
  ret = api->insert_dhtkey (&dhtkeyuid, &k1);
  CHECK(ret);
  ret = api->insert_dhtkey (&dhtkeyuid, &k2);
  CHECK(ret);
  ret = api->insert_query (&sqlqueryuid, internaluid, 2, 4, 0, &p2, &k1);
  CHECK(ret);
  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, 1, 1, DHTLOG_GET, &p1, &k2,
                       &p4, &p3);
  CHECK(ret);
  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, 2, 0, DHTLOG_PUT, &p3, &k1,
                       &p4, &p2);
  CHECK(ret);
  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, 3, 1, DHTLOG_ROUTE, &p3, &k2,
                       &p2, NULL);
  CHECK(ret);
  ret =
    api->insert_route (&sqlrouteuid, sqlqueryuid, 4, 7, DHTLOG_ROUTE, &p3, &k2,
                       NULL, NULL);
  CHECK(ret);
  sleep (1);
  ret = api->insert_stat(&p1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17);
  CHECK(ret);
  ret = api->insert_stat(&p2, 12, 23, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27);
  CHECK(ret);
  ret = api->update_trial (trialuid, 787);
  CHECK(ret);
  ret = api->add_generic_stat (&p2, "nonsense", "section", 77765);
  CHECK(ret);
  return 0;
}



static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DHTLOG_Handle *api;
  ok = 0;
  api = GNUNET_DHTLOG_connect (cfg);

  if (api == NULL)
    {
      ok = 1;
      return;
    }
  ok = test(api);

  GNUNET_DHTLOG_disconnect(api);
}


static int
check ()
{
  char *const argv[] = { "test-dhtlog-api",
    "-c",
    "test_dhtlog_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-dhtlog-api", "nohelp",
                      options, &run, NULL);
  if (ok != 0)
    fprintf (stderr, "Test failed with error code: %d\n", ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-datacache-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}

/* end of test_dhtlog.c */
