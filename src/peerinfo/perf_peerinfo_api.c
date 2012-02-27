/*
     This file is part of GNUnet.
     (C) 2004, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/test_peerinfo_hammer.c
 * @brief testcase for peerinfo_api.c, hopefully hammer the peerinfo service
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_program_lib.h"
#include "gnunet_time_lib.h"
#include "peerinfo.h"
#include <gauger.h>

#define START_SERVICE 1

#define NUM_REQUESTS 5000

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_PEERINFO_IteratorContext *ic[NUM_REQUESTS];

static struct GNUNET_PEERINFO_Handle *h;

static unsigned int numpeers;

static struct GNUNET_PeerIdentity pid;


static int
check_it (void *cls, const struct GNUNET_HELLO_Address *address,
          struct GNUNET_TIME_Absolute expiration)
{
#if DEBUG
  if (addrlen > 0)
  {
    FPRINTF (stderr, "name: %s, addr: %s\n", tname, (const char *) addr);
  }
#endif
  return GNUNET_OK;
}


static size_t
address_generator (void *cls, size_t max, void *buf)
{
  size_t *agc = cls;
  size_t ret;
  char *caddress;
  struct GNUNET_HELLO_Address address;

  if (*agc == 0)
    return 0;

  GNUNET_asprintf (&caddress, "Address%d", *agc);
  address.peer = pid;
  address.address_length = strlen (caddress) + 1;
  address.address = caddress;
  address.transport_name = "peerinfotest";
  ret =
      GNUNET_HELLO_add_address (&address,
                                GNUNET_TIME_relative_to_absolute
                                (GNUNET_TIME_UNIT_HOURS), buf, max);
  GNUNET_free (caddress);
  *agc = 0;
  return ret;
}


static void
add_peer (size_t i)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_HELLO_Message *h2;

  memset (&pkey, i, sizeof (pkey));
  GNUNET_CRYPTO_hash (&pkey, sizeof (pkey), &pid.hashPubKey);
  h2 = GNUNET_HELLO_create (&pkey, &address_generator, &i);
  GNUNET_PEERINFO_add_peer (h, h2);
  GNUNET_free (h2);
}


static void
process (void *cls, const struct GNUNET_PeerIdentity *peer,
         const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  if (peer == NULL)
  {
#if DEBUG
    FPRINTF (stderr, "Process received NULL response\n");
#endif
  }
  else
  {
#if DEBUG
    FPRINTF (stderr, "Processed a peer\n");
#endif
    numpeers++;
    if (0 && (hello != NULL))
      GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &check_it, NULL);

  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  size_t i;

  cfg = c;
  h = GNUNET_PEERINFO_connect (cfg);
  GNUNET_assert (h != NULL);
  for (i = 0; i < NUM_REQUESTS; i++)
  {
    add_peer (i);
    ic[i] =
        GNUNET_PEERINFO_iterate (h, NULL,
                                 GNUNET_TIME_relative_multiply
                                 (GNUNET_TIME_UNIT_SECONDS, 30), &process, cls);
  }
}

static int
check ()
{
  int ok = 0;

  char *const argv[] = { "perf-peerinfo-api",
    "-c",
    "test_peerinfo_api_data.conf",
#if DEBUG_PEERINFO
    "-L", "DEBUG",
#else
    "-L", "ERROR",
#endif
    NULL
  };
#if START_SERVICE
  struct GNUNET_OS_Process *proc;

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-peerinfo",
                               "gnunet-service-peerinfo",
#if DEBUG_PEERINFO
                               "-L", "DEBUG",
#else
                               "-L", "ERROR",
#endif
                               "-c", "test_peerinfo_api_data.conf", NULL);
#endif
  GNUNET_assert (NULL != proc);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "perf-peerinfo-api", "nohelp", options, &run, &ok);
  FPRINTF (stderr, "Received %u/%u calls before timeout\n", numpeers,
           NUM_REQUESTS * NUM_REQUESTS / 2);
  GAUGER ("PEERINFO", "Peerinfo lookups", numpeers / 30, "peers/s");
#if START_SERVICE
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_close (proc);
  proc = NULL;

#endif
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("perf_peerinfo_api",
#if DEBUG_PEERINFO
                    "DEBUG",
#else
                    "ERROR",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-peerinfo");
  return ret;
}

/* end of perf_peerinfo_api.c */
