/*
     This file is part of GNUnet.
     (C) 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @file peerinfo/test_peerinfo_api.c
 * @brief testcase for peerinfo_api.c
 * @author Christian Grothoff
 *
 * TODO:
 * - test merging of HELLOs (add same peer twice...)
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_program_lib.h"
#include "gnunet_time_lib.h"


static int
check_it (void *cls,
          const char *tname,
          struct GNUNET_TIME_Absolute expiration,
          const void *addr, size_t addrlen)
{
  unsigned int *agc = cls;

  if (addrlen > 0)
    {
      GNUNET_assert (0 == strcmp ("peerinfotest", tname));
      GNUNET_assert (0 == strncmp ("Address", addr, addrlen));
      (*agc) -= (1 << (addrlen - 1));
    }
  return GNUNET_OK;
}


static void
process (void *cls,
         const struct GNUNET_PeerIdentity *peer,
         const struct GNUNET_HELLO_Message *hello, uint32_t trust)
{
  int *ok = cls;
  unsigned int agc;

  if (peer == NULL)
    {
      GNUNET_assert (peer == NULL);
      GNUNET_assert (2 == *ok);
      GNUNET_assert (trust == 0);
      *ok = 0;
      return;
    }

  if (hello != NULL)
    {
      GNUNET_assert (3 == *ok);
      agc = 3;
      GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &check_it, &agc);
      GNUNET_assert (agc == 0);
      *ok = 2;
    }
}


static size_t
address_generator (void *cls, size_t max, void *buf)
{
  size_t *agc = cls;
  size_t ret;

  if (0 == *agc)
    return 0;
  ret = GNUNET_HELLO_add_address ("peerinfotest",
                                  GNUNET_TIME_relative_to_absolute
                                  (GNUNET_TIME_UNIT_HOURS), "Address", *agc,
                                  buf, max);
  (*agc)--;
  return ret;
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  size_t agc;
  struct GNUNET_PeerIdentity pid;

  memset (&pkey, 32, sizeof (pkey));
  GNUNET_CRYPTO_hash (&pkey, sizeof (pkey), &pid.hashPubKey);
  agc = 2;
  hello = GNUNET_HELLO_create (&pkey, &address_generator, &agc);
  GNUNET_assert (hello != NULL);
  GNUNET_PEERINFO_add_peer (cfg, sched, &pid, hello);
  GNUNET_PEERINFO_for_all (cfg,
                           sched,
                           NULL,
                           0,
                           GNUNET_TIME_relative_multiply
                           (GNUNET_TIME_UNIT_SECONDS, 15), &process, cls);
  GNUNET_free (hello);
}


static int
check ()
{
  int ok = 3;
  pid_t pid;
  char *const argv[] = { "test-peerinfo-api",
    "-c",
    "test_peerinfo_api_data.conf",
#if DEBUG_PEERINFO
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  pid = GNUNET_OS_start_process ("gnunet-service-peerinfo",
                                 "gnunet-service-peerinfo",
#if DEBUG_PEERINFO
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_peerinfo_api_data.conf", NULL);
  sleep (1);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-peerinfo-api", "nohelp",
                      options, &run, &ok);
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait(p->arm_pid);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret = 0;

  ret = check ();

  return ret;
}

/* end of test_peerinfo_api.c */
