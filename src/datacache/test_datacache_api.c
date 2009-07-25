/*
     This file is part of GNUnet.
     (C) 2006 Christian Grothoff (and other contributing authors)

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
 * @file applications/dstore/dstore_test.c
 * @brief Test for the dstore implementations.
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_dstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

static int error;

static int
checkIt (const GNUNET_HashCode * key,
         unsigned int type, unsigned int size, const char *data, void *cls)
{
  if (size != sizeof (GNUNET_HashCode))
    {
      printf ("ERROR: Invalid size\n");
      error = 2;
    }
  if (0 != memcmp (data, cls, size))
    {
      printf ("ERROR: Invalid data\n");
      error = 3;
    }
  return GNUNET_OK;
}

/**
 * Add testcode here!
 */
static int
test (GNUNET_Dstore_ServiceAPI * api)
{
  GNUNET_HashCode k;
  GNUNET_HashCode n;
  GNUNET_CronTime exp;
  unsigned int i;

  exp = GNUNET_get_time () + 5 * GNUNET_CRON_MINUTES;
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < 100; i++)
    {
      GNUNET_hash (&k, sizeof (GNUNET_HashCode), &n);
      ASSERT (GNUNET_OK == api->put (&k,
                                     i % 2,
                                     exp, sizeof (GNUNET_HashCode),
                                     (const char *) &n));
      k = n;
    }
  memset (&k, 0, sizeof (GNUNET_HashCode));
  for (i = 0; i < 100; i++)
    {
      GNUNET_hash (&k, sizeof (GNUNET_HashCode), &n);
      ASSERT (1 == api->get (&k, i % 2, &checkIt, &n));
      k = n;
    }
  return GNUNET_OK;
FAILURE:
  return GNUNET_SYSERR;
}

#define TEST_DB "/tmp/GNUnet_dstore_test/"

int
main (int argc, char *argv[])
{
  GNUNET_Dstore_ServiceAPI *api;
  int ok;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_CronManager *cron;

  GNUNET_disable_entropy_gathering ();
  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  cron = GNUNET_cron_create (NULL);
  GNUNET_CORE_init (NULL, cfg, cron, NULL);
  api = GNUNET_CORE_request_service ("dstore");
  if (api != NULL)
    {
      ok = test (api);
      GNUNET_CORE_release_service (api);
    }
  else
    ok = GNUNET_SYSERR;
  GNUNET_CORE_done ();
  if (ok == GNUNET_SYSERR)
    return 1;
  return error;
}

/* end of dstore_test.c */
