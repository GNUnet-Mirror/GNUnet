/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file datastore/test_datastore_api.c
 * @brief Test for the datastore implementation.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util.h"
#include "gnunet_protocols.h"
#include "gnunet_sqstore_service.h"
#include "core.h"

#define ASSERT(x) do { if (! (x)) { printf("Error at %s:%d\n", __FILE__, __LINE__); goto FAILURE;} } while (0)

static GNUNET_CronTime now;

static GNUNET_DatastoreValue *
initValue (int i)
{
  GNUNET_DatastoreValue *value;

  value = GNUNET_malloc (sizeof (GNUNET_DatastoreValue) + 8 * i);
  value->size = htonl (sizeof (GNUNET_DatastoreValue) + 8 * i);
  value->type = htonl (i);
  value->priority = htonl (i + 1);
  value->anonymity_level = htonl (i);
  value->expiration_time = GNUNET_htonll (now - i * GNUNET_CRON_SECONDS);
  memset (&value[1], i, 8 * i);
  return value;
}

static int
checkValue (const GNUNET_HashCode * key,
            const GNUNET_DatastoreValue * val, void *closure,
            unsigned long long uid)
{
  int i;
  int ret;
  GNUNET_DatastoreValue *value;

  i = *(int *) closure;
  value = initValue (i);
  if ((value->size == val->size) &&
      (0 == memcmp (val, value, ntohl (val->size))))
    ret = GNUNET_OK;
  else
    {
      /*
         printf("Wanted: %u, %llu; got %u, %llu - %d\n",
         ntohl(value->size), GNUNET_ntohll(value->expiration_time),
         ntohl(val->size), GNUNET_ntohll(val->expiration_time),
         memcmp(val, value, ntohl(val->size))); */
      ret = GNUNET_SYSERR;
    }
  GNUNET_free (value);
  return ret;
}

static int
iterateUp (const GNUNET_HashCode * key, const GNUNET_DatastoreValue * val,
           int *closure, unsigned long long uid)
{
  int ret;

  ret = checkValue (key, val, closure, uid);
  (*closure) += 2;
  return ret;
}

static int
iterateDown (const GNUNET_HashCode * key,
             const GNUNET_DatastoreValue * val, int *closure,
             unsigned long long uid)
{
  int ret;

  (*closure) -= 2;
  ret = checkValue (key, val, closure, uid);
  return ret;
}

static int
iterateDelete (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * val, void *closure,
               unsigned long long uid)
{
  return GNUNET_NO;
}

static int
iteratePriority (const GNUNET_HashCode * key,
                 const GNUNET_DatastoreValue * val,
                 GNUNET_SQstore_ServiceAPI * api, unsigned long long uid)
{
  api->update (uid, 4, 0);
  return GNUNET_OK;
}

static int
priorityCheck (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * val, int *closure,
               unsigned long long uid)
{
  int id;

  id = (*closure);
  if (id + 1 == ntohl (val->priority))
    return GNUNET_OK;
  fprintf (stderr,
           "Wrong priority, wanted %u got %u\n", id + 1,
           ntohl (val->priority));
  return GNUNET_SYSERR;
}

static int
multipleCheck (const GNUNET_HashCode * key,
               const GNUNET_DatastoreValue * val,
               GNUNET_DatastoreValue ** last, unsigned long long uid)
{
  if (*last != NULL)
    {
      if (((*last)->size == val->size) &&
          (0 == memcmp (*last, val, ntohl (val->size))))
        return GNUNET_SYSERR;   /* duplicate! */
      GNUNET_free (*last);
    }
  *last = GNUNET_malloc (ntohl (val->size));
  memcpy (*last, val, ntohl (val->size));
  return GNUNET_OK;
}


/**
 * Add testcode here!
 */
static int
test (GNUNET_SQstore_ServiceAPI * api)
{
  GNUNET_DatastoreValue *value;
  GNUNET_HashCode key;
  unsigned long long oldSize;
  int i;

  now = 1000000;
  oldSize = api->getSize ();
  for (i = 0; i < 256; i++)
    {
      value = initValue (i);
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      ASSERT (GNUNET_OK == api->put (&key, value));
      GNUNET_free (value);
    }
  ASSERT (oldSize < api->getSize ());
  for (i = 255; i >= 0; i--)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      ASSERT (1 == api->get (&key, NULL, i, &checkValue, (void *) &i));
    }
  ASSERT (256 ==
          api->iterateLowPriority (GNUNET_ECRS_BLOCKTYPE_ANY, NULL, NULL));
  ASSERT (256 ==
          api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY, NULL, NULL));
  for (i = 255; i >= 0; i--)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      ASSERT (1 == api->get (&key, NULL, i, &checkValue, (void *) &i));
    }

  oldSize = api->getSize ();
  for (i = 255; i >= 0; i -= 2)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      value = initValue (i);
      if (1 != api->get (&key, NULL, 0, &iterateDelete, NULL))
        {
          GNUNET_free (value);
          ASSERT (0);
        }
      GNUNET_free (value);
    }
  ASSERT (oldSize > api->getSize ());
  i = 0;
  ASSERT (128 == api->iterateLowPriority (GNUNET_ECRS_BLOCKTYPE_ANY,
                                          (GNUNET_DatastoreValueIterator) &
                                          iterateUp, &i));
  ASSERT (256 == i);
  ASSERT (128 == api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                             (GNUNET_DatastoreValueIterator) &
                                             iterateDown, &i));
  ASSERT (0 == i);
  ASSERT (128 == api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                             (GNUNET_DatastoreValueIterator) &
                                             iterateDelete, api));
  i = 0;
  ASSERT (0 ==
          api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                      (GNUNET_DatastoreValueIterator) &
                                      iterateDown, &i));
  i = 42;
  value = initValue (i);
  memset (&key, 256 - i, sizeof (GNUNET_HashCode));
  api->put (&key, value);
  ASSERT (1 == api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                           (GNUNET_DatastoreValueIterator) &
                                           priorityCheck, &i));
  ASSERT (1 == api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                           (GNUNET_DatastoreValueIterator) &
                                           priorityCheck, &i));
  ASSERT (1 ==
          api->iterateAllNow ((GNUNET_DatastoreValueIterator) &
                              iteratePriority, api));
  i += 4;
  ASSERT (1 == api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                           (GNUNET_DatastoreValueIterator) &
                                           priorityCheck, &i));
  GNUNET_free (value);

  /* test multiple results */
  value = initValue (i + 1);
  api->put (&key, value);
  GNUNET_free (value);

  value = NULL;
  ASSERT (2 == api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY,
                                           (GNUNET_DatastoreValueIterator) &
                                           multipleCheck, &value));
  GNUNET_free (value);
  ASSERT (2 ==
          api->iterateAllNow ((GNUNET_DatastoreValueIterator) & iterateDelete,
                              api));
  ASSERT (0 ==
          api->iterateExpirationTime (GNUNET_ECRS_BLOCKTYPE_ANY, NULL, NULL));
  api->drop ();

  return GNUNET_OK;

FAILURE:
  api->drop ();
  return GNUNET_SYSERR;
}

int
main (int argc, char *argv[])
{
  GNUNET_SQstore_ServiceAPI *api;
  int ok;
  struct GNUNET_GC_Configuration *cfg;
  struct GNUNET_CronManager *cron;

  cfg = GNUNET_GC_create ();
  if (-1 == GNUNET_GC_parse_configuration (cfg, "check.conf"))
    {
      GNUNET_GC_free (cfg);
      return -1;
    }
  cron = GNUNET_cron_create (NULL);
  GNUNET_CORE_init (NULL, cfg, cron, NULL);
  api = GNUNET_CORE_request_service ("sqstore");
  if (api != NULL)
    {
      ok = test (api);
      GNUNET_CORE_release_service (api);
    }
  else
    ok = GNUNET_SYSERR;
  GNUNET_CORE_done ();
  GNUNET_cron_destroy (cron);
  GNUNET_GC_free (cfg);
  if (ok == GNUNET_SYSERR)
    return 1;
  return 0;
}

/* end of test_datastore_api.c */
