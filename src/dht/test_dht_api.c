/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2015, 2017 GNUnet e.V.

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
 * @file dht/test_dht_api.c
 * @brief base test case for dht api
 * @author Christian Grothoff
 *
 * This test case tests DHT api to DUMMY DHT service communication.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dht_service.h"


/**
 * How long until we really give up on a particular testcase portion?
 */
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

static struct GNUNET_DHT_Handle *dht_handle;

static struct GNUNET_DHT_GetHandle *get_handle;

static struct GNUNET_DHT_PutHandle *put_handle;

static int ok = 1;

static struct GNUNET_SCHEDULER_Task *die_task;


static void
do_shutdown (void *cls)
{
  if (NULL != die_task)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = NULL;
  }
  if (NULL != put_handle)
  {
    GNUNET_DHT_put_cancel (put_handle);
    put_handle = NULL;
  }
  if (NULL != get_handle)
  {
    GNUNET_DHT_get_stop (get_handle);
    get_handle = NULL;
  }
  GNUNET_DHT_disconnect (dht_handle);
  dht_handle = NULL;
}


static void
end_badly (void *cls)
{
  die_task = NULL;
  FPRINTF (stderr,
           "%s",
           "Ending on an unhappy note.\n");
  GNUNET_SCHEDULER_shutdown ();
  ok = 1;
}


static void
test_get_iterator (void *cls,
                   struct GNUNET_TIME_Absolute exp,
                   const struct GNUNET_HashCode *key,
                   const struct GNUNET_PeerIdentity *get_path,
                   unsigned int get_path_length,
                   const struct GNUNET_PeerIdentity *put_path,
                   unsigned int put_path_length,
                   enum GNUNET_BLOCK_Type type,
                   size_t size,
                   const void *data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test_get_iterator called (we got a result), stopping get request!\n");
  GNUNET_SCHEDULER_shutdown ();
  ok = 0;
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param success result of PUT
 */
static void
test_get (void *cls,
          int success)
{
  struct GNUNET_HashCode hash;

  put_handle = NULL;
  memset (&hash,
          42,
          sizeof (struct GNUNET_HashCode));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called test_get!\n");
  GNUNET_assert (dht_handle != NULL);
  get_handle = GNUNET_DHT_get_start (dht_handle,
                                     GNUNET_BLOCK_TYPE_TEST,
                                     &hash,
                                     1,
                                     GNUNET_DHT_RO_NONE,
                                     NULL,
                                     0,
                                     &test_get_iterator,
                                     NULL);

  if (NULL == get_handle)
  {
    GNUNET_break (0);
    ok = 1;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_HashCode hash;
  char *data;
  size_t data_size = 42;

  GNUNET_assert (ok == 1);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  die_task = GNUNET_SCHEDULER_add_delayed (TOTAL_TIMEOUT,
                                           &end_badly,
                                           NULL);
  memset (&hash,
          42,
          sizeof (struct GNUNET_HashCode));
  data = GNUNET_malloc (data_size);
  memset (data, 43, data_size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called test_put!\n");
  dht_handle = GNUNET_DHT_connect (cfg,
                                   100);
  GNUNET_assert (NULL != dht_handle);
  put_handle = GNUNET_DHT_put (dht_handle,
                               &hash,
                               1,
                               GNUNET_DHT_RO_NONE,
                               GNUNET_BLOCK_TYPE_TEST,
                               data_size,
                               data,
                               GNUNET_TIME_relative_to_absolute (TOTAL_TIMEOUT),
                               &test_get,
                               NULL);
  GNUNET_free (data);
}


int
main (int argc,
      char *argv[])
{
  if (0 != GNUNET_TESTING_peer_run ("test-dht-api",
				    "test_dht_api_data.conf",
				    &run, NULL))
    return 1;
  return ok;
}

/* end of test_dht_api.c */
