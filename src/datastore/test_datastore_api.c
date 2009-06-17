/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 * - test multiple values under same key
 * - test "update"
 * - test storage reservations
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_datastore_service.h"

static struct GNUNET_DATASTORE_Handle *datastore;

static struct GNUNET_TIME_Absolute now;


static size_t
get_size (int i)
{
  return 8 * i;
}


static const void *
get_data (int i)
{
  static char buf[60000]; 
  memset (buf, i, 8 * i);
  return buf;
}


static int
get_type(int i)
{
  return i;
}


static int 
get_priority (int i)
{
  return i+1;
}


static int
get_anonymity(int i)
{
  return i;
}


static struct GNUNET_TIME_Absolute 
get_expiration (int i)
{
  struct GNUNET_TIME_Absolute av;

  av.value = now.value - i * 1000;
  return av;
}


static void
check_success (void *cls,
	       int success,
	       const char *msg)
{
  GNUNET_assert (GNUNET_OK == success);
}


static void
check_failure (void *cls,
	       int success,
	       const char *msg)
{
  GNUNET_assert (GNUNET_OK != success);
  GNUNET_assert (NULL != msg);
}


static void 
check_value (void *cls,
	     const GNUNET_HashCode * key,
	     uint32_t size,
	     const void *data,
	     uint32_t type,
	     uint32_t priority,
	     uint32_t anonymity,
	     struct GNUNET_TIME_Absolute
	     expiration, uint64_t uid)
{
  int *iptr = cls;
  int i;

  if (key == NULL)
    return;
  i = *iptr;
  GNUNET_assert (size == get_size (i));
  GNUNET_assert (0 == memcmp (data, get_data(i), size));
  GNUNET_assert (type == get_type (i));
  GNUNET_assert (priority == get_priority (i));
  GNUNET_assert (anonymity == get_anonymity(i));
  GNUNET_assert (expiration.value == get_expiration(i).value);
}


static void 
delete_value (void *cls,
	     const GNUNET_HashCode * key,
	     uint32_t size,
	     const void *data,
	     uint32_t type,
	     uint32_t priority,
	     uint32_t anonymity,
	     struct GNUNET_TIME_Absolute
	     expiration, uint64_t uid)
{
  if (key == NULL)
    return;
  GNUNET_DATASTORE_remove (datastore,
			   key,
			   size,
			   data,
			   &check_success,
			   NULL);
  ((int*)key)[0]++;
  GNUNET_DATASTORE_remove (datastore,
			   key,
			   size,
			   data,
			   &check_failure,
			   NULL);
}



static void 
check_nothing (void *cls,
	     const GNUNET_HashCode * key,
	     uint32_t size,
	     const void *data,
	     uint32_t type,
	     uint32_t priority,
	     uint32_t anonymity,
	     struct GNUNET_TIME_Absolute
	     expiration, uint64_t uid)
{
  GNUNET_assert (key == NULL);
}



static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile, struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_HashCode key;
  int i;
  int *iptr;

  datastore = GNUNET_DATASTORE_connect (cfg, sched);
  now.value = 1000000;
  for (i = 0; i < 256; i++)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      GNUNET_DATASTORE_put (datastore,
			    0,
			    &key,
			    get_size (i),
			    get_data (i),
			    get_type (i),
			    get_priority (i),
			    get_anonymity (i),
			    get_expiration (i),
			    &check_success,
			    NULL);
    }
  for (i = 255; i >= 0; i--)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      iptr = GNUNET_malloc(sizeof(int));
      *iptr = i;
      GNUNET_DATASTORE_get (datastore, 
			    &key,
			    get_type (i),
			    &check_value,
			    iptr);
    }
  for (i = 255; i >= 0; i--)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      iptr = GNUNET_malloc(sizeof(int));
      *iptr = i;
      GNUNET_DATASTORE_get (datastore, 
			    &key,
			    get_type (i),
			    &delete_value,
			    iptr);
    }
  for (i = 255; i >= 0; i--)
    {
      memset (&key, 256 - i, sizeof (GNUNET_HashCode));
      iptr = GNUNET_malloc(sizeof(int));
      *iptr = i;
      GNUNET_DATASTORE_get (datastore, 
			    &key,
			    get_type (i),
			    &check_nothing,
			    iptr);
    }
  /* check reservations */

  /* check update */

  /* test multiple results */

  GNUNET_DATASTORE_disconnect (datastore, GNUNET_YES);
}



static int
check ()
{
  int ok = 1 + 2 + 4 + 8;
  pid_t pid;
  char *const argv[] = { "test-datastore-api",
    "-c",
    "test_datastore_api_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  pid = GNUNET_OS_start_process ("gnunet-service-datastore",
                                 "gnunet-service-datastore",
#if VERBOSE
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_datastore_api_data.conf", NULL);
  sleep (1);
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-datastore-api", "nohelp",
                      options, &run, &ok);
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait(pid);
  if (ok != 0)
    fprintf (stderr, "Missed some testcases: %u\n", ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-datastore-api",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();

  return ret;
}



/* end of test_datastore_api.c */
