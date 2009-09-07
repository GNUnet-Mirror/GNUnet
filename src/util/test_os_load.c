/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_os_load.c
 * @brief testcase for util/os_load.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_time_lib.h"

#define VERBOSE 0

static int
testcpu ()
{
  static long k;
  int ret;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  fprintf (stderr, "CPU load test, this may take a while.");
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (cfg != NULL);
  /* need to run each phase for more than 10s since
     statuscalls only refreshes that often... */
  GNUNET_CONFIGURATION_set_value_number (cfg, "LOAD", "MAXCPULOAD", 100);
  GNUNET_OS_load_cpu_get (cfg);
  start = GNUNET_TIME_absolute_get ();
  while ((GNUNET_TIME_absolute_get_duration (start).value < 120 * 1000) &&
         (0 != GNUNET_OS_load_cpu_get (cfg)))
    sleep (1);
  start = GNUNET_TIME_absolute_get ();
  ret = GNUNET_OS_load_cpu_get (cfg);
  if (ret > 10)
    {
      fprintf (stderr,
               "\nWARNING: base load too high (%d) to run CPU load test.\n",
               ret);
      GNUNET_CONFIGURATION_destroy (cfg);
      return 0;
    }
  if (ret == -1)
    {
      fprintf (stderr, "\nWARNING: CPU load determination not supported.\n");
      GNUNET_CONFIGURATION_destroy (cfg);
      return 0;
    }
  while (GNUNET_TIME_absolute_get_duration (start).value < 60 * 1000)
    {
      k++;                      /* do some processing to drive load up */
      if (ret < GNUNET_OS_load_cpu_get (cfg))
        break;
    }
  if (ret >= GNUNET_OS_load_cpu_get (cfg))
    {
      fprintf (stderr,
               "\nbusy loop failed to increase CPU load: %d >= %d.",
               ret, GNUNET_OS_load_cpu_get (cfg));
      ret = 1;
    }
  else
    {
#if VERBOSE
      fprintf (stderr,
               "\nbusy loop increased CPU load: %d < %d.",
               ret, GNUNET_OS_load_cpu_get (cfg));
#endif
      ret = 0;
    }
  fprintf (stderr, "\n");


  GNUNET_CONFIGURATION_destroy (cfg);
  return ret;
}

static int
testdisk ()
{
  int ret;
  struct GNUNET_DISK_FileHandle *fh;
  char buf[65536];
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  fprintf (stderr, "IO load test, this may take a while.");
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (cfg != NULL);
  /* need to run each phase for more than 10s since
     statuscalls only refreshes that often... */
  GNUNET_CONFIGURATION_set_value_number (cfg, "LOAD", "MAXIOLOAD", 100);
  GNUNET_OS_load_disk_get (cfg);
  start = GNUNET_TIME_absolute_get ();
  while ((GNUNET_TIME_absolute_get_duration (start).value < 12 * 1000) &&
         (0 != GNUNET_OS_load_disk_get (cfg)))
    sleep (1);
  start = GNUNET_TIME_absolute_get ();
  ret = GNUNET_OS_load_disk_get (cfg);
  if (ret > 10)
    {
      fprintf (stderr,
               "WARNING: base load too high (%d) to run IO load test.\n",
               ret);
      GNUNET_CONFIGURATION_destroy (cfg);
      return 0;
    }
  if (ret == -1)
    {
      fprintf (stderr, "WARNING: IO load determination not supported.\n");
      GNUNET_CONFIGURATION_destroy (cfg);
      return 0;
    }
  memset (buf, 42, sizeof (buf));
  fh = GNUNET_DISK_file_open (".loadfile", GNUNET_DISK_OPEN_WRITE
      | GNUNET_DISK_OPEN_CREATE, GNUNET_DISK_PERM_USER_READ
      | GNUNET_DISK_PERM_USER_WRITE);
  GNUNET_assert (GNUNET_NO == GNUNET_DISK_handle_invalid(fh));
  while (GNUNET_TIME_absolute_get_duration (start).value < 60 * 1000)
    {
      GNUNET_DISK_file_seek (fh, GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                           1024 * 1024 * 1024), GNUNET_DISK_SEEK_SET);
      GNUNET_assert (sizeof (buf) == GNUNET_DISK_file_write (fh, buf, sizeof (buf)));
      GNUNET_DISK_file_sync (fh);
      if (ret < GNUNET_OS_load_disk_get (cfg))
        break;
    }
  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fh));
  GNUNET_break (0 == UNLINK (".loadfile"));
  if (ret >= GNUNET_OS_load_disk_get (cfg))
    {
      fprintf (stderr,
               "\nbusy loop failed to increase IO load: %d >= %d.",
               ret, GNUNET_OS_load_disk_get (cfg));
      ret = 1;
    }
  else
    {
#if VERBOSE
      fprintf (stderr,
               "\nbusy loop increased disk load: %d < %d.",
               ret, GNUNET_OS_load_disk_get (cfg));
#endif
      ret = 0;
    }
  fprintf (stderr, "\n");
  GNUNET_CONFIGURATION_destroy (cfg);
  return ret;
}

int
main (int argc, char *argv[])
{
  int errCnt = 0;

  GNUNET_log_setup ("test-os-load", "WARNING", NULL);
  if (0 != testcpu ())
    errCnt++;
  if (0 != testdisk ())
    errCnt++;
  return errCnt;
}
