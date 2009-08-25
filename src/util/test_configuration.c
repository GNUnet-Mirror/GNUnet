/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/test_configuration.c
 * @brief Test that the configuration module works.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"

static struct GNUNET_CONFIGURATION_Handle *cfg;

static int
testConfig ()
{
  char *c;
  unsigned long long l;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "test", "b", &c))
    return 1;
  if (0 != strcmp ("b", c))
    {
      fprintf (stderr, "Got `%s'\n", c);
      GNUNET_free (c);
      return 2;
    }
  GNUNET_free (c);
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "test", "five", &l))
    return 3;
  if (5 != l)
    return 4;
  GNUNET_CONFIGURATION_set_value_string (cfg, "more", "c", "YES");
  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_yesno (cfg, "more", "c"))
    return 5;
  GNUNET_CONFIGURATION_set_value_number (cfg, "NUMBERS", "TEN", 10);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "NUMBERS", "TEN", &c))
    return 6;
  if (0 != strcmp (c, "10"))
    {
      GNUNET_free (c);
      return 7;
    }
  GNUNET_free (c);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "last", "test", &c))
    return 8;
#ifndef MINGW
  if (0 != strcmp (c, "/hello/world"))
#else
  #define HI "\\hello\\world"
  if (strstr (c, HI) != c + strlen (c) - strlen (HI))
#endif
    {
      GNUNET_free (c);
      return 9;
    }
  GNUNET_free (c);

  return 0;
}

static const char *want[] = {
  "/Hello",
  "/File Name",
  "/World",
  NULL,
  NULL,
};

static int
check (void *data, const char *fn)
{
  int *idx = data;

  if (0 == strcmp (want[*idx], fn))
    {
      (*idx)++;
      return GNUNET_OK;
    }
  return GNUNET_SYSERR;
}

static int
testConfigFilenames ()
{
  int idx;

  idx = 0;
  if (3 != GNUNET_CONFIGURATION_iterate_value_filenames (cfg,
                                                         "FILENAMES",
                                                         "test",
                                                         &check, &idx))
    return 8;
  if (idx != 3)
    return 16;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_remove_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "/File Name"))
    return 24;

  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_remove_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "/File Name"))
    return 32;
  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_remove_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "Stuff"))
    return 40;

  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_append_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "/Hello"))
    return 48;
  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_append_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "/World"))
    return 56;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_append_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "/File 1"))
    return 64;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_append_value_filename (cfg,
                                                  "FILENAMES",
                                                  "test", "/File 2"))
    return 72;

  idx = 0;
  want[1] = "/World";
  want[2] = "/File 1";
  want[3] = "/File 2";
  if (4 != GNUNET_CONFIGURATION_iterate_value_filenames (cfg,
                                                         "FILENAMES",
                                                         "test",
                                                         &check, &idx))
    return 80;
  if (idx != 4)
    return 88;
  return 0;
}

int
main (int argc, char *argv[])
{
  int failureCount = 0;
  char *c;

  GNUNET_log_setup ("test_configuration", "WARNING", NULL);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (cfg != NULL);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_parse (cfg, "test_configuration_data.conf"))
    {
      fprintf (stderr, "Failed to parse configuration file\n");
      GNUNET_CONFIGURATION_destroy (cfg);
      return 1;
    }
  failureCount += testConfig ();
  failureCount += 2 * testConfigFilenames ();

  if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg, "/tmp/gnunet-test.conf"))
    {
      fprintf (stderr, "Failed to write configuration file\n");
      GNUNET_CONFIGURATION_destroy (cfg);
      return 1;
    }
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_assert (0 == UNLINK ("/tmp/gnunet-test.conf"));

  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (cfg, "test_configuration_data.conf"))
    {
      GNUNET_break (0);
      GNUNET_CONFIGURATION_destroy (cfg);
      return 1;
    }
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_string (cfg, "TESTING", "WEAKRANDOM",
                                              &c))
      || (0 != strcmp (c, "YES")))
    {
      GNUNET_CONFIGURATION_destroy (cfg);
      return 1;
    }
  GNUNET_free (c);
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS", "SERVICEHOME",
                                              &c))
      || (0 != strcmp (c, "/var/lib/gnunet/")))
    {
      GNUNET_CONFIGURATION_destroy (cfg);
      return 1;
    }
  GNUNET_free (c);
  GNUNET_CONFIGURATION_destroy (cfg);
  if (failureCount != 0)
    {
      fprintf (stderr, "Test failed: %u\n", failureCount);
      return 1;
    }
  return 0;
}
