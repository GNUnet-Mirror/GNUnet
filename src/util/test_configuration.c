/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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
 * @file util/test_configuration.c
 * @brief Test that the configuration module works.
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_disk_lib.h"

#define DEBUG GNUNET_EXTRA_LOGGING

/* Test Configuration Diffs Options */
enum
{
  EDIT_NOTHING,
  EDIT_SECTION,
  EDIT_ALL,
  ADD_NEW_SECTION,
  ADD_NEW_ENTRY,
  REMOVE_SECTION,
  REMOVE_ENTRY,
  COMPARE
#if DEBUG
      , PRINT
#endif
};

static struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_CONFIGURATION_Handle *cfgDefault;

struct DiffsCBData
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CONFIGURATION_Handle *cfgDiffs;
  const char *section;
  int callBackOption;
  int status;
};


static void
initDiffsCBData (struct DiffsCBData *cbData)
{
  cbData->section = NULL;
  cbData->cfg = NULL;
  cbData->cfgDiffs = NULL;
  cbData->callBackOption = -1;
  cbData->status = 0;
}


/**
 * callback function for modifying
 * and comparing configuration
*/
static void
diffsCallBack (void *cls, const char *section, const char *option,
               const char *value)
{
  struct DiffsCBData *cbData = cls;
  int cbOption = cbData->callBackOption;

  switch (cbOption)
  {
  case EDIT_SECTION:
    if (NULL == cbData->section)
      cbData->section = section;
    if (strcmp (cbData->section, section) == 0)
    {
      GNUNET_CONFIGURATION_set_value_string (cbData->cfg, section, option,
                                             "new-value");
      GNUNET_CONFIGURATION_set_value_string (cbData->cfgDiffs, section, option,
                                             "new-value");
    }
    break;
  case EDIT_ALL:
    GNUNET_CONFIGURATION_set_value_string (cbData->cfg, section, option,
                                           "new-value");
    GNUNET_CONFIGURATION_set_value_string (cbData->cfgDiffs, section, option,
                                           "new-value");
    break;
  case ADD_NEW_ENTRY:
  {
    static int hit = 0;

    if (hit == 0)
    {
      hit = 1;
      GNUNET_CONFIGURATION_set_value_string (cbData->cfg, section, "new-key",
                                             "new-value");
      GNUNET_CONFIGURATION_set_value_string (cbData->cfgDiffs, section,
                                             "new-key", "new-value");
    }
    break;
  }
  case COMPARE:
  {
    int ret;
    char *diffValue;

    diffValue = NULL;
    ret =
        GNUNET_CONFIGURATION_get_value_string (cbData->cfgDiffs, section,
                                               option, &diffValue);
    if (NULL != diffValue)
    {
      if (ret == GNUNET_SYSERR || strcmp (diffValue, value) != 0)
        cbData->status = 1;
    }
    else
      cbData->status = 1;
    GNUNET_free_non_null (diffValue);
    break;
  }
#if 0
  case PRINT:
    if (NULL == cbData->section)
    {
      cbData->section = section;
      printf ("\nSection: %s\n", section);
    }
    else if (strcmp (cbData->section, section) != 0)
    {
      cbData->section = section;
      printf ("\nSection: %s\n", section);
    }
    printf ("%s = %s\n", option, value);
#endif
  default:
    break;
  }
}


static struct GNUNET_CONFIGURATION_Handle *
editConfiguration (struct GNUNET_CONFIGURATION_Handle *cfg, int option)
{
  struct DiffsCBData diffsCB;

  initDiffsCBData (&diffsCB);
  diffsCB.cfgDiffs = GNUNET_CONFIGURATION_create ();

  switch (option)
  {
  case EDIT_SECTION:
  case EDIT_ALL:
  case ADD_NEW_ENTRY:
    diffsCB.callBackOption = option;
    diffsCB.cfg = cfg;
    GNUNET_CONFIGURATION_iterate (cfg, diffsCallBack, &diffsCB);
    break;
  case EDIT_NOTHING:
    /* Do nothing */
    break;
  case ADD_NEW_SECTION:
  {
    int i;
    char *key;

    for (i = 0; i < 5; i++)
    {
      GNUNET_asprintf (&key, "key%d", i);
      GNUNET_CONFIGURATION_set_value_string (cfg, "new-section", key,
                                             "new-value");
      GNUNET_CONFIGURATION_set_value_string (diffsCB.cfgDiffs, "new-section",
                                             key, "new-value");
      GNUNET_free (key);
    }
    break;
  }
  case REMOVE_SECTION:
    break;
  case REMOVE_ENTRY:
    break;
  default:
    break;
  }

  return diffsCB.cfgDiffs;
}

/**
 * Checking configuration diffs
 */
static int
checkDiffs (struct GNUNET_CONFIGURATION_Handle *cfgDefault, int option)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CONFIGURATION_Handle *cfgDiffs;
  struct DiffsCBData cbData;
  int ret;
  char *diffsFileName;

  initDiffsCBData (&cbData);

  cfg = GNUNET_CONFIGURATION_create ();
  /* load defaults */
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (cfg, NULL));

  /* Modify configuration and save it */
  cfgDiffs = editConfiguration (cfg, option);
  diffsFileName = GNUNET_DISK_mktemp ("gnunet-test-configurations-diffs.conf");
  if (diffsFileName == NULL)
  {
    GNUNET_break (0);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_CONFIGURATION_destroy (cfgDiffs);
    return 1;
  }
  GNUNET_CONFIGURATION_write_diffs (cfgDefault, cfg, diffsFileName);
  GNUNET_CONFIGURATION_destroy (cfg);

  /* Compare the dumped configuration with modifications done */
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_parse (cfg, diffsFileName));
  remove (diffsFileName);
  cbData.callBackOption = COMPARE;
  cbData.cfgDiffs = cfgDiffs;
  GNUNET_CONFIGURATION_iterate (cfg, diffsCallBack, &cbData);
  if (1 == (ret = cbData.status))
  {
    FPRINTF (stderr, "%s", 
             "Incorrect Configuration Diffs: Diffs may contain data not actually edited\n");
    goto housekeeping;
  }
  cbData.cfgDiffs = cfg;
  GNUNET_CONFIGURATION_iterate (cfgDiffs, diffsCallBack, &cbData);
  if ((ret = cbData.status) == 1)
    FPRINTF (stderr, "%s", 
             "Incorrect Configuration Diffs: Data may be missing in diffs\n");

housekeeping:
#if 0
  cbData.section = NULL;
  cbData.callBackOption = PRINT;
  printf ("\nExpected Diffs:\n");
  GNUNET_CONFIGURATION_iterate (cfgDiffs, diffsCallBack, &cbData);
  cbData.section = NULL;
  printf ("\nActual Diffs:\n");
  GNUNET_CONFIGURATION_iterate (cfg, diffsCallBack, &cbData);
#endif
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_CONFIGURATION_destroy (cfgDiffs);
  GNUNET_free (diffsFileName);
  return ret;
}


static int
testConfig ()
{
  char *c;
  unsigned long long l;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "test", "b", &c))
    return 1;
  if (0 != strcmp ("b", c))
  {
    FPRINTF (stderr, "Got `%s'\n", c);
    GNUNET_free (c);
    return 2;
  }
  GNUNET_free (c);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "test", "five", &l))
  {
    GNUNET_break (0);
    return 3;
  }
  if (5 != l)
  {
    GNUNET_break (0);
    return 4;
  }
  GNUNET_CONFIGURATION_set_value_string (cfg, "more", "c", "YES");
  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_yesno (cfg, "more", "c"))
  {
    GNUNET_break (0);
    return 5;
  }
  GNUNET_CONFIGURATION_set_value_number (cfg, "NUMBERS", "TEN", 10);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "NUMBERS", "TEN", &c))
  {
    GNUNET_break (0);
    return 6;
  }
  if (0 != strcmp (c, "10"))
  {
    GNUNET_free (c);
    GNUNET_break (0);
    return 7;
  }
  GNUNET_free (c);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "last", "test", &c))
  {
    GNUNET_break (0);
    return 8;
  }
#ifndef MINGW
  if (0 != strcmp (c, "/hello/world"))
#else
#define HI "\\hello\\world"
  if (strstr (c, HI) != c + strlen (c) - strlen (HI))
#endif
  {
    GNUNET_break (0);
    GNUNET_free (c);
    return 9;
  }
  GNUNET_free (c);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_size (cfg, "last", "size", &l))
  {
    GNUNET_break (0);
    return 10;
  }
  if (l != 512 * 1024)
  {
    GNUNET_break (0);
    return 11;
  }
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
  GNUNET_break (0);
  return GNUNET_SYSERR;
}

static int
testConfigFilenames ()
{
  int idx;

  idx = 0;
  if (3 !=
      GNUNET_CONFIGURATION_iterate_value_filenames (cfg, "FILENAMES", "test",
                                                    &check, &idx))
  {
    GNUNET_break (0);
    return 8;
  }
  if (idx != 3)
    return 16;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_remove_value_filename (cfg, "FILENAMES", "test",
                                                  "/File Name"))
  {
    GNUNET_break (0);
    return 24;
  }

  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_remove_value_filename (cfg, "FILENAMES", "test",
                                                  "/File Name"))
  {
    GNUNET_break (0);
    return 32;
  }
  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_remove_value_filename (cfg, "FILENAMES", "test",
                                                  "Stuff"))
  {
    GNUNET_break (0);
    return 40;
  }

  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_append_value_filename (cfg, "FILENAMES", "test",
                                                  "/Hello"))
  {
    GNUNET_break (0);
    return 48;
  }
  if (GNUNET_NO !=
      GNUNET_CONFIGURATION_append_value_filename (cfg, "FILENAMES", "test",
                                                  "/World"))
  {
    GNUNET_break (0);
    return 56;
  }

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_append_value_filename (cfg, "FILENAMES", "test",
                                                  "/File 1"))
  {
    GNUNET_break (0);
    return 64;
  }

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_append_value_filename (cfg, "FILENAMES", "test",
                                                  "/File 2"))
  {
    GNUNET_break (0);
    return 72;
  }

  idx = 0;
  want[1] = "/World";
  want[2] = "/File 1";
  want[3] = "/File 2";
  if (4 !=
      GNUNET_CONFIGURATION_iterate_value_filenames (cfg, "FILENAMES", "test",
                                                    &check, &idx))
  {
    GNUNET_break (0);
    return 80;
  }
  if (idx != 4)
  {
    GNUNET_break (0);
    return 88;
  }
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
    FPRINTF (stderr, "%s",  "Failed to parse configuration file\n");
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  failureCount += testConfig ();
  if (failureCount > 0)
    goto error;

  failureCount = testConfigFilenames ();
  if (failureCount > 0)
    goto error;

  if (GNUNET_OK != GNUNET_CONFIGURATION_write (cfg, "/tmp/gnunet-test.conf"))
  {
    FPRINTF (stderr, "%s",  "Failed to write configuration file\n");
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "TESTING", "WEAKRANDOM", &c))
  {
    GNUNET_break (0);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }
  if (0 != strcmp (c, "YES"))
  {
    GNUNET_break (0);
    GNUNET_free (c);
    GNUNET_CONFIGURATION_destroy (cfg);
    return 1;
  }

  GNUNET_free (c);
  GNUNET_CONFIGURATION_destroy (cfg);

  /* Testing configuration diffs */
  cfgDefault = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfgDefault, NULL))
  {
    GNUNET_break (0);
    GNUNET_CONFIGURATION_destroy (cfgDefault);
    return 1;
  }

  /* Nothing changed in the new configuration */
  failureCount += checkDiffs (cfgDefault, EDIT_NOTHING);

  /* Modify all entries of the last section */
  failureCount += checkDiffs (cfgDefault, EDIT_SECTION);

  /* Add a new section */
  failureCount += checkDiffs (cfgDefault, ADD_NEW_SECTION);

  /* Add a new entry to the last section */
  failureCount += checkDiffs (cfgDefault, ADD_NEW_ENTRY);

  /* Modify all entries in the configuration */
  failureCount += checkDiffs (cfgDefault, EDIT_ALL);

  GNUNET_CONFIGURATION_destroy (cfgDefault);

error:
  if (failureCount != 0)
  {
    FPRINTF (stderr, "Test failed: %u\n", failureCount);
    return 1;
  }
  return 0;
}
