/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009, 2015, 2016 GNUnet e.V.

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
 * @file transport-testing-filenames.c
 * @brief convenience string manipulation functions for tests
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "transport-testing.h"


/**
 * Removes all directory separators from absolute filename
 *
 * @param file the absolute file name, e.g. as found in argv[0]
 * @return extracted file name, has to be freed by caller
 */
static char *
extract_filename (const char *file)
{
  char *pch = GNUNET_strdup (file);
  char *backup = pch;
  char *filename = NULL;
  char *res;

#if WINDOWS
  if ((strlen (pch) >= 3) && pch[1] == ':')
  {
    if (NULL != strstr (pch, "\\"))
    {
      pch = strtok (pch, "\\");
      while (pch != NULL)
      {
        pch = strtok (NULL, "\\");
        if (pch != NULL)
          filename = pch;
      }
    }
  }
  if (filename != NULL)
    pch = filename; /* If we miss the next condition, filename = pch will
                     * not harm us.
                     */
#endif
  if (NULL != strstr (pch, "/"))
  {
    pch = strtok (pch, "/");
    while (pch != NULL)
    {
      pch = strtok (NULL, "/");
      if (pch != NULL)
      {
        filename = pch;
      }
    }
  }
  else
    filename = pch;

  res = GNUNET_strdup (filename);
  GNUNET_free (backup);
  return res;
}


/**
 * Extracts the test filename from an absolute file name and removes
 * the extension
 *
 * @param file absolute file name
 * @return the result
 */
char *
GNUNET_TRANSPORT_TESTING_get_test_name (const char *file)
{
  char *backup = extract_filename (file);
  char *filename = backup;
  char *dotexe;
  char *ret;

  if (NULL == filename)
    return NULL;

  /* remove "lt-" */
  filename = strstr (filename, "test");
  if (NULL == filename)
  {
    GNUNET_free (backup);
    return NULL;
  }

  /* remove ".exe" */
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';
  ret = GNUNET_strdup (filename);
  GNUNET_free (backup);
  return ret;
}


/**
 * Extracts the filename from an absolute file name and removes the extension
 *
 * @param file absolute file name
 * @return the result
 */
char *
GNUNET_TRANSPORT_TESTING_get_test_source_name (const char *file)
{
  char *src = extract_filename (file);
  char *split;

  split = strstr (src, ".");
  if (NULL != split)
    split[0] = '\0';
  return src;
}


/**
 * Extracts the plugin name from an absolute file name and the test name
 *
 * @param file absolute file name
 * @param test test name
 * @return the result
 */
char *
GNUNET_TRANSPORT_TESTING_get_test_plugin_name (const char *file,
                                               const char *test)
{
  char *filename;
  char *dotexe;
  char *e = extract_filename (file);
  char *t = extract_filename (test);
  char *ret;

  if (NULL == e)
    goto fail;
  /* remove "lt-" */
  filename = strstr (e, "tes");
  if (NULL == filename)
    goto fail;
  /* remove ".exe" */
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';

  /* find last _ */
  filename = strstr (filename, t);
  if (NULL == filename)
    goto fail;
  /* copy plugin */
  filename += strlen (t);
  if ('\0' != *filename)
    filename++;
  ret = GNUNET_strdup (filename);
  goto suc;
fail:
  ret = NULL;
suc:
  GNUNET_free (t);
  GNUNET_free (e);
  return ret;
}


/**
 * This function takes the filename (e.g. argv[0), removes a "lt-"-prefix and
 * if existing ".exe"-prefix and adds the peer-number
 *
 * @param file filename of the test, e.g. argv[0]
 * @param count peer number
 * @return the result
 */
char *
GNUNET_TRANSPORT_TESTING_get_config_name (const char *file,
                                          int count)
{
  char *filename = extract_filename (file);
  char *backup = filename;
  char *dotexe;
  char *ret;

  if (NULL == filename)
    return NULL;
  /* remove "lt-" */
  filename = strstr (filename, "test");
  if (NULL == filename)
    goto fail;
  /* remove ".exe" */
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';
  GNUNET_asprintf (&ret,
                   "%s_peer%u.conf",
                   filename,
                   count);
  GNUNET_free (backup);
  return ret;
fail:
  GNUNET_free (backup);
  return NULL;
}


/* end of transport-testing-filenames.c */
