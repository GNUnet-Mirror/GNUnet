/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file fs/gnunet-fs.c
 * @brief special file-sharing functions
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"

/**
 * Return value.
 */
static int ret;

/**
 * Handle to FS service.
 */
static struct GNUNET_FS_Handle *fs;

/**
 * Option -i given?
 */
static int list_indexed_files;

/**
 * Option -v given?
 */
static unsigned int verbose;


/**
 * Print indexed filenames to stdout.
 *
 * @param cls closure
 * @param filename the name of the file
 * @param file_id hash of the contents of the indexed file
 * @return GNUNET_OK to continue iteration
 */
static int
print_indexed (void *cls,
               const char *filename,
               const struct GNUNET_HashCode *file_id)
{
  if (NULL == filename)
  {
    GNUNET_FS_stop (fs);
    fs = NULL;
    return GNUNET_OK;
  }
  if (verbose)
    fprintf (stdout, "%s: %s\n", GNUNET_h2s (file_id), filename);
  else
    fprintf (stdout, "%s\n", filename);
  return GNUNET_OK;
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (list_indexed_files)
  {
    fs = GNUNET_FS_start (cfg,
                          "gnunet-fs",
                          NULL,
                          NULL,
                          GNUNET_FS_FLAGS_NONE,
                          GNUNET_FS_OPTIONS_END);
    if (NULL == fs)
    {
      ret = 1;
      return;
    }
    if (NULL == GNUNET_FS_get_indexed_files (fs, &print_indexed, NULL))
    {
      ret = 2;
      GNUNET_FS_stop (fs);
      fs = NULL;
      return;
    }
  }
}


/**
 * The main function to access special file-sharing functions.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_flag ('i',
                               "list-indexed",
                               gettext_noop (
                                 "print a list of all indexed files"),
                               &list_indexed_files),

    GNUNET_GETOPT_option_verbose (&verbose),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc,
                             argv,
                             "gnunet-fs [OPTIONS]",
                             gettext_noop ("Special file-sharing operations"),
                             options,
                             &run,
                             NULL))
        ? ret
        : 1;
  GNUNET_free ((void *) argv);
  return ret;
}


/* end of gnunet-fs.c */
