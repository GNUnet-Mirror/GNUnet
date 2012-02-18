/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
static int verbose;


/**
 * Print indexed filenames to stdout.
 *
 * @param cls closure
 * @param filename the name of the file
 * @param file_id hash of the contents of the indexed file
 * @return GNUNET_OK to continue iteration
 */
static int
print_indexed (void *cls, const char *filename, const GNUNET_HashCode * file_id)
{
  if (NULL == filename)
  {
    GNUNET_FS_stop (fs);
    fs = NULL;
    return GNUNET_OK;
  }
  if (verbose)
    FPRINTF (stdout, "%s: %s\n", GNUNET_h2s (file_id), filename);
  else
    FPRINTF (stdout, "%s\n", filename);
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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  if (list_indexed_files)
  {
    fs = GNUNET_FS_start (cfg, "gnunet-fs", NULL, NULL, GNUNET_FS_FLAGS_NONE,
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
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'i', "list-indexed", NULL,
     gettext_noop ("print a list of all indexed files"), 0,
     &GNUNET_GETOPT_set_one, &list_indexed_files},
    GNUNET_GETOPT_OPTION_VERBOSE (&verbose),
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-fs [OPTIONS]",
                              gettext_noop ("Special file-sharing operations"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-fs.c */
