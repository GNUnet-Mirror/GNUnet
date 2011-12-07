/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file template/gnunet-testing.c
 * @brief tool to use testing functionality from cmd line
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_testing_lib.h"

/**
 * Final status code.
 */
static int ret;

unsigned int create_cfg;

 int create_cfg_no;

static char * create_cfg_template;


static int
create_unique_cfgs (const char * template, const unsigned int no)
{
  int fail = GNUNET_NO;

  uint16_t port = 20000;
  uint32_t upnum = 1;
  uint32_t fdnum = 1;

  if (GNUNET_NO == GNUNET_DISK_file_test(template))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Configuration template `%s': file not found\n", create_cfg_template);
    return 1;
  }

  int cur = 0;
  char * cur_file;
  struct GNUNET_CONFIGURATION_Handle *cfg_tmpl = GNUNET_CONFIGURATION_create();
  struct GNUNET_CONFIGURATION_Handle *cfg_new = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_load(cfg_tmpl, create_cfg_template))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load template `%s'\n", create_cfg_template);
    GNUNET_CONFIGURATION_destroy(cfg_tmpl);

    return 1;
  }

  while (cur < no)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Creating configuration no. %u \n", cur);
    GNUNET_asprintf(&cur_file,"%04u-%s",cur, create_cfg_template);
    cfg_new = GNUNET_TESTING_create_cfg(cfg_tmpl, cur, &port, &upnum, NULL, &fdnum);

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Writing configuration no. %u to file `%s' \n", cur, cur_file);
    if (GNUNET_OK != GNUNET_CONFIGURATION_write(cfg_new, cur_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to write configuration no. %u \n", cur);
      fail = GNUNET_YES;
    }


    GNUNET_free (cur_file);
    if (fail == GNUNET_YES)
      break;
    cur ++;
  }

  GNUNET_CONFIGURATION_destroy(cfg_tmpl);
  if (fail == GNUNET_NO)
    return 0;
  else
    return 1;
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
  /* main code here */
  if ((create_cfg == GNUNET_YES) &&
      (create_cfg_no > 0) &&
      (create_cfg_template != NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating %u configuration files based on template `%s'\n", create_cfg_no, create_cfg_template);
    ret = create_unique_cfgs (create_cfg_template, create_cfg_no);
  }
  else
  {
    ret = 1;
  }
  GNUNET_free_non_null (create_cfg_template);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'C', "create", NULL, gettext_noop ("create unique configuration files"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &create_cfg},
    {'n', "number", NULL, gettext_noop ("number of unique configuration files to create"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &create_cfg_no},
    {'t', "template", NULL, gettext_noop ("configuration template"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &create_cfg_template},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-testing",
                              gettext_noop ("Command line tool to access the testing library"), options, &run,
                              NULL)) ? ret : 1;
}

/* end of gnunet-testing.c */
