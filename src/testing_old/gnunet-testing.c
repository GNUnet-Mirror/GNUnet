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
 * @file testing/gnunet-testing.c
 * @brief tool to use testing functionality from cmd line
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_testing_lib.h"

#define HOSTKEYFILESIZE 914

/**
 * Final status code.
 */
static int ret;

static unsigned int create_hostkey;

static unsigned int create_cfg;

static int create_no;

static char * create_cfg_template;

static char * create_hostkey_file;

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
  char *service_home = NULL;
  char *cur_service_home = NULL;

  struct GNUNET_CONFIGURATION_Handle *cfg_new = NULL;
  struct GNUNET_CONFIGURATION_Handle *cfg_tmpl = GNUNET_CONFIGURATION_create();

  /* load template */
  if ((create_cfg_template != NULL) && (GNUNET_OK != GNUNET_CONFIGURATION_load(cfg_tmpl, create_cfg_template)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not load template `%s'\n", create_cfg_template);
    GNUNET_CONFIGURATION_destroy(cfg_tmpl);

    return 1;
  }
  /* load defaults */
  else if (GNUNET_OK != GNUNET_CONFIGURATION_load(cfg_tmpl,  NULL))
  {
    GNUNET_break (0);
    return 1;
  }

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg_tmpl, "PATHS", "SERVICEHOME", &service_home))
  {
    GNUNET_asprintf(&service_home, "%s", "/tmp/testing");
  }
  else
  {
    int s = strlen (service_home);
    if (service_home[s-1] == DIR_SEPARATOR)
      service_home[s-1] = '\0';
  }

  while (cur < no)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating configuration no. %u \n", cur);
    if (create_cfg_template != NULL)
      GNUNET_asprintf (&cur_file,"%04u-%s",cur, create_cfg_template);
    else
      GNUNET_asprintf (&cur_file,"%04u%s",cur, ".conf");


    GNUNET_asprintf (&cur_service_home, "%s-%04u%c",service_home, cur, DIR_SEPARATOR);
    GNUNET_CONFIGURATION_set_value_string (cfg_tmpl,"PATHS","SERVICEHOME", cur_service_home);
    GNUNET_CONFIGURATION_set_value_string (cfg_tmpl,"PATHS","DEFAULTCONFIG", cur_file);
    GNUNET_free (cur_service_home);

    cfg_new = GNUNET_TESTING_create_cfg(cfg_tmpl, cur, &port, &upnum, NULL, &fdnum);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Writing configuration no. %u to file `%s' \n", cur, cur_file);
    if (GNUNET_OK != GNUNET_CONFIGURATION_write(cfg_new, cur_file))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to write configuration no. %u \n", cur);
      fail = GNUNET_YES;
    }

    GNUNET_CONFIGURATION_destroy (cfg_new);
    GNUNET_free (cur_file);
    if (fail == GNUNET_YES)
      break;
    cur ++;
  }

  GNUNET_CONFIGURATION_destroy(cfg_tmpl);
  GNUNET_free (service_home);
  if (fail == GNUNET_NO)
    return 0;
  else
    return 1;
}

static int
create_hostkeys (const unsigned int no)
{
  struct GNUNET_DISK_FileHandle *fd;
  int cur = 0;
  uint64_t fs;
  uint64_t total_hostkeys;
  char *hostkey_data;
  char *hostkey_src_file;
  char *hostkey_dest_file;

  /* prepare hostkeys */
  if (create_hostkey_file == NULL)
    hostkey_src_file = "../../contrib/testing_hostkeys.dat";
  else
  {
    hostkey_src_file = create_hostkey_file;
  }

  if (GNUNET_YES != GNUNET_DISK_file_test (hostkey_src_file))
  {
    if (create_hostkey_file == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not read hostkeys file, specify hostkey file with -H!\n"));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Specified hostkey file `%s' not found!\n"), create_hostkey_file);
    return 1;
  }
  else
  {
    /* Check hostkey file size, read entire thing into memory */
    fd = GNUNET_DISK_file_open (hostkey_src_file, GNUNET_DISK_OPEN_READ,
                                GNUNET_DISK_PERM_NONE);
    if (NULL == fd)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", hostkey_src_file);
      return 1;
    }

    if (GNUNET_OK != GNUNET_DISK_file_size (hostkey_src_file, &fs, GNUNET_YES, GNUNET_YES))
      fs = 0;

    if (0 != (fs % HOSTKEYFILESIZE))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "File size %llu seems incorrect for hostkeys...\n", fs);
    }
    else
    {
      total_hostkeys = fs / HOSTKEYFILESIZE;
      hostkey_data = GNUNET_malloc_large (fs);
      GNUNET_assert (fs == GNUNET_DISK_file_read (fd, hostkey_data, fs));
      GNUNET_log  (GNUNET_ERROR_TYPE_DEBUG,
                       "Read %llu hostkeys from file\n", total_hostkeys);
    }
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));
  }

  while (cur < no)
  {
    GNUNET_asprintf (&hostkey_dest_file, "%04u-hostkey",cur);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_DISK_directory_create_for_file (hostkey_dest_file));
    fd = GNUNET_DISK_file_open (hostkey_dest_file,
                                GNUNET_DISK_OPEN_READWRITE |
                                GNUNET_DISK_OPEN_CREATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
    GNUNET_assert (fd != NULL);
    GNUNET_assert (HOSTKEYFILESIZE ==
                   GNUNET_DISK_file_write (fd, &hostkey_data[cur * HOSTKEYFILESIZE], HOSTKEYFILESIZE));
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                     "Wrote hostkey to file: `%s' \n", hostkey_dest_file);
    GNUNET_free (hostkey_dest_file);
    cur ++;
  }

  GNUNET_free (hostkey_data);

  return 0;
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
  if (create_cfg == GNUNET_YES)
  {
    if (create_no > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating %u configuration files based on template `%s'\n", create_no, create_cfg_template);
      ret = create_unique_cfgs (create_cfg_template, create_no);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing arguments! \n");
      ret = 1;
    }
  }

  if (create_hostkey == GNUNET_YES)
  {
    if  (create_no > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating %u hostkeys \n", create_no);
      ret = create_hostkeys (create_no);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Missing arguments! \n");
      ret = 1;
    }
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
    {'C', "cfg", NULL, gettext_noop ("create unique configuration files"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &create_cfg},
     {'k', "key", NULL, gettext_noop ("create hostkey files from pre-computed hostkey list"),
     GNUNET_NO, &GNUNET_GETOPT_set_one, &create_hostkey},
     {'H', "hostkeys", NULL, gettext_noop ("host key file"),
     GNUNET_YES, &GNUNET_GETOPT_set_string, &create_hostkey_file},
    {'n', "number", NULL, gettext_noop ("number of unique configuration files or hostkeys to create"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &create_no},
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
