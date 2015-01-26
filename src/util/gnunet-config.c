/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file util/gnunet-config.c
 * @brief tool to access and manipulate GNUnet configuration files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Name of the section
 */
static char *section;

/**
 * Name of the option
 */
static char *option;

/**
 * Value to set
 */
static char *value;

/**
 * Treat option as a filename.
 */
static int is_filename;

/**
 * Whether to show the sections.
 */
static int list_sections;

/**
 * Return value from 'main'.
 */
static int ret;


/**
 * Print each option in a given section.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
print_option (void *cls, const char *section,
	      const char *option,
	      const char *value)
{
  fprintf (stdout,
	   "%s = %s\n", option, value);
}


/**
 * Print out given section name.
 *
 * @param cls unused
 * @param section a section in the configuration file
 */
static void
print_section_name (void *cls,
                    const char *section)
{
  fprintf (stdout, "%s\n", section);
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
  struct GNUNET_CONFIGURATION_Handle *out;

  if (NULL == section || list_sections)
  {
    if (! list_sections)
    {
      fprintf (stderr, _("--section argument is required\n"));
    }
    fprintf (stderr, _("The following sections are available:\n"));
    GNUNET_CONFIGURATION_iterate_sections (cfg, &print_section_name, NULL);
    ret = 1;
    return;
  }

  if (NULL == value)
  {
    if (NULL == option)
    {
      GNUNET_CONFIGURATION_iterate_section_values (cfg, section,
						   &print_option, NULL);
    }
    else
    {
      if (is_filename)
      {
	if (GNUNET_OK !=
	    GNUNET_CONFIGURATION_get_value_filename (cfg, section, option, &value))
	{
	  GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
				     section, option);
	  ret = 3;
	  return;
	}
      }
      else
      {
	if (GNUNET_OK !=
	    GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &value))
	{
	  GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
				     section, option);
	  ret = 3;
	  return;
	}
      }
      fprintf (stdout, "%s\n", value);
    }
  }
  else
  {
    if (NULL == option)
    {
      fprintf (stderr, _("--option argument required to set value\n"));
      ret = 1;
      return;
    }
    out = GNUNET_CONFIGURATION_dup (cfg);
    GNUNET_CONFIGURATION_set_value_string (out, section, option, value);
    if (GNUNET_OK !=
	GNUNET_CONFIGURATION_write (out, cfgfile))
      ret = 2;
    GNUNET_CONFIGURATION_destroy (out);
    return;
  }
}


/**
 * Program to manipulate configuration files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 'f', "filename", NULL,
      gettext_noop ("obtain option of value as a filename (with $-expansion)"),
      0, &GNUNET_GETOPT_set_one, &is_filename },
    { 's', "section", "SECTION",
      gettext_noop ("name of the section to access"),
      1, &GNUNET_GETOPT_set_string, &section },
    { 'o', "option", "OPTION",
      gettext_noop ("name of the option to access"),
      1, &GNUNET_GETOPT_set_string, &option },
    { 'V', "value", "VALUE",
      gettext_noop ("value to set"),
      1, &GNUNET_GETOPT_set_string, &value },
    { 'S', "list-sections", NULL,
      gettext_noop ("print available configuration sections"),
      0, &GNUNET_GETOPT_set_one, &list_sections },
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-config [OPTIONS]",
			     gettext_noop ("Manipulate GNUnet configuration files"),
			     options, &run, NULL)) ? 0 : ret;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-config.c */
