/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * Backend to check if the respective plugin is
 * loadable. NULL if no check is to be performed.
 * The value is the "basename" of the plugin to load.
 */
static char *backend_check;

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
static int global_ret;

/**
 * Should we generate a configuration file that is clean and
 * only contains the deltas to the defaults?
 */
static int rewrite;


/**
 * Print each option in a given section.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
print_option (void *cls,
              const char *section,
              const char *option,
              const char *value)
{
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  (void) section;
  if (is_filename)
  {
    char *value_fn;
    char *fn;

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                            section,
                                                            option,
                                                            &value_fn));
    fn = GNUNET_STRINGS_filename_expand (value_fn);
    if (NULL == fn)
      fn = value_fn;
    else
      GNUNET_free (value_fn);
    fprintf (stdout, "%s = %s\n", option, fn);
    GNUNET_free (fn);
  }
  else
  {
    fprintf (stdout, "%s = %s\n", option, value);
  }
}


/**
 * Print out given section name.
 *
 * @param cls unused
 * @param section a section in the configuration file
 */
static void
print_section_name (void *cls, const char *section)
{
  (void) cls;
  fprintf (stdout, "%s\n", section);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving,
 *                                                     can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_Handle *out = NULL;
  struct GNUNET_CONFIGURATION_Handle *diff = NULL;
  char *cfg_fn;

  (void) cls;
  (void) args;
  if (NULL != backend_check)
  {
    char *name;

    GNUNET_asprintf (&name, "libgnunet_plugin_%s", backend_check);
    global_ret = (GNUNET_OK == GNUNET_PLUGIN_test (name)) ? 0 : 77;
    GNUNET_free (name);
    return;
  }
  if (rewrite)
  {
    struct GNUNET_CONFIGURATION_Handle *def;

    def = GNUNET_CONFIGURATION_create ();
    if (GNUNET_OK != GNUNET_CONFIGURATION_load (def, NULL))
    {
      fprintf (stderr, _ ("failed to load configuration defaults"));
      global_ret = 1;
      return;
    }
    diff = GNUNET_CONFIGURATION_get_diff (def, cfg);
    cfg = diff;
  }
  if (((! rewrite) && (NULL == section)) || list_sections)
  {
    if (! list_sections)
    {
      fprintf (stderr,
               _ ("%s or %s argument is required\n"),
               "--section",
               "--list-sections");
      global_ret = 1;
    }
    else
    {
      fprintf (stderr, _ ("The following sections are available:\n"));
      GNUNET_CONFIGURATION_iterate_sections (cfg, &print_section_name, NULL);
    }
    goto cleanup;
  }

  if ((NULL != section) && (NULL == value))
  {
    if (NULL == option)
    {
      GNUNET_CONFIGURATION_iterate_section_values (cfg,
                                                   section,
                                                   &print_option,
                                                   (void *) cfg);
    }
    else
    {
      if (is_filename)
      {
        if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                                  section,
                                                                  option,
                                                                  &value))
        {
          GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, section, option);
          global_ret = 3;
          goto cleanup;
        }
      }
      else
      {
        if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                section,
                                                                option,
                                                                &value))
        {
          GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, section, option);
          global_ret = 3;
          goto cleanup;
        }
      }
      fprintf (stdout, "%s\n", value);
    }
  }
  else if (NULL != section)
  {
    if (NULL == option)
    {
      fprintf (stderr, _ ("--option argument required to set value\n"));
      global_ret = 1;
      goto cleanup;
    }
    out = GNUNET_CONFIGURATION_dup (cfg);
    GNUNET_CONFIGURATION_set_value_string (out, section, option, value);
  }
  cfg_fn = NULL;
  if (NULL == cfgfile)
  {
    const char *xdg = getenv ("XDG_CONFIG_HOME");
    if (NULL != xdg)
      GNUNET_asprintf (&cfg_fn,
                       "%s%s%s",
                       xdg,
                       DIR_SEPARATOR_STR,
                       GNUNET_OS_project_data_get ()->config_file);
    else
      cfg_fn = GNUNET_strdup (GNUNET_OS_project_data_get ()->user_config_file);
    cfgfile = cfg_fn;
  }
  if ((NULL != diff) || (NULL != out))
  {
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_write ((NULL == out) ? diff : out, cfgfile))
      global_ret = 2;
  }
  GNUNET_free_non_null (cfg_fn);
  if (NULL != out)
    GNUNET_CONFIGURATION_destroy (out);
cleanup:
  if (NULL != diff)
    GNUNET_CONFIGURATION_destroy (diff);
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
  struct GNUNET_GETOPT_CommandLineOption options[] =
    {GNUNET_GETOPT_option_flag (
       'f',
       "filename",
       gettext_noop ("interpret option value as a filename (with $-expansion)"),
       &is_filename),
     GNUNET_GETOPT_option_exclusive (GNUNET_GETOPT_option_string (
       'b',
       "supported-backend",
       "BACKEND",
       gettext_noop (
         "test if the current installation supports the specified BACKEND"),
       &backend_check)),
     GNUNET_GETOPT_option_string ('s',
                                  "section",
                                  "SECTION",
                                  gettext_noop (
                                    "name of the section to access"),
                                  &section),
     GNUNET_GETOPT_option_string ('o',
                                  "option",
                                  "OPTION",
                                  gettext_noop ("name of the option to access"),
                                  &option),
     GNUNET_GETOPT_option_string ('V',
                                  "value",
                                  "VALUE",
                                  gettext_noop ("value to set"),
                                  &value),
     GNUNET_GETOPT_option_flag ('S',
                                "list-sections",
                                gettext_noop (
                                  "print available configuration sections"),
                                &list_sections),
     GNUNET_GETOPT_option_flag (
       'w',
       "rewrite",
       gettext_noop (
         "write configuration file that only contains delta to defaults"),
       &rewrite),
     GNUNET_GETOPT_OPTION_END};
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret =
    GNUNET_PROGRAM_run (argc,
                        argv,
                        "gnunet-config [OPTIONS]",
                        gettext_noop ("Manipulate GNUnet configuration files"),
                        options,
                        &run,
                        NULL);
  GNUNET_free ((void *) argv);
  if (GNUNET_OK == ret)
    return global_ret;
  return ret;
}

/* end of gnunet-config.c */
