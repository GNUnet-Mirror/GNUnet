/*
     This file is part of GNUnet
     Copyright (C) 2006, 2011 GNUnet e.V.

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
*/

/**
 * @file src/util/getopt_helpers.c
 * @brief implements command line that sets option
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-getopt", __VA_ARGS__)


/**
 * Print out program version (implements --version).
 *
 * @param ctx command line processing context
 * @param scls additional closure (points to version string)
 * @param option name of the option
 * @param value not used (NULL)
 * @return #GNUNET_NO (do not continue, not an error)
 */
static int
print_version (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
               void *scls,
               const char *option,
               const char *value)
{
  const char *version = scls;

  (void) option;
  (void) value;
  printf ("%s v%s\n",
	  ctx->binaryName,
	  version);
  return GNUNET_NO;
}


/**
 * Define the option to print the version of
 * the application (-v option)
 *
 * @param version string with the version number
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_version (const char *version)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  'v',
    .name = "version",
    .description = gettext_noop("print the version number"),
    .processor = &print_version,
    .scls = (void *) version
  };
  return clo;
}


/**
 * At what offset does the help text start?
 */
#define BORDER 29

/**
 * Print out details on command line options (implements --help).
 *
 * @param ctx command line processing context
 * @param scls additional closure (points to about text)
 * @param option name of the option
 * @param value not used (NULL)
 * @return #GNUNET_NO (do not continue, not an error)
 */
static int
format_help (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
             void *scls,
             const char *option,
             const char *value)
{
  const char *about = scls;
  size_t slen;
  unsigned int i;
  int j;
  size_t ml;
  size_t p;
  char *scp;
  const char *trans;
  const struct GNUNET_GETOPT_CommandLineOption *opt;
  const struct GNUNET_OS_ProjectData *pd;

  (void) option;
  (void) value;
  if (NULL != about)
  {
    printf ("%s\n%s\n", ctx->binaryOptions, gettext (about));
    printf (_
	    ("Arguments mandatory for long options are also mandatory for short options.\n"));
  }
  i = 0;
  opt = ctx->allOptions;
  while (NULL != opt[i].description)
  {
    if (opt[i].shortName == '\0')
      printf ("      ");
    else
      printf ("  -%c, ", opt[i].shortName);
    printf ("--%s", opt[i].name);
    slen = 8 + strlen (opt[i].name);
    if (NULL != opt[i].argumentHelp)
    {
      printf ("=%s", opt[i].argumentHelp);
      slen += 1 + strlen (opt[i].argumentHelp);
    }
    if (slen > BORDER)
    {
      printf ("\n%*s", BORDER, "");
      slen = BORDER;
    }
    if (slen < BORDER)
    {
      printf ("%*s", (int) (BORDER - slen), "");
      slen = BORDER;
    }
    if (0 < strlen (opt[i].description))
      trans = gettext (opt[i].description);
    else
      trans = "";
    ml = strlen (trans);
    p = 0;
OUTER:
    while (ml - p > 78 - slen)
    {
      for (j = p + 78 - slen; j > (int) p; j--)
      {
        if (isspace ((unsigned char) trans[j]))
        {
          scp = GNUNET_malloc (j - p + 1);
          GNUNET_memcpy (scp, &trans[p], j - p);
          scp[j - p] = '\0';
          printf ("%s\n%*s", scp, BORDER + 2, "");
          GNUNET_free (scp);
          p = j + 1;
          slen = BORDER + 2;
          goto OUTER;
        }
      }
      /* could not find space to break line */
      scp = GNUNET_malloc (78 - slen + 1);
      GNUNET_memcpy (scp, &trans[p], 78 - slen);
      scp[78 - slen] = '\0';
      printf ("%s\n%*s", scp, BORDER + 2, "");
      GNUNET_free (scp);
      slen = BORDER + 2;
      p = p + 78 - slen;
    }
    /* print rest */
    if (p < ml)
      printf ("%s\n", &trans[p]);
    if (strlen (trans) == 0)
      printf ("\n");
    i++;
  }
  pd = GNUNET_OS_project_data_get ();
  printf ("Report bugs to %s.\n"
          "GNUnet home page: %s\n"
          "General help using GNU software: http://www.gnu.org/gethelp/\n",
          pd->bug_email,
          pd->homepage);
  return GNUNET_NO;
}


/**
 * Defining the option to print the command line
 * help text (-h option).
 *
 * @param about string with brief description of the application
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_help (const char *about)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName = 'h',
    .name = "help",
    .description = gettext_noop("print this help"),
    .processor = format_help,
    .scls = (void *) about
  };

  return clo;
}


/**
 * Set an option of type 'unsigned int' from the command line. Each
 * time the option flag is given, the value is incremented by one.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'int'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'unsigned int')
 * @param option name of the option
 * @param value not used (NULL)
 * @return #GNUNET_OK
 */
static int
increment_value (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                 void *scls,
                 const char *option,
                 const char *value)
{
  unsigned int *val = scls;

  (void) ctx;
  (void) option;
  (void) value;
  (*val)++;
  return GNUNET_OK;
}


/**
 * Increment @a val each time the option flag is given by one.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val increment by 1 each time the option is present
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_increment_uint (char shortName,
				     const char *name,
				     const char *description,
				     unsigned int *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .description = description,
    .processor = &increment_value,
    .scls = (void *) val
  };

  return clo;
}


/**
 * Define the '-V' verbosity option.  Using the option more
 * than once increments @a level each time.
 *
 * @param[out] level set to the verbosity level
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_verbose (unsigned int *level)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName = 'V',
    .name = "verbose",
    .description = gettext_noop("be verbose"),
    .processor = &increment_value,
    .scls = (void *) level
  };

  return clo;
}


/**
 * Set an option of type 'int' from the command line to 1 if the
 * given option is present.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'int'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'int')
 * @param option name of the option
 * @param value not used (NULL)
 * @return #GNUNET_OK
 */
static int
set_one (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
         void *scls,
         const char *option,
         const char *value)
{
  int *val = scls;

  (void) ctx;
  (void) option;
  (void) value;
  *val = 1;
  return GNUNET_OK;
}


/**
 * Allow user to specify a flag (which internally means setting
 * an integer to 1/#GNUNET_YES/#GNUNET_OK.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to 1 if the option is present
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_flag (char shortName,
			   const char *name,
			   const char *description,
			   int *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .description = description,
    .processor = &set_one,
    .scls = (void *) val
  };

  return clo;
}


/**
 * Set an option of type 'char *' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'char *', which will be allocated with the requested string.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'char *',
 *             which will be allocated)
 * @param option name of the option
 * @param value actual value of the option (a string)
 * @return #GNUNET_OK
 */
static int
set_string (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
            void *scls,
            const char *option,
            const char *value)
{
  char **val = scls;

  (void) ctx;
  (void) option;
  GNUNET_assert (NULL != value);
  GNUNET_free_non_null (*val);
  *val = GNUNET_strdup (value);
  return GNUNET_OK;
}


/**
 * Allow user to specify a string.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] str set to the string
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_string (char shortName,
                             const char *name,
                             const char *argumentHelp,
                             const char *description,
                             char **str)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_string,
    .scls = (void *) str
  };

  return clo;
}


/**
 * Define the '-L' log level option.  Note that we do not check
 * that the log level is valid here.
 *
 * @param[out] level set to the log level
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_loglevel (char **level)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName = 'L',
    .name = "log",
    .argumentHelp = "LOGLEVEL",
    .description = gettext_noop("configure logging to use LOGLEVEL"),
    .require_argument = 1,
    .processor = &set_string,
    .scls = (void *) level
  };

  return clo;
}


/**
 * Set an option of type 'char *' from the command line with
 * filename expansion a la #GNUNET_STRINGS_filename_expand().
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the `char *`,
 *             which will be allocated)
 * @param option name of the option
 * @param value actual value of the option (a string)
 * @return #GNUNET_OK
 */
static int
set_filename (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
              void *scls,
              const char *option,
              const char *value)
{
  char **val = scls;

  (void) ctx;
  (void) option;
  GNUNET_assert (NULL != value);
  GNUNET_free_non_null (*val);
  *val = GNUNET_STRINGS_filename_expand (value);
  return GNUNET_OK;
}


/**
 * Allow user to specify a filename (automatically path expanded).
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] str set to the string
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_filename (char shortName,
			       const char *name,
			       const char *argumentHelp,
			       const char *description,
			       char **str)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_filename,
    .scls = (void *) str
  };

  return clo;
}


/**
 * Allow user to specify log file name (-l option)
 *
 * @param[out] logfn set to the name of the logfile
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_logfile (char **logfn)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  'l',
    .name = "logfile",
    .argumentHelp = "FILENAME",
    .description = gettext_noop ("configure logging to write logs to FILENAME"),
    .require_argument = 1,
    .processor = &set_filename,
    .scls = (void *) logfn
  };

  return clo;
}


/**
 * Allow user to specify configuration file name (-c option)
 *
 * @param[out] fn set to the name of the configuration file
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_cfgfile (char **fn)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  'c',
    .name = "config",
    .argumentHelp = "FILENAME",
    .description = gettext_noop("use configuration file FILENAME"),
    .require_argument = 1,
    .processor = &set_filename,
    .scls = (void *) fn
  };

  return clo;
}


/**
 * Set an option of type 'unsigned long long' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'unsigned long long'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'unsigned long long')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_ulong (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
           void *scls,
           const char *option,
           const char *value)
{
  unsigned long long *val = scls;

  (void) ctx;
  if (1 != SSCANF (value,
                   "%llu",
                   val))
  {
    FPRINTF (stderr,
             _("You must pass a number to the `%s' option.\n"),
             option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Allow user to specify an `unsigned long long`
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the value specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_ulong (char shortName,
			    const char *name,
			    const char *argumentHelp,
			    const char *description,
			    unsigned long long *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_ulong,
    .scls = (void *) val
  };

  return clo;
}


/**
 * Set an option of type 'struct GNUNET_TIME_Relative' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'struct GNUNET_TIME_Relative'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'struct GNUNET_TIME_Relative')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_relative_time (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                   void *scls,
                   const char *option,
                   const char *value)
{
  struct GNUNET_TIME_Relative *val = scls;
  
  (void) ctx;  
  if (GNUNET_OK !=
      GNUNET_STRINGS_fancy_time_to_relative (value,
					     val))
  {
    FPRINTF (stderr,
             _("You must pass relative time to the `%s' option.\n"),
             option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Allow user to specify a `struct GNUNET_TIME_Relative`
 * (using human-readable "fancy" time).
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the time specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_relative_time (char shortName,
				    const char *name,
				    const char *argumentHelp,
				    const char *description,
				    struct GNUNET_TIME_Relative *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_relative_time,
    .scls = (void *) val
  };

  return clo;
}


/**
 * Set an option of type 'struct GNUNET_TIME_Absolute' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'struct GNUNET_TIME_Absolute'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the `struct GNUNET_TIME_Absolute`)
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_absolute_time (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                   void *scls,
                   const char *option,
                   const char *value)
{
  struct GNUNET_TIME_Absolute *val = scls;

  (void) ctx;
  if (GNUNET_OK !=
      GNUNET_STRINGS_fancy_time_to_absolute (value,
					     val))
  {
    FPRINTF (stderr,
             _("You must pass absolute time to the `%s' option.\n"),
             option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Allow user to specify a `struct GNUNET_TIME_Absolute`
 * (using human-readable "fancy" time).
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the time specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_absolute_time (char shortName,
				    const char *name,
				    const char *argumentHelp,
				    const char *description,
				    struct GNUNET_TIME_Absolute *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_absolute_time,
    .scls = (void *) val
  };

  return clo;
}


/**
 * Set an option of type 'unsigned int' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'unsigned int'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'unsigned int')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_uint (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
          void *scls,
          const char *option,
          const char *value)
{
  unsigned int *val = scls;

  (void) ctx;
  if('-' == *value)
  {
	FPRINTF (stderr,
		_("Your input for the '%s' option has to be a non negative number \n"),
		option);
    	return GNUNET_SYSERR;
  }
  if (1 != SSCANF (value,
                   "%u",
                   val))
  {
    FPRINTF (stderr,
             _("You must pass a number to the `%s' option.\n"),
             option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Allow user to specify an unsigned integer.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the value specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_uint (char shortName,
			   const char *name,
			   const char *argumentHelp,
			   const char *description,
			   unsigned int *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_uint,
    .scls = (void *) val
  };

  return clo;
}



/**
 * Set an option of type 'uint16_t' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'uint16_t'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'unsigned int')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_uint16 (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
	    void *scls,
	    const char *option,
	    const char *value)
{
  uint16_t *val = scls;
  unsigned int v;
  
  (void) ctx;
  if (1 != SSCANF (value,
                   "%u",
                   &v))
  {
    FPRINTF (stderr,
             _("You must pass a number to the `%s' option.\n"),
             option);
    return GNUNET_SYSERR;
  }
  if (v > UINT16_MAX)
  {
    FPRINTF (stderr,
             _("You must pass a number below %u to the `%s' option.\n"),
	     (unsigned int) UINT16_MAX,
             option);
    return GNUNET_SYSERR;
  }
  *val = (uint16_t) v;
  return GNUNET_OK;
}


/**
 * Allow user to specify an uint16_t.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the value specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_uint16 (char shortName,
			     const char *name,
			     const char *argumentHelp,
			     const char *description,
			     uint16_t *val)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_uint16,
    .scls = (void *) val
  };

  return clo;
}


/**
 * Closure for #set_base32().
 */
struct Base32Context
{
  /**
   * Value to initialize (already allocated)
   */
  void *val;

  /**
   * Number of bytes expected for @e val.
   */
  size_t val_size;
};


/**
 * Set an option of type 'unsigned int' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'unsigned int'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'unsigned int')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_base32 (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
            void *scls,
            const char *option,
            const char *value)
{
  struct Base32Context *bc = scls;

  (void) ctx;
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (value,
                                     strlen (value),
                                     bc->val,
                                     bc->val_size))
  {
    fprintf (stderr,
             _("Argument `%s' malformed. Expected base32 (Crockford) encoded value.\n"),
             option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Helper function to clean up after
 * #GNUNET_GETOPT_option_base32_fixed_size.
 *
 * @param cls value to GNUNET_free()
 */
static void
free_bc (void *cls)
{
  GNUNET_free (cls);
}


/**
 * Allow user to specify a binary value using Crockford
 * Base32 encoding.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val binary value decoded from Crockford Base32-encoded argument
 * @param val_size size of @a val in bytes
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_base32_fixed_size (char shortName,
                                            const char *name,
                                            const char *argumentHelp,
                                            const char *description,
                                            void *val,
                                            size_t val_size)
{
  struct Base32Context *bc = GNUNET_new (struct Base32Context);
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_base32,
    .cleaner = &free_bc,
    .scls = (void *) bc
  };

  bc->val = val;
  bc->val_size = val_size;
  return clo;
}


/**
 * Make the given option mandatory.
 *
 * @param opt option to modify
 * @return @a opt with the mandatory flag set.
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_option_mandatory (struct GNUNET_GETOPT_CommandLineOption opt)
{
  opt.option_mandatory = 1;
  return opt;
}


/* end of getopt_helpers.c */
