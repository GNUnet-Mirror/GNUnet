/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Command line parsing and --help formatting
 *
 * @defgroup getopt  Getopt library
 * Command line parsing and --help formatting
 * @{
 */

#ifndef GNUNET_GETOPT_LIB_H
#define GNUNET_GETOPT_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_configuration_lib.h"

/**
 * @brief General context for command line processors.
 */
struct GNUNET_GETOPT_CommandLineProcessorContext
{

  /**
   * Name of the application
   */
  const char *binaryName;

  /**
   * Name of application with option summary
   */
  const char *binaryOptions;

  /**
   * Array with all command line options.
   */
  const struct GNUNET_GETOPT_CommandLineOption *allOptions;

  /**
   * Original command line
   */
  char *const *argv;

  /**
   * Total number of argv's.
   */
  unsigned int argc;

  /**
   * Current argument.
   */
  unsigned int currentArgument;

};


/**
 * @brief Process a command line option
 *
 * @param ctx context for all options
 * @param scls specific closure (for this processor)
 * @param option long name of the option (i.e. "config" for --config)
 * @param value argument, NULL if none was given
 * @return #GNUNET_OK to continue processing other options, #GNUNET_SYSERR to abort
 */
typedef int
(*GNUNET_GETOPT_CommandLineOptionProcessor) (struct
                                             GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                                             void *scls,
                                             const char *option,
                                             const char *value);


/**
 * @brief Definition of a command line option.
 */
struct GNUNET_GETOPT_CommandLineOption
{

  /**
   * Short name of the option.
   */
  const char shortName;

  /**
   * Long name of the option (may not be NULL)
   */
  const char *name;

  /**
   * Name of the argument for the user in help text
   */
  const char *argumentHelp;

  /**
   * Help text for the option (description)
   */
  const char *description;

  /**
   * Is an argument required?  #GNUNET_NO (includes optional) or
   * #GNUNET_YES (required)
   */
  int require_argument;

  /**
   * Handler for the option.
   */
  GNUNET_GETOPT_CommandLineOptionProcessor processor;

  /**
   * Function to call on @e scls to clean up after processing all
   * the arguments. Can be NULL.
   */
  void (*cleaner)(void *cls);

  /**
   * Specific closure to pass to the processor.
   */
  void *scls;

};


/**
 * Defining the option to print the command line
 * help text (-h option).
 *
 * @param about string with brief description of the application
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_HELP (const char *about);


/**
 * Define the option to print the version of
 * the application (-v option)
 *
 * @param version string with the version number
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_VERSION (const char *version);



/**
 * Allow user to specify log file name (-l option)
 *
 * @param[out] logfn set to the name of the logfile
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_LOGFILE (char **logfn);


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
GNUNET_GETOPT_OPTION_STRING (char shortName,
                             const char *name,
                             const char *argumentHelp,
                             const char *description,
                             char **str);

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
GNUNET_GETOPT_OPTION_FILENAME (char shortName,
                               const char *name,
                               const char *argumentHelp,
                               const char *description,
                               char **str);


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
GNUNET_GETOPT_OPTION_SET_BASE32_FIXED_SIZE (char shortName,
                                            const char *name,
                                            const char *argumentHelp,
                                            const char *description,
                                            void *val,
                                            size_t val_size);


/**
 * Allow user to specify a binary value using Crockford
 * Base32 encoding where the size of the binary value is
 * automatically determined from its type.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val binary value decoded from Crockford Base32-encoded argument;
 *             size is determined by type (sizeof (*val)).
 */
#define GNUNET_GETOPT_OPTION_SET_BASE32_AUTO(shortName,name,argumentHelp,description,val) \
  GNUNET_GETOPT_OPTION_SET_BASE32_FIXED_SIZE(shortName,name,argumentHelp,description,val,sizeof(*val))


/**
 * Allow user to specify a flag (which internally means setting
 * an integer to 1/#GNUNET_YES/#GNUNET_OK.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param description long help text for the option
 * @param[out] val set to 1 if the option is present
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_SET_ONE (char shortName,
                              const char *name,
                              const char *description,
                              int *val);


/**
 * Allow user to specify an `unsigned int`.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the value specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_SET_UINT (char shortName,
                               const char *name,
                               const char *argumentHelp,
                               const char *description,
                               unsigned int *val);


/**
 * Allow user to specify an `unsigned long long`.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the value specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_SET_ULONG (char shortName,
                                const char *name,
                                const char *argumentHelp,
                                const char *description,
                                unsigned long long *val);


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
GNUNET_GETOPT_OPTION_SET_RELATIVE_TIME (char shortName,
                                        const char *name,
                                        const char *argumentHelp,
                                        const char *description,
                                        struct GNUNET_TIME_Relative *val);


/**
 * Increment @a val each time the option flag is given by one.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to 1 if the option is present
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_INCREMENT_VALUE (char shortName,
                                      const char *name,
                                      const char *description,
                                      unsigned int *val);


/**
 * Define the '-L' log level option.  Note that we do not check
 * that the log level is valid here.
 *
 * @param[out] level set to the log level
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_LOGLEVEL (char **level);


/**
 * Define the '-V' verbosity option.  Using the option more
 * than once increments @a level each time.
 *
 * @param[out] level set to the verbosity level
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_VERBOSE (unsigned int *level);


/**
 * Allow user to specify log file name (-l option)
 *
 * @param[out] logfn set to the name of the logfile
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_LOGFILE (char **logfn);


/**
 * Allow user to specify configuration file name (-c option)
 *
 * @param[out] fn set to the name of the configuration file
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_GETOPT_OPTION_CFG_FILE (char **fn);


/**
 * Marker for the end of the list of options.
 */
#define GNUNET_GETOPT_OPTION_END \
  { '\0', NULL, NULL, NULL, 0, NULL, NULL, NULL }


/**
 * Parse the command line.
 *
 * @param binaryOptions Name of application with option summary
 * @param allOptions defined options and handlers
 * @param argc number of arguments in @a argv
 * @param argv actual arguments
 * @return index into argv with first non-option
 *   argument, or #GNUNET_SYSERR on error
 */
int
GNUNET_GETOPT_run (const char *binaryOptions,
                   const struct GNUNET_GETOPT_CommandLineOption *allOptions,
                   unsigned int argc,
                   char *const *argv);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_GETOPT_LIB_H */
#endif

/** @} */ /* end of group getopt */

/* end of gnunet_getopt_lib.h */
