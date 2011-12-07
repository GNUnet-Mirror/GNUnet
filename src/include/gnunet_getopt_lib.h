/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009, 2011 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_getopt_lib.h
 * @brief command line parsing and --help formatting
 *
 * @author Christian Grothoff
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
 * @return GNUNET_OK to continue processing other options, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_GETOPT_CommandLineOptionProcessor) (struct
                                                         GNUNET_GETOPT_CommandLineProcessorContext
                                                         * ctx, void *scls,
                                                         const char *option,
                                                         const char *value);

/**
 * @brief Definition of a command line option.
 */
struct GNUNET_GETOPT_CommandLineOption
{

  /**
   * Short name of the option (use '\\0' for none).
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
   * Is an argument required?  0: GNUNET_NO (includes optional), 1: GNUNET_YES.
   */
  int require_argument;

  /**
   * Handler for the option.
   */
  GNUNET_GETOPT_CommandLineOptionProcessor processor;

  /**
   * Specific closure to pass to the processor.
   */
  void *scls;

};

/**
 * Macro defining the option to print the command line
 * help text (-h option).
 *
 * @param about string with brief description of the application
 */
#define GNUNET_GETOPT_OPTION_HELP(about) \
  { 'h', "help", (const char *) NULL, gettext_noop("print this help"), 0, &GNUNET_GETOPT_format_help_, (void *) about }


/**
 * Macro defining the option to print the version of
 * the application (-v option)
 *
 * @param version string with the version number
 */
#define GNUNET_GETOPT_OPTION_VERSION(version) \
  { 'v', "version", (const char *) NULL, gettext_noop("print the version number"), 0, &GNUNET_GETOPT_print_version_, (void *) version }


/**
 * Allow user to specify log file name (-l option)
 *
 * @param logfn set to the name of the logfile
 */
#define GNUNET_GETOPT_OPTION_LOGFILE(logfn)				\
  { 'l', "logfile", "LOGFILE", gettext_noop("configure logging to write logs to LOGFILE"), 1, &GNUNET_GETOPT_set_string, (void *) logfn }


/**
 * Allow user to specify log level (-L option)
 *
 * @param loglev set to the log level
 */
#define GNUNET_GETOPT_OPTION_LOGLEVEL(loglev)				\
  { 'L', "log", "LOGLEVEL", gettext_noop("configure logging to use LOGLEVEL"), 1, &GNUNET_GETOPT_set_string, (void *) loglev }


/**
 * Get number of verbose (-V) flags
 *
 * @param level where to store the verbosity level (should be an 'int')
 */
#define GNUNET_GETOPT_OPTION_VERBOSE(level)				\
  { 'V', "verbose", (const char *) NULL, gettext_noop("be verbose"), 0, &GNUNET_GETOPT_increment_value, (void *) level }


/**
 * Get configuration file name (-c option)
 *
 * @param fn set to the configuration file name
 */
#define GNUNET_GETOPT_OPTION_CFG_FILE(fn)				\
  { 'c', "config", "FILENAME", gettext_noop("use configuration file FILENAME"), 1, &GNUNET_GETOPT_set_string, (void *) fn }


/**
 * Marker for the end of the list of options.
 */
#define GNUNET_GETOPT_OPTION_END \
  { '\0', NULL, NULL, NULL, 0, NULL, NULL }


/**
 * Parse the command line.
 *
 * @param binaryOptions Name of application with option summary
 * @param allOptions defined options and handlers
 * @param argc number of arguments
 * @param argv actual arguments
 * @return index into argv with first non-option
 *   argument, or GNUNET_SYSERR on error
 */
int
GNUNET_GETOPT_run (const char *binaryOptions,
                   const struct GNUNET_GETOPT_CommandLineOption *allOptions,
                   unsigned int argc, char *const *argv);


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
 * @return GNUNET_OK if parsing the value worked
 */
int
GNUNET_GETOPT_set_ulong (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                         void *scls, const char *option, const char *value);


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
 * @return GNUNET_OK if parsing the value worked
 */
int
GNUNET_GETOPT_set_uint (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                        void *scls, const char *option, const char *value);


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
 * @return GNUNET_OK
 */
int
GNUNET_GETOPT_set_one (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                       void *scls, const char *option, const char *value);


/**
 * Set an option of type 'char *' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'char *'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'char *',
 *             which will be allocated)
 * @param option name of the option
 * @param value actual value of the option (a string)
 * @return GNUNET_OK
 */
int
GNUNET_GETOPT_set_string (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                          void *scls, const char *option, const char *value);

/**
 * Set an option of type 'unsigned int' from the command line. Each
 * time the option flag is given, the value is incremented by one.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'int'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'int')
 * @param option name of the option
 * @param value not used (NULL)
 * @return GNUNET_OK
 */
int
GNUNET_GETOPT_increment_value (struct GNUNET_GETOPT_CommandLineProcessorContext
                               *ctx, void *scls, const char *option,
                               const char *value);


/* *************** internal prototypes - use macros above! ************* */

/**
 * Print out details on command line options (implements --help).
 *
 * @param ctx command line processing context
 * @param scls additional closure (points to about text)
 * @param option name of the option
 * @param value not used (NULL)
 * @return GNUNET_SYSERR (do not continue)
 */
int
GNUNET_GETOPT_format_help_ (struct GNUNET_GETOPT_CommandLineProcessorContext
                            *ctx, void *scls, const char *option,
                            const char *value);

/**
 * Print out program version (implements --version).
 *
 * @param ctx command line processing context
 * @param scls additional closure (points to version string)
 * @param option name of the option
 * @param value not used (NULL)
 * @return GNUNET_SYSERR (do not continue)
 */
int
GNUNET_GETOPT_print_version_ (struct GNUNET_GETOPT_CommandLineProcessorContext
                              *ctx, void *scls, const char *option,
                              const char *value);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_GETOPT_LIB_H */
#endif
/* end of gnunet_getopt_lib.h */
