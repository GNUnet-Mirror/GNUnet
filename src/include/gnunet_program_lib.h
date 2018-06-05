/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @author Christian Grothoff
 *
 * @file
 * Functions related to starting programs
 *
 * @defgroup program  Program library
 * Start command-line programs.
 * @{
 */

#ifndef GNUNET_PROGRAM_LIB_H
#define GNUNET_PROGRAM_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_configuration_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_scheduler_lib.h"

/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
typedef void
(*GNUNET_PROGRAM_Main) (void *cls,
                        char *const *args,
                        const char *cfgfile,
                        const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Run a standard GNUnet command startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments in @a argv
 * @param argv command line arguments
 * @param binaryName our expected name
 * @param binaryHelp help text for the program
 * @param options command line options
 * @param task main function to run
 * @param task_cls closure for @a task
 * @param run_without_scheduler #GNUNET_NO start the scheduler,
 *        #GNUNET_YES do not start the scheduler just run the main task
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_PROGRAM_run2 (int argc,
                     char *const *argv,
                     const char *binaryName,
                     const char *binaryHelp,
                     const struct GNUNET_GETOPT_CommandLineOption *options,
                     GNUNET_PROGRAM_Main task,
                     void *task_cls,
                     int run_without_scheduler);


/**
 * Run a standard GNUnet command startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @param binaryName our expected name
 * @param binaryHelp helptext for "-h" option (about the app)
 * @param options command line options
 * @param task main function to run
 * @param task_cls closure for @a task
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_PROGRAM_run (int argc,
                    char *const *argv,
                    const char *binaryName,
                    const char *binaryHelp,
                    const struct GNUNET_GETOPT_CommandLineOption *options,
                    GNUNET_PROGRAM_Main task,
		    void *task_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_PROGRAM_LIB_H */
#endif

/** @} */  /* end of group program */

/* end of gnunet_program_lib.h */
