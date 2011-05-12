/*
     This file is part of GNUnet.
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file monkey/gnunet-monkey.c
 * @brief Monkey: gnunet automated debugging tool
 */

#include <stdio.h>
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_monkey_action.h"

static const char* mode;
static const char* dumpFileName;
static const char* binaryName;
static const char* emailAddress;
static const char* edbFilePath;
static const char* gdbBinaryPath;
static int ret = 0;

/**
 * Main function that will launch the action api.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
	int result;
	struct GNUNET_MONKEY_ACTION_Context *cntxt;

	if (strcasecmp(mode, "email") == 0) {
		if (NULL == emailAddress) {
			GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Working in email mode requires an email address!\n");
			ret = 1;
			return;
		}
	} else if (strcasecmp(mode, "text") == 0) {
		if (NULL == dumpFileName) {
			GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Working in text mode requires a path for the dump file!\n");
			ret = 1;
			return;
		}
	}

	/* Initialize context for the Action API */
	cntxt = GNUNET_malloc(sizeof(struct GNUNET_MONKEY_ACTION_Context));
	cntxt->binary_name = binaryName;
	cntxt->expression_database_path = edbFilePath;
	cntxt->gdb_binary_path = gdbBinaryPath;

	result = GNUNET_MONKEY_ACTION_rerun_with_gdb(cntxt);
	switch (result) {
	int retVal;
	case GDB_STATE_ERROR:
		break;
	case GDB_STATE_EXIT_NORMALLY:
		GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Debug with gdb, program exited normally!\n");
		/*FIXME: Valgrind should be launched here */
		break;
	case GDB_STATE_STOPPED:
		/*FIXME: Expression Database should be inspected here (before writing the report) */
		retVal = GNUNET_MONKEY_ACTION_inspect_expression_database(cntxt);
		if (GNUNET_NO == retVal) {
			GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error using Expression Database!\n");
			ret = 1;
			break;
		} else if (GDB_STATE_ERROR == retVal) {
			/* GDB could not locate a NULL value expression, launch Valgrind */
			retVal = GNUNET_MONKEY_ACTION_rerun_with_valgrind(cntxt);
			if (GNUNET_NO == retVal) {
				GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error using Valgrind!\n");
				ret = 1;
				break;
			}
		}
		if(GNUNET_OK != GNUNET_MONKEY_ACTION_format_report(cntxt)){
			GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error in generating debug report!\n");
			ret = 1;
		}
		if (strcasecmp(mode, "email") == 0) {
			if (GNUNET_OK != GNUNET_MONKEY_ACTION_report_email(cntxt)) {
				GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error sending email!\n");
				ret = 1;
			}
		} else {
			/* text mode */
			if (GNUNET_OK != GNUNET_MONKEY_ACTION_report_file(cntxt, dumpFileName)) {
				GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Error in saving debug file!\n");
				ret = 1;
			}
		}
		break;
	default:
		break;
	}
}


int main(int argc, char *argv[])
{
 static const struct GNUNET_GETOPT_CommandLineOption options[] = {
     {'m', "mode", NULL, gettext_noop ("monkey's mode of operation: options are \"text\" or \"email\""),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &mode},
     {'b', "binary", NULL, gettext_noop ("binary for program to debug with monkey"),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &binaryName},
     {'o', "output", NULL, gettext_noop ("path to file to dump monkey's output in case of text mode"),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &dumpFileName},
     {'a', "address", NULL, gettext_noop ("address to send email to in case of email mode"),
          GNUNET_YES, &GNUNET_GETOPT_set_string, &emailAddress},
     {'d', "database", NULL, gettext_noop ("path to Expression Database file"),
                    GNUNET_YES, &GNUNET_GETOPT_set_string, &edbFilePath},
     {'g', "gdb", NULL, gettext_noop ("path to gdb binary in use; default is /usr/bin/gdb"),
                    GNUNET_YES, &GNUNET_GETOPT_set_string, &gdbBinaryPath},
      GNUNET_GETOPT_OPTION_END
   };
 
 if (argc < 2) {
	 printf("%s", "Monkey should take arguments: Use --help to get a list of options.\n");
	 return 1;
 }
 
 if (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                       argv,
                       "gnunet-monkey",
                       gettext_noop
                       ("Automatically debug a service"),
                       options, &run, NULL))
     {
       return ret;
     }

     return 1;
}

