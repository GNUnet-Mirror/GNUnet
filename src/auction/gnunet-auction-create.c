/*
   This file is part of GNUnet.
   Copyright (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 GNUnet e.V.

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
 * @file auction/gnunet-auction-create.c
 * @brief tool to create a new auction
 * @author Markus Teich
 */
#include "platform.h"

#include <float.h>

#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"
/* #include "gnunet_auction_service.h" */

#define FIRST_PRICE 0
#define OUTCOME_PRIVATE 0
#define OUTCOME_PUBLIC 1

static int ret; /** Final status code. */
static char *fndesc; /** filename of the item description */
static char *fnprices; /** filename of the price map */
static struct GNUNET_TIME_Relative dround; /** max round duration */
static struct GNUNET_TIME_Relative dstart; /** time until auction starts */
static unsigned int m = FIRST_PRICE; /** auction parameter m */
static int outcome = OUTCOME_PRIVATE; /** outcome */
static int interactive; /** keep running in foreground */


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
	 char *const *args,
	 const char *cfgfile,
	 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	unsigned int i;
	double cur, prev = DBL_MAX;
	json_t *pmap;
	json_t *parray;
	json_t *pnode;
	json_error_t jerr;

	/* cmdline parsing */
	if (GNUNET_TIME_UNIT_ZERO.rel_value_us == dstart.rel_value_us)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "required argument --regtime missing or invalid (zero)\n");
		goto fail;
	}
	if (GNUNET_TIME_UNIT_ZERO.rel_value_us == dround.rel_value_us)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "required argument --roundtime missing or invalid (zero)\n");
		goto fail;
	}
	if (!fndesc)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "required argument --description missing\n");
		goto fail;
	}
	if (!fnprices)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "required argument --pricemap missing\n");
		goto fail;
	}

	/* parse and check pricemap validity */
	if (!(pmap = json_load_file (fnprices, JSON_DECODE_INT_AS_REAL, &jerr)))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "parsing pricemap json at %d:%d: %s\n",
		            jerr.line, jerr.column, jerr.text);
		goto fail;
	}
	if (-1 == json_unpack_ex (pmap, &jerr, JSON_VALIDATE_ONLY,
	                          "{s:s, s:[]}", "currency", "prices"))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "validating pricemap: %s\n", jerr.text);
		goto fail;
	}
	if (!(parray = json_object_get (pmap, "prices")) || !json_is_array (parray))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		            "could not get `prices` array node from pricemap\n");
		goto fail;
	}
	if (0 == json_array_size (parray))
	{
		GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "empty pricemap array\n");
		goto fail;
	}
	json_array_foreach (parray, i, pnode)
	{
		if (-1 == json_unpack_ex (pnode, &jerr, 0, "F", &cur))
		{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			            "validating pricearray index %d: %s\n", i, jerr.text);
			goto fail;
		}
		if (prev <= cur)
		{
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			            "validating pricearray index %d: "
			            "prices must be strictly monotonically decreasing\n",
			            i);
			goto fail;
		}
		prev = cur;
	}

	return;

fail:
	ret = 1;
	return;
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
	struct GNUNET_GETOPT_CommandLineOption options[] = {

                GNUNET_GETOPT_option_filename ('d',
                                               "description",
                                               "FILE",
                                               gettext_noop ("description of the item to be sold"),
                                               &fndesc),

                GNUNET_GETOPT_option_filename ('p',
                                               "pricemap",
                                               "FILE",
                                               gettext_noop ("mapping of possible prices"),
                                               &fnprices),

                GNUNET_GETOPT_option_relative_time ('r',
                                                        "roundtime",
                                                        "DURATION",
                                                        gettext_noop ("max duration per round"),
                                                        &dround),

                GNUNET_GETOPT_option_relative_time ('s',
                                                        "regtime",
                                                        "DURATION",
                                                        gettext_noop ("duration until auction starts"),
                                                        &dstart),
                GNUNET_GETOPT_option_uint ('m',
                                               "m",
                                               "NUMBER",
                                               gettext_noop ("number of items to sell\n"
                                                             "0 for first price auction\n"
			                                     ">0 for vickrey/M+1st price auction"),
                                               &m), 

                GNUNET_GETOPT_option_flag ('u',
                                              "public",
                                              gettext_noop ("public auction outcome"),
                                              &outcome),

                GNUNET_GETOPT_option_flag ('i',
                                              "interactive",
                                              gettext_noop ("keep running in foreground until auction completes"),
                                              &interactive),

		GNUNET_GETOPT_OPTION_END
	};
	if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
		return 2;

	ret = (GNUNET_OK ==
		   GNUNET_PROGRAM_run (argc, argv,
							   "gnunet-auction-create",
							   gettext_noop ("create a new auction and "
							                 "start listening for bidders"),
							   options,
							   &run,
							   NULL)) ? ret : 1;
	GNUNET_free ((void*) argv);
	return ret;
}
