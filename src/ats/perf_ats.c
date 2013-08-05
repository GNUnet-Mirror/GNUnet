/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats.c
 * @brief ats benchmark: start peers and modify preferences, monitor change over time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define TESTNAME_PREFIX "perf_ats_"

static int ret;
static char *solver;
static char *preference;

static void
check (void *cls, char *const *args, const char *cfgfile,
       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Benchmarking solver `%s' on preference `%s'\n"), solver, preference);
	ret = 0;
}


int
main (int argc, char *argv[])
{
	char *tmp;
	char *tmp_sep;
	char *conf_name;

  ret = 1;

  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  /* figure out testname */
  tmp = strstr (argv[0], TESTNAME_PREFIX);
  if (NULL == tmp)
  {
  	fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
  	return GNUNET_SYSERR;
  }
  tmp += strlen(TESTNAME_PREFIX);
  solver = GNUNET_strdup (tmp);
  tmp_sep = strchr (solver, '_');
  if (NULL == tmp_sep)
  {
  	fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
  	GNUNET_free (solver);
  	return GNUNET_SYSERR;
  }
  tmp_sep[0] = '\0';
  preference = GNUNET_strdup(tmp_sep + 1);

  GNUNET_asprintf(&conf_name, "%s%s_%s.conf", TESTNAME_PREFIX, solver, preference);

  char *argv2[] = { "perf_ats",
    "-c",
    conf_name,
    "-L", "WARNING",
    NULL
  };
  GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                      "perf_ats", "nohelp", options,
                      &check, NULL);

  GNUNET_free (solver);
  GNUNET_free (preference);
  GNUNET_free (conf_name);

  return ret;
}

/* end of file perf_ats.c */
