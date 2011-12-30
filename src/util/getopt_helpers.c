/*
     This file is part of GNUnet
     (C) 2006, 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/util/getopt_helpers.c
 * @brief implements command line that sets option
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)


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
                              const char *value)
{
  const char *version = scls;

  printf ("%s v%s\n", ctx->binaryName, version);
  return GNUNET_SYSERR;
}



#define BORDER 29

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

  printf ("%s\n%s\n", ctx->binaryOptions, gettext (about));
  printf (_
          ("Arguments mandatory for long options are also mandatory for short options.\n"));
  i = 0;
  opt = ctx->allOptions;
  while (opt[i].description != NULL)
  {
    if (opt[i].shortName == '\0')
      printf ("      ");
    else
      printf ("  -%c, ", opt[i].shortName);
    printf ("--%s", opt[i].name);
    slen = 8 + strlen (opt[i].name);
    if (opt[i].argumentHelp != NULL)
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
      for (j = p + 78 - slen; j > p; j--)
      {
        if (isspace ((unsigned char) trans[j]))
        {
          scp = GNUNET_malloc (j - p + 1);
          memcpy (scp, &trans[p], j - p);
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
      memcpy (scp, &trans[p], 78 - slen);
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
  printf ("Report bugs to gnunet-developers@gnu.org.\n"
          "GNUnet home page: http://www.gnu.org/software/gnunet/\n"
          "General help using GNU software: http://www.gnu.org/gethelp/\n");
  return GNUNET_SYSERR;
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
 * @param scls additional closure (will point to the 'int')
 * @param option name of the option
 * @param value not used (NULL)
 * @return GNUNET_OK
 */
int
GNUNET_GETOPT_increment_value (struct GNUNET_GETOPT_CommandLineProcessorContext
                               *ctx, void *scls, const char *option,
                               const char *value)
{
  int *val = scls;

  (*val)++;
  return GNUNET_OK;
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
 * @return GNUNET_OK
 */
int
GNUNET_GETOPT_set_one (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                       void *scls, const char *option, const char *value)
{
  int *val = scls;

  *val = 1;
  return GNUNET_OK;
}


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
                          void *scls, const char *option, const char *value)
{
  char **val = scls;

  GNUNET_assert (value != NULL);
  GNUNET_free_non_null (*val);
  *val = GNUNET_strdup (value);
  return GNUNET_OK;
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
 * @return GNUNET_OK if parsing the value worked
 */
int
GNUNET_GETOPT_set_ulong (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                         void *scls, const char *option, const char *value)
{
  unsigned long long *val = scls;

  if (1 != SSCANF (value, "%llu", val))
  {
    FPRINTF (stderr, _("You must pass a number to the `%s' option.\n"), option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
 * @return GNUNET_OK if parsing the value worked
 */
int
GNUNET_GETOPT_set_uint (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                        void *scls, const char *option, const char *value)
{
  unsigned int *val = scls;

  if (1 != SSCANF (value, "%u", val))
  {
    FPRINTF (stderr, _("You must pass a number to the `%s' option.\n"), option);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/* end of getopt_helpers.c */
