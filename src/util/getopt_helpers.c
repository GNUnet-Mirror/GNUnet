/*
     This file is part of GNUnet
     (C) 2006 Christian Grothoff (and other contributing authors)

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
      trans = gettext (opt[i].description);
      ml = strlen (trans);
      p = 0;
    OUTER:
      while (ml - p > 78 - slen)
        {
          for (j = p + 78 - slen; j > p; j--)
            {
              if (isspace (trans[j]))
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


int
GNUNET_GETOPT_increment_value (struct
                               GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                               void *scls, const char *cmdLineOption,
                               const char *value)
{
  int *val = scls;
  (*val)++;
  return GNUNET_OK;
}

int
GNUNET_GETOPT_set_one (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                       void *scls, const char *option, const char *value)
{
  int *val = scls;
  *val = 1;
  return GNUNET_OK;
}

int
GNUNET_GETOPT_set_string (struct GNUNET_GETOPT_CommandLineProcessorContext
                          *ctx, void *scls, const char *option,
                          const char *value)
{
  char **val = scls;

  GNUNET_assert (value != NULL);
  if (NULL != *val)
    GNUNET_free (*val);
  *val = GNUNET_strdup (value);
  return GNUNET_OK;
}

int
GNUNET_GETOPT_set_ulong (struct GNUNET_GETOPT_CommandLineProcessorContext
                         *ctx, void *scls, const char *option,
                         const char *value)
{
  unsigned long long *val = scls;
  if (1 != SSCANF (value, "%llu", val))
    {
      fprintf (stderr,
               _("You must pass a number to the `%s' option.\n"), "-X");
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


int
GNUNET_GETOPT_set_uint (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                        void *scls, const char *option, const char *value)
{
  unsigned int *val = scls;

  if (1 != SSCANF (value, "%u", val))
    {
      fprintf (stderr,
               _("You must pass a number to the `%s' option.\n"), "-X");
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/* end of getopt_helpers.c */
