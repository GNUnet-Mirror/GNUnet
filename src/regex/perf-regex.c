/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file regex/prof-regex.c
 * @brief Test how long it takes to create a automaton from a string regex.
 * @author Bartlomiej Polot
 */
#include <regex.h>
#include <time.h>
#include "platform.h"
#include "gnunet_regex_lib.h"

static const char *exe;

static void
usage(void)
{
  fprintf (stderr, "Usage: %s REGEX_FILE COMPRESSION\n", exe);
}

/**
 * The main function to obtain peer information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_REGEX_Automaton* dfa;
  char **regexes;
  char *buffer;
  char *regex;
  unsigned int nr;
  unsigned int i;
  int compression;
  long size;
  size_t len;
  FILE *f;

  GNUNET_log_setup ("perf-regex", "DEBUG", NULL);
  exe = argv[0];
  if (3 != argc)
  {
    usage();
    return 1;
  }
  f = fopen (argv[1], "r");
  if (NULL == f)
  {
    fprintf (stderr, "Can't open file %s\n", argv[1]);
    usage();
    return 2;
  }
  fseek (f, 0, SEEK_END);
  size = ftell (f);
  fprintf (stderr, "using file %s, size %ld\n", argv[1], size);
  fseek (f, 0, SEEK_SET);
  buffer = GNUNET_malloc (size + 1);
  regexes = GNUNET_malloc (sizeof (char *));
  nr = 1;
  do
  {
    if (NULL == fgets (buffer, size + 1, f))
    {
      fprintf (stderr, "Can't read file %s\n", argv[1]);
      usage();
      return 3;
    }
    len = strlen (buffer);
    if (len < 1)
      continue;
    if ('\n' == buffer[len - 1])
    {
      len--;
      buffer[len] = '\0';
    }
    if (len < 6 || strncmp (&buffer[len - 6], "(0|1)*", 6) != 0)
    {
      fprintf (stderr, "\nWARNING:\n");
      fprintf (stderr, "%s (line %u) does not end in (0|1)*\n", buffer, nr);
    }
    else
    {
      buffer[len - 6] = '\0';
    }
    GNUNET_array_grow (regexes, nr, nr+1);
    regexes[nr - 2] = GNUNET_strdup (buffer);
    regexes[nr - 1] = NULL;
  } while (ftell(f) < size);
  GNUNET_free (buffer);

  buffer = GNUNET_REGEX_combine (regexes);

  GNUNET_asprintf (&regex, "GNVPN-0001-PAD(%s)(0|1)*", buffer);
  size = strlen (regex);
  
  // fprintf (stderr, "Combined regex:\n%s\n", regex);
  //   return 0;

  compression = atoi (argv[2]);
  dfa = GNUNET_REGEX_construct_dfa (regex, size, compression);
  GNUNET_REGEX_automaton_destroy (dfa);
  GNUNET_free (buffer);
  for (i=0;i<nr;i++)
    GNUNET_free_non_null (regexes[i]);
  GNUNET_array_grow (regexes, nr, 0);
  return 0;
}

/* end of prof-regex.c */
