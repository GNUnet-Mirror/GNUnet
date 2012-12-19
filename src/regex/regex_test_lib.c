/*
 *  This file is part of GNUnet
 *  (C) 2012 Christian Grothoff (and other contributing authors)
 * 
 *  GNUnet is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; either version 3, or (at your
 *  option) any later version.
 * 
 *  GNUnet is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with GNUnet; see the file COPYING.  If not, write to the
 *  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *  Boston, MA 02111-1307, USA.
 */
/**
 * @file src/regex/regex_test_lib.c
 * @brief library to read regexes representing IP networks from a file.
 *        and simplyfinying the into one big regex, in order to run
 *        tests (regex performance, mesh profiler).
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"

struct RegexCombineCtx {
  struct RegexCombineCtx *next;
  struct RegexCombineCtx *prev;

  struct RegexCombineCtx *head;
  struct RegexCombineCtx *tail;

  char *s;
};


/**
 * Extract a string from all prefix-combined regexes.
 *
 * @param ctx Context with 0 or more regexes.
 *
 * @return Regex that matches any of the added regexes.
 */
static char *
regex_combine (struct RegexCombineCtx *ctx)
{
  struct RegexCombineCtx *p;
  size_t len;
  char *regex;
  char *tmp;
  char *s;

  if (NULL != ctx->s)
    GNUNET_asprintf (&regex, "%s(", ctx->s);
  else
    regex = GNUNET_strdup ("(");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "prefix: %s\n", regex);

  for (p = ctx->head; NULL != p; p = p->next)
  {
    s = regex_combine (p);
    GNUNET_asprintf (&tmp, "%s%s|", regex, s);
    GNUNET_free_non_null (s);
    GNUNET_free_non_null (regex);
    regex = tmp;
  }
  len = strlen (regex);
  if (1 == len)
  {
    GNUNET_free (regex);
    return GNUNET_strdup ("");
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pre-partial: %s\n", regex);
  if ('|' == regex[len - 1])
    regex[len - 1] = ')';
  if ('(' == regex[len - 1])
    regex[len - 1] = '\0';

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "partial: %s\n", regex);
  return regex;
}


/**
 * Add a single regex to a context, combining with exisiting regex by-prefix.
 *
 * @param ctx Context with 0 or more regexes.
 * @param regex Regex to add.
 */
static void
regex_add (struct RegexCombineCtx *ctx, const char *regex)
{
  struct RegexCombineCtx *p;
  const char *rest;

  rest = &regex[1];
  for (p = ctx->head; NULL != p; p = p->next)
  {
    if (p->s[0] == regex[0])
    {
      if (1 == strlen(p->s))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "common char %s\n", p->s);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "adding %s\n", rest);
        regex_add (p, rest);
      }
      else
      {
        struct RegexCombineCtx *new;
        new = GNUNET_malloc (sizeof (struct RegexCombineCtx));
        new->s = GNUNET_strdup (&p->s[1]);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " p has now %s\n", p->s);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " p will have %.1s\n", p->s);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " regex is %s\n", regex);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " new has now %s\n", new->s);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " rest is now %s\n", rest);
        p->s[1] = '\0'; /* dont realloc */
        GNUNET_CONTAINER_DLL_insert (p->head, p->tail, new);
        regex_add (p, rest);
      }
      return;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " no  match\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " new state %s\n", regex);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " under %s\n", ctx->s);
  p = GNUNET_malloc (sizeof (struct RegexCombineCtx));
  p->s = GNUNET_strdup (regex);
  GNUNET_CONTAINER_DLL_insert (ctx->head, ctx->tail, p);
}


/**
 * Free all resources used by the context node and all its children.
 *
 * @param ctx Context to free.
 */
static void
regex_ctx_destroy (struct RegexCombineCtx *ctx)
{
  struct RegexCombineCtx *p;
  struct RegexCombineCtx *next;

  for (p = ctx->head; NULL != p; p = next)
  {
    next = p->next;
    regex_ctx_destroy (p);
  }
  GNUNET_free (ctx->s);
  GNUNET_free (ctx);
}


/**
 * Return a prefix-combine regex that matches the same strings as
 * any of the original regexes.
 *
 * WARNING: only useful for reading specific regexes for specific applications,
 *          namely the gnunet-regex-profiler / gnunet-regex-daemon.
 *          This function DOES NOT support arbitrary regex combining.
 */
char *
GNUNET_REGEX_combine (char * const regexes[])
{
  unsigned int i;
  char *combined;
  const char *current;
  struct RegexCombineCtx *ctx;

  ctx = GNUNET_malloc (sizeof (struct RegexCombineCtx));
  for (i = 0; regexes[i]; i++)
  {
    current = regexes[i];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Regex %u: %s\n", i, current);
    regex_add (ctx, current);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\nCombining...\n");

  combined = regex_combine (ctx);

  regex_ctx_destroy (ctx);

  return combined;
}


/**
 * Read a set of regexes from a file, one per line and return them in an array
 * suitable for GNUNET_REGEX_combine.
 * The array must be free'd using GNUNET_REGEX_free_from_file.
 *
 * @param filename Name of the file containing the regexes.
 *
 * @return A newly allocated, NULL terminated array of regexes.
 */
char **
GNUNET_REGEX_read_from_file (const char *filename)
{
  struct GNUNET_DISK_FileHandle *f;
  unsigned int nr;
  unsigned int offset;
  off_t size;
  size_t len;
  char *buffer;
  char *regex;
  char **regexes;

  f = GNUNET_DISK_file_open (filename,
                             GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_NONE);
  if (NULL == f)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Can't open file %s for reading\n", filename);
    return NULL;
  }
  if (GNUNET_OK != GNUNET_DISK_file_handle_size (f, &size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Can't get size of file %s\n", filename);
    GNUNET_DISK_file_close (f);
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "using file %s, size %llu\n",
              filename, (unsigned long long) size);

  buffer = GNUNET_malloc (size + 1);
  GNUNET_DISK_file_read (f, buffer, size);
  GNUNET_DISK_file_close (f);
  regexes = GNUNET_malloc (sizeof (char *));
  nr = 1;
  offset = 0;
  regex = NULL;
  do
  {
    if (NULL == regex)
      regex = GNUNET_malloc (size + 1);
    len = (size_t) sscanf (&buffer[offset], "%s", regex);
    if (0 == len)
      break;
    len = strlen (regex);
    offset += len + 1;
    if (len < 1)
      continue;
    if (len < 6 || strncmp (&regex[len - 6], "(0|1)*", 6) != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%s (line %u) does not end in \"(0|1)*\"\n",
                  buffer, nr);
    }
    else
    {
      len -= 6;
      buffer[len] = '\0';
    }
    regex = GNUNET_realloc (regex, len + 1);
    GNUNET_array_grow (regexes, nr, nr + 1);
    regexes[nr - 2] = regex;
    regexes[nr - 1] = NULL;
    regex = NULL;
  } while (offset < size);
  GNUNET_free_non_null (regex);
  GNUNET_free (buffer);

  return regexes;
}


/**
 * Free all memory reserved for a set of regexes created by read_from_file.
 *
 * @param regexes NULL-terminated array of regexes.
 */
void
GNUNET_REGEX_free_from_file (char **regexes)
{
  unsigned int i;

  for (i = 0; regexes[i]; i++)
    GNUNET_free (regexes[i]);
  GNUNET_free (regexes);
}

/* end of regex_test_lib.c */