/*
 *  This file is part of GNUnet
 *  Copyright (C) 2012 Christian Grothoff (and other contributing authors)
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
 *        tests (regex performance, cadet profiler).
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Struct to hold the tree formed by prefix-combining the regexes.
 */
struct RegexCombineCtx {

  /**
   * Next node with same prefix but different token.
   */
  struct RegexCombineCtx *next;

  /**
   * Prev node with same prefix but different token.
   */
  struct RegexCombineCtx *prev;

  /**
   * First child node with same prefix and token.
   */
  struct RegexCombineCtx *head;

  /**
   * Last child node.
   */
  struct RegexCombineCtx *tail;

  /**
   * Token.
   */
  char *s;
};

/*
static void
space (int n)
{
  int i;
  for (i = 0; i < n; i++)
    printf ("  ");
}

static void
debugctx (struct RegexCombineCtx *ctx, int level)
{
  struct RegexCombineCtx *p;
  space (level);
  if (NULL != ctx->s)
    printf ("'%s'\n", ctx->s);
  else
    printf ("NULL\n");
  for (p = ctx->head; NULL != p; p = p->next)
  {
    debugctx (p, level + 1);
  }
}
*/

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
  int opt;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new combine %s\n", ctx->s);
  regex = GNUNET_strdup ("");
  opt = GNUNET_NO;
  for (p = ctx->head; NULL != p; p = p->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "adding '%s' to innner %s\n", p->s, ctx->s);
    s = regex_combine (p);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  total '%s'\n", s);
    if (strlen(s) == 0)
    {
      opt = GNUNET_YES;
    }
    else
    {
      GNUNET_asprintf (&tmp, "%s%s|", regex, s);
      GNUNET_free_non_null (regex);
      regex = tmp;
    }
    GNUNET_free_non_null (s);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  so far '%s' for inner %s\n", regex, ctx->s);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "opt: %d, innner: '%s'\n", opt, regex);
  len = strlen (regex);
  if (0 == len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "empty, returning ''\n");
    GNUNET_free (regex);
    return NULL == ctx->s ? NULL : GNUNET_strdup (ctx->s);
  }

  if ('|' == regex[len - 1])
    regex[len - 1] = '\0';

  if (NULL != ctx->s)
  {
    if (opt)
      GNUNET_asprintf (&s, "%s(%s)?", ctx->s, regex);
    else
      GNUNET_asprintf (&s, "%s(%s)", ctx->s, regex);
    GNUNET_free (regex);
    regex = s;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "partial: %s\n", regex);
  return regex;
}


/**
 * Get the number of matching characters on the prefix of both strings.
 *
 * @param s1 String 1.
 * @param s2 String 2.
 *
 * @return Number of characters of matching prefix.
 */
static unsigned int
get_prefix_length (const char *s1, const char *s2)
{
  unsigned int l1;
  unsigned int l2;
  unsigned int limit;
  unsigned int i;

  l1 = strlen (s1);
  l2 = strlen (s2);
  limit = l1 > l2 ? l2 : l1;

  for (i = 1; i <= limit; i++)
  {
    if (0 != strncmp (s1, s2, i))
      return i - 1;
  }
  return limit;
}


/**
 * Return the child context with the longest prefix match with the regex.
 * Usually only one child will match, search all just in case.
 *
 * @param ctx Context whose children to search.
 * @param regex String to match.
 *
 * @return Child with the longest prefix, NULL if no child matches.
 */
static struct RegexCombineCtx *
get_longest_prefix (struct RegexCombineCtx *ctx, const char *regex)
{
  struct RegexCombineCtx *p;
  struct RegexCombineCtx *best;
  unsigned int l;
  unsigned int best_l;

  best_l = 0;
  best = NULL;
  for (p = ctx->head; NULL != p; p = p->next)
  {
    l = get_prefix_length (p->s, regex);
    if (l > best_l)
    {
      GNUNET_break (0 == best_l);
      best = p;
      best_l = l;
    }
  }
  return best;
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
  struct RegexCombineCtx *newctx;
  unsigned int prefix_l;
  const char *rest_r;
  const char *rest_s;
  size_t len;

  if (0 == strlen (regex))
    return;

  p = get_longest_prefix (ctx, regex);
  if (NULL != p) /* There is some prefix match, reduce regex and try again */
  {
    prefix_l = get_prefix_length (p->s, regex);
    rest_s = &p->s[prefix_l];
    rest_r = &regex[prefix_l];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "chosen '%s' [%u]\n", p->s, prefix_l);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "prefix r '%.*s'\n", prefix_l, p->s);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "rest r '%s'\n", rest_r);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "rest s '%s'\n", rest_s);
    len = strlen (p->s);
    if (prefix_l < len) /* only partial match, split existing state */
    {
      newctx = GNUNET_new (struct RegexCombineCtx);
      newctx->head = p->head;
      newctx->tail = p->tail;
      newctx->s = GNUNET_malloc(len - prefix_l + 1);
      strncpy (newctx->s, rest_s, len - prefix_l + 1);

      p->head = newctx;
      p->tail = newctx;
      p->s[prefix_l] = '\0';
    }
    regex_add (p, rest_r);
    return;
  }
  /* There is no prefix match, add new */
  if (NULL == ctx->head && NULL != ctx->s)
  {
    /* this was the end before, add empty string */
    newctx = GNUNET_new (struct RegexCombineCtx);
    newctx->s = GNUNET_strdup ("");
    GNUNET_CONTAINER_DLL_insert (ctx->head, ctx->tail, newctx);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " no match\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " new state %s\n", regex);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " under %s\n", ctx->s);
  newctx = GNUNET_new (struct RegexCombineCtx);
  newctx->s = GNUNET_strdup (regex);
  GNUNET_CONTAINER_DLL_insert (ctx->head, ctx->tail, newctx);
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
  GNUNET_free_non_null (ctx->s); /* 's' on root node is null */
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
REGEX_TEST_combine (char * const regexes[])
{
  unsigned int i;
  char *combined;
  const char *current;
  struct RegexCombineCtx *ctx;

  ctx = GNUNET_new (struct RegexCombineCtx);
  for (i = 0; regexes[i]; i++)
  {
    current = regexes[i];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Regex %u: %s\n", i, current);
    regex_add (ctx, current);
    /* debugctx (ctx, 0); */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\nCombining...\n");
  /* debugctx (ctx, 0); */

  combined = regex_combine (ctx);

  regex_ctx_destroy (ctx);

  return combined;
}


/**
 * Read a set of regexes from a file, one per line and return them in an array
 * suitable for REGEX_TEST_combine.
 * The array must be free'd using REGEX_TEST_free_from_file.
 *
 * @param filename Name of the file containing the regexes.
 *
 * @return A newly allocated, NULL terminated array of regexes.
 */
char **
REGEX_TEST_read_from_file (const char *filename)
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
    regex[len] = '\0';
    regex = GNUNET_realloc (regex, len + 1);
    GNUNET_array_grow (regexes, nr, nr + 1);
    GNUNET_assert (NULL == regexes[nr - 2]);
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
REGEX_TEST_free_from_file (char **regexes)
{
  unsigned int i;

  for (i = 0; regexes[i]; i++)
    GNUNET_free (regexes[i]);
  GNUNET_free (regexes);
}

/* end of regex_test_lib.c */
