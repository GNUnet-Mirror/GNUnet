/*
 *  This file is part of GNUnet
 *  Copyright (C) 2012-2017 GNUnet e.V.
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
 *  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA 02110-1301, USA.
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
struct RegexCombineCtx
{
  /**
   * Child nodes with same prefix and token.
   */
  struct RegexCombineCtx **children;

  /**
   * Alphabet size (how many @a children there are)
   */
  unsigned int size;

  /**
   * Token.
   */
  char *s;
};


/**
 * Char 2 int
 *
 * Convert a character into its int value depending on the base used
 *
 * @param c Char
 * @param size base (2, 8 or 16(hex))
 *
 * @return Int in range [0, (base-1)]
 */
static int
c2i (char c, int size)
{
  switch (size)
  {
    case 2:
    case 8:
      return c - '0';
      break;
    case 16:
      if (c >= '0' && c <= '9')
        return c - '0';
      else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Cannot convert char %c in base %u\n",
                    c, size);
        GNUNET_assert (0);
      }
      break;
    default:
      GNUNET_assert (0);
  }
}


/**
 * Printf spaces to indent the regex tree
 *
 * @param n Indentation level
 */
static void
space (int n)
{
  int i;
  for (i = 0; i < n; i++)
    fprintf (stderr, "| ");
}


/**
 * Printf the combined regex ctx.
 *
 * @param ctx The ctx to printf
 * @param level Indentation level to start with
 */
static void
debugctx (struct RegexCombineCtx *ctx, int level)
{
  return;
  unsigned int i;
  if (NULL != ctx->s)
  {
    space (level - 1);
    fprintf (stderr, "%u:'%s'\n", c2i(ctx->s[0], ctx->size), ctx->s);
  }
  else
    fprintf (stderr, "ROOT (base %u)\n", ctx->size);
  for (i = 0; i < ctx->size; i++)
  {
    if (NULL != ctx->children[i])
    {
      space (level);
      debugctx (ctx->children[i], level + 1);
    }
  }
  fflush(stderr);
}


/**
 * Add a single regex to a context, combining with exisiting regex by-prefix.
 *
 * @param ctx Context with 0 or more regexes.
 * @param regex Regex to add.
 */
static void
regex_add (struct RegexCombineCtx *ctx, const char *regex);


/**
 * Create and initialize a new RegexCombineCtx.
 *
 * @param alphabet_size Size of the alphabet (and the Trie array)
 */
static struct RegexCombineCtx *
new_regex_ctx (unsigned int alphabet_size)
{
  struct RegexCombineCtx *ctx;
  size_t array_size;

  array_size = sizeof(struct RegexCombineCtx *) * alphabet_size;
  ctx = GNUNET_new (struct RegexCombineCtx);
  ctx->children = GNUNET_malloc (array_size);
  ctx->size = alphabet_size;

  return ctx;
}

static void
move_children (struct RegexCombineCtx *dst, const struct RegexCombineCtx *src)
{
  size_t array_size;

  array_size = sizeof(struct RegexCombineCtx *) * src->size;
  memcpy (dst->children, src->children, array_size);
  for (int i = 0; i < src->size; i++)
  {
    src->children[i] = NULL;
  }
}


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
  unsigned int i;
  size_t len;
  char *regex;
  char *tmp;
  char *s;
  int opt;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new combine %s\n", ctx->s);
  regex = GNUNET_strdup ("");
  opt = GNUNET_NO;
  for (i = 0; i < ctx->size; i++)
  {
    p = ctx->children[i];
    if (NULL == p)
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "adding '%s' to innner %s\n",
                p->s, ctx->s);
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

  for (i = 0; i < limit; i++)
  {
    if (s1[i] != s2[i])
      return i;
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
  unsigned int i;
  unsigned int l;
  unsigned int best_l;

  best_l = 0;
  best = NULL;

  for (i = 0; i < ctx->size; i++)
  {
    p = ctx->children[i];
    if (NULL == p)
      continue;

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

static void
regex_add_multiple (struct RegexCombineCtx *ctx,
                    const char *regex,
                    struct RegexCombineCtx **children)
{
  char tmp[2];
  long unsigned int i;
  size_t l;
  struct RegexCombineCtx *newctx;
  unsigned int count;

  if ('(' != regex[0])
  {
    GNUNET_assert (0);
  }

  /* Does the regex cover *all* possible children? Then don't add any,
   * as it will be covered by the post-regex "(a-z)*"
   */
  l = strlen (regex);
  count = 0;
  for (i = 1UL; i < l; i++)
  {
    if (regex[i] != '|' && regex[i] != ')')
    {
      count++;
    }
  }
  if (count == ctx->size)
  {
    return;
  }

  /* Add every component as a child node */
  tmp[1] = '\0';
  for (i = 1UL; i < l; i++)
  {
    if (regex[i] != '|' && regex[i] != ')')
    {
      tmp[0] = regex[i];
      newctx = new_regex_ctx(ctx->size);
      newctx->s = GNUNET_strdup (tmp);
      if (children != NULL)
        memcpy (newctx->children, children, sizeof (*children) * ctx->size);
      ctx->children[c2i(tmp[0], ctx->size)] = newctx;
    }
  }
}

/**
 * Add a single regex to a context, splitting the exisiting state.
 *
 * We only had a partial match, split existing state, truncate the current node
 * so it only contains the prefix, add suffix(es) as children.
 *
 * @param ctx Context to split.
 * @param len Lenght of ctx->s
 * @param prefix_l Lenght of common prefix of the new regex and @a ctx->s
 */
static void
regex_split (struct RegexCombineCtx *ctx,
             unsigned int len,
             unsigned int prefix_l)
{
  struct RegexCombineCtx *newctx;
  unsigned int idx;
  char *suffix;

  suffix = GNUNET_malloc (len - prefix_l + 1);
  strncpy (suffix, &ctx->s[prefix_l], len - prefix_l + 1);

  /* Suffix saved, truncate current node so it only contains the prefix,
   * copy any children nodes to put as grandchildren and initialize new empty
   * children array.
   */
  ctx->s[prefix_l] = '\0';

  /* If the suffix is an OR expression, add multiple children */
  if ('(' == suffix[0])
  {
    struct RegexCombineCtx **tmp;

    tmp = ctx->children;
    ctx->children = GNUNET_malloc (sizeof(*tmp) * ctx->size);
    regex_add_multiple (ctx, suffix, tmp);
    GNUNET_free (tmp);
    return;
  }

  /* The suffix is a normal string, add as one node */
  newctx = new_regex_ctx (ctx->size);
  newctx->s = suffix;
  move_children (newctx, ctx);
  idx = c2i(suffix[0], ctx->size);
  ctx->children[idx] = newctx;
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
  long unsigned int l;
  unsigned int prefix_l;
  const char *rest_r;
  const char *rest_s;
  size_t len;
  int idx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "regex_add '%s' into '%s'\n",
              regex, ctx->s);
  l = strlen (regex);
  if (0UL == l)
    return;

  /* If the regex is in the form of (a|b|c), add every character separately */
  if ('(' == regex[0])
  {
    regex_add_multiple (ctx, regex, NULL);
    return;
  }

  p = get_longest_prefix (ctx, regex);
  if (NULL != p)
  {
    /* There is some prefix match, reduce regex and try again */
    prefix_l = get_prefix_length (p->s, regex);
    rest_s = &p->s[prefix_l];
    rest_r = &regex[prefix_l];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "chosen '%s' [%u]\n", p->s, prefix_l);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "prefix r '%.*s'\n", prefix_l, p->s);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "rest r '%s'\n", rest_r);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "rest s '%s'\n", rest_s);
    len = strlen (p->s);
    if (prefix_l < len)
    {
      regex_split (p, len, prefix_l);
    }
    regex_add (p, rest_r);
    return;
  }

  /* There is no prefix match, add new */
  idx = c2i(regex[0], ctx->size);
  if (NULL == ctx->children[idx] && NULL != ctx->s)
  {
    /* this was the end before, add empty string */
    newctx = new_regex_ctx (ctx->size);
    newctx->s = GNUNET_strdup ("");
    ctx->children[idx] = newctx;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " no match\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " new state %s\n", regex);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " under %s\n", ctx->s);
  newctx = new_regex_ctx(ctx->size);
  newctx->s = GNUNET_strdup (regex);
  ctx->children[idx] = newctx;
}


/**
 * Free all resources used by the context node and all its children.
 *
 * @param ctx Context to free.
 */
static void
regex_ctx_destroy (struct RegexCombineCtx *ctx)
{
  unsigned int i;

  if (NULL == ctx)
    return;

  for (i = 0; i < ctx->size; i++)
  {
    regex_ctx_destroy (ctx->children[i]);
  }
  GNUNET_free_non_null (ctx->s); /* 's' on root node is null */
  GNUNET_free (ctx->children);
  GNUNET_free (ctx);
}


/**
 * Combine an array of regexes into a single prefix-shared regex.
 * Returns a prefix-combine regex that matches the same strings as
 * any of the original regexes.
 *
 * WARNING: only useful for reading specific regexes for specific applications,
 *          namely the gnunet-regex-profiler / gnunet-regex-daemon.
 *          This function DOES NOT support arbitrary regex combining.
 *
 * @param regexes A NULL-terminated array of regexes.
 * @param alphabet_size Size of the alphabet the regex uses.
 *
 * @return A string with a single regex that matches any of the original regexes
 */
char *
REGEX_TEST_combine (char * const regexes[], unsigned int alphabet_size)
{
  unsigned int i;
  char *combined;
  const char *current;
  struct RegexCombineCtx *ctx;

  ctx = new_regex_ctx (alphabet_size);
  for (i = 0; regexes[i]; i++)
  {
    current = regexes[i];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Regex %u: %s\n", i, current);
    regex_add (ctx, current);
    debugctx (ctx, 0);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "\nCombining...\n");
  debugctx (ctx, 0);

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
