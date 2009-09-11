/*
 * @file upnp_util.cUtility Functions
 * @ingroup core
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "platform.h"
#include "util.h"
#include "gnunet_util.h"

/* Returns a NULL-terminated string after unescaping an entity
 * (eg. &amp;, &lt; &#38 etc.) starting at s. Returns NULL on failure.*/
static char *
detect_entity (const char *text, int *length)
{
  const char *pln;
  int len;
  int pound;
  char b[7];
  char *buf;

  if (!text || *text != '&')
    return NULL;

#define IS_ENTITY(s)  (!strncasecmp(text, s, (len = sizeof(s) - 1)))

  if (IS_ENTITY ("&amp;"))
    pln = "&";
  else if (IS_ENTITY ("&lt;"))
    pln = "<";
  else if (IS_ENTITY ("&gt;"))
    pln = ">";
  else if (IS_ENTITY ("&nbsp;"))
    pln = " ";
  else if (IS_ENTITY ("&copy;"))
    pln = "\302\251";           /* or use g_unichar_to_utf8(0xa9); */
  else if (IS_ENTITY ("&quot;"))
    pln = "\"";
  else if (IS_ENTITY ("&reg;"))
    pln = "\302\256";           /* or use g_unichar_to_utf8(0xae); */
  else if (IS_ENTITY ("&apos;"))
    pln = "\'";
  else if (*(text + 1) == '#' && (sscanf (text, "&#%u;", &pound) == 1) &&
           pound != 0 && *(text + 3 + (int) log10 (pound)) == ';')
    {
      buf = GNUNET_convert_string_to_utf8 (NULL,
                                           (const char *) &pound,
                                           2, "UNICODE");
      if (strlen (buf) > 6)
        buf[6] = '\0';
      strcpy (b, buf);
      pln = b;
      GNUNET_free (buf);
      len = 2;
      while (isdigit ((int) text[len]))
        len++;
      if (text[len] == ';')
        len++;
    }
  else
    return NULL;

  if (length)
    *length = len;
  return GNUNET_strdup (pln);
}

char *
g_strdup_printf (const char *fmt, ...)
{
  size_t size;
  char *buf;
  va_list va;

  va_start (va, fmt);
  size = VSNPRINTF (NULL, 0, fmt, va) + 1;
  va_end (va);
  buf = GNUNET_malloc (size);
  va_start (va, fmt);
  VSNPRINTF (buf, size, fmt, va);
  va_end (va);
  return buf;
}

char *
gaim_unescape_html (const char *html)
{
  if (html != NULL)
    {
      const char *c = html;
      char *ret = GNUNET_strdup ("");
      char *app;
      while (*c)
        {
          int len;
          char *ent;

          if ((ent = detect_entity (c, &len)) != NULL)
            {
              app = g_strdup_printf ("%s%s", ret, ent);
              GNUNET_free (ret);
              ret = app;
              c += len;
              GNUNET_free (ent);
            }
          else if (!strncmp (c, "<br>", 4))
            {
              app = g_strdup_printf ("%s%s", ret, "\n");
              GNUNET_free (ret);
              ret = app;
              c += 4;
            }
          else
            {
              app = g_strdup_printf ("%s%c", ret, *c);
              GNUNET_free (ret);
              ret = app;
              c++;
            }
        }
      return ret;
    }
  return NULL;
}


int
gaim_str_has_prefix (const char *s, const char *p)
{
  if ((s == NULL) || (p == NULL))
    return 0;
  return !strncmp (s, p, strlen (p));
}

/* end of util.c */
