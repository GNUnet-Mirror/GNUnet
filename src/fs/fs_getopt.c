/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_getopt.c
 * @brief helper functions for command-line argument processing
 * @author Igor Wronsky, Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs_api.h"

/* ******************** command-line option parsing API ******************** */

/**
 * Command-line option parser function that allows the user
 * to specify one or more '-k' options with keywords.  Each
 * specified keyword will be added to the URI.  A pointer to
 * the URI must be passed as the "scls" argument.
 *
 * @param ctx command line processor context
 * @param scls must be of type "struct GNUNET_FS_Uri **"
 * @param option name of the option (typically 'k')
 * @param value command line argument given
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_getopt_set_keywords (struct GNUNET_GETOPT_CommandLineProcessorContext
                               *ctx, void *scls, const char *option,
                               const char *value)
{
  struct GNUNET_FS_Uri **uri = scls;
  struct GNUNET_FS_Uri *u = *uri;
  char *val;
  size_t slen;

  if (u == NULL)
  {
    u = GNUNET_malloc (sizeof (struct GNUNET_FS_Uri));
    *uri = u;
    u->type = ksk;
    u->data.ksk.keywordCount = 0;
    u->data.ksk.keywords = NULL;
  }
  else
  {
    GNUNET_assert (u->type == ksk);
  }
  slen = strlen (value);
  if (slen == 0)
    return GNUNET_SYSERR;       /* cannot be empty */
  if (value[0] == '+')
  {
    /* simply preserve the "mandatory" flag */
    if (slen < 2)
      return GNUNET_SYSERR;     /* empty keywords not allowed */
    if ((value[1] == '"') && (slen > 3) && (value[slen - 1] == '"'))
    {
      /* remove the quotes, keep the '+' */
      val = GNUNET_malloc (slen - 1);
      val[0] = '+';
      memcpy (&val[1], &value[2], slen - 3);
      val[slen - 2] = '\0';
    }
    else
    {
      /* no quotes, just keep the '+' */
      val = GNUNET_strdup (value);
    }
  }
  else
  {
    if ((value[0] == '"') && (slen > 2) && (value[slen - 1] == '"'))
    {
      /* remove the quotes, add a space */
      val = GNUNET_malloc (slen);
      val[0] = ' ';
      memcpy (&val[1], &value[1], slen - 2);
      val[slen - 1] = '\0';
    }
    else
    {
      /* add a space to indicate "not mandatory" */
      val = GNUNET_malloc (slen + 2);
      strcpy (val, " ");
      strcat (val, value);
    }
  }
  GNUNET_array_append (u->data.ksk.keywords, u->data.ksk.keywordCount, val);
  return GNUNET_OK;
}


/**
 * Command-line option parser function that allows the user to specify
 * one or more '-m' options with metadata.  Each specified entry of
 * the form "type=value" will be added to the metadata.  A pointer to
 * the metadata must be passed as the "scls" argument.
 *
 * @param ctx command line processor context
 * @param scls must be of type "struct GNUNET_MetaData **"
 * @param option name of the option (typically 'k')
 * @param value command line argument given
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_getopt_set_metadata (struct GNUNET_GETOPT_CommandLineProcessorContext
                               *ctx, void *scls, const char *option,
                               const char *value)
{
  struct GNUNET_CONTAINER_MetaData **mm = scls;
  enum EXTRACTOR_MetaType type;
  const char *typename;
  const char *typename_i18n;
  struct GNUNET_CONTAINER_MetaData *meta;
  char *tmp;

  meta = *mm;
  if (meta == NULL)
  {
    meta = GNUNET_CONTAINER_meta_data_create ();
    *mm = meta;
  }

#if ENABLE_NLS
  tmp = GNUNET_STRINGS_to_utf8 (value, strlen (value), nl_langinfo (CODESET));
#else
  tmp = GNUNET_STRINGS_to_utf8 (value, strlen (value), "utf-8");
#endif
  type = EXTRACTOR_metatype_get_max ();
  while (type > 0)
  {
    type--;
    typename = EXTRACTOR_metatype_to_string (type);
    typename_i18n = dgettext (LIBEXTRACTOR_GETTEXT_DOMAIN, typename);
    if ((strlen (tmp) >= strlen (typename) + 1) &&
        (tmp[strlen (typename)] == ':') &&
        (0 == strncmp (typename, tmp, strlen (typename))))
    {
      GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>", type,
                                         EXTRACTOR_METAFORMAT_UTF8,
                                         "text/plain",
                                         &tmp[strlen (typename) + 1],
                                         strlen (&tmp[strlen (typename) + 1]) +
                                         1);
      GNUNET_free (tmp);
      tmp = NULL;
      break;
    }
    if ((strlen (tmp) >= strlen (typename_i18n) + 1) &&
        (tmp[strlen (typename_i18n)] == ':') &&
        (0 == strncmp (typename_i18n, tmp, strlen (typename_i18n))))
    {
      GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>", type,
                                         EXTRACTOR_METAFORMAT_UTF8,
                                         "text/plain",
                                         &tmp[strlen (typename_i18n) + 1],
                                         strlen (&tmp
                                                 [strlen (typename_i18n) + 1]) +
                                         1);
      GNUNET_free (tmp);
      tmp = NULL;
      break;
    }
  }
  if (tmp != NULL)
  {
    GNUNET_CONTAINER_meta_data_insert (meta, "<gnunet>",
                                       EXTRACTOR_METATYPE_UNKNOWN,
                                       EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                       tmp, strlen (tmp) + 1);
    GNUNET_free (tmp);
    printf (_
            ("Unknown metadata type in metadata option `%s'.  Using metadata type `unknown' instead.\n"),
            value);
  }
  return GNUNET_OK;
}

/* end of fs_getopt.c */
