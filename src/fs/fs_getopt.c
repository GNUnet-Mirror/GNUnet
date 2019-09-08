/*
     This file is part of GNUnet.
     Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file fs/fs_getopt.c
 * @brief helper functions for command-line argument processing
 * @author Igor Wronsky, Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_getopt_lib.h"
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
 * @return #GNUNET_OK on success
 */
static int
getopt_set_keywords(struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                    void *scls,
                    const char *option,
                    const char *value)
{
  struct GNUNET_FS_Uri **uri = scls;
  struct GNUNET_FS_Uri *u = *uri;
  char *val;
  size_t slen;

  if (NULL == u)
    {
      u = GNUNET_new(struct GNUNET_FS_Uri);
      *uri = u;
      u->type = GNUNET_FS_URI_KSK;
      u->data.ksk.keywordCount = 0;
      u->data.ksk.keywords = NULL;
    }
  else
    {
      GNUNET_assert(GNUNET_FS_URI_KSK == u->type);
    }
  slen = strlen(value);
  if (0 == slen)
    return GNUNET_SYSERR;       /* cannot be empty */
  if (value[0] == '+')
    {
      /* simply preserve the "mandatory" flag */
      if (slen < 2)
        return GNUNET_SYSERR;   /* empty keywords not allowed */
      if ((value[1] == '"') && (slen > 3) && (value[slen - 1] == '"'))
        {
          /* remove the quotes, keep the '+' */
          val = GNUNET_malloc(slen - 1);
          val[0] = '+';
          GNUNET_memcpy(&val[1],
                        &value[2],
                        slen - 3);
          val[slen - 2] = '\0';
        }
      else
        {
          /* no quotes, just keep the '+' */
          val = GNUNET_strdup(value);
        }
    }
  else
    {
      if ((value[0] == '"') && (slen > 2) && (value[slen - 1] == '"'))
        {
          /* remove the quotes, add a space */
          val = GNUNET_malloc(slen);
          val[0] = ' ';
          GNUNET_memcpy(&val[1],
                        &value[1],
                        slen - 2);
          val[slen - 1] = '\0';
        }
      else
        {
          /* add a space to indicate "not mandatory" */
          val = GNUNET_malloc(slen + 2);
          strcpy(val, " ");
          strcat(val, value);
        }
    }
  GNUNET_array_append(u->data.ksk.keywords,
                      u->data.ksk.keywordCount,
                      val);
  return GNUNET_OK;
}


/**
 * Allow user to specify keywords.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] topKeywords set to the desired value
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_FS_GETOPT_KEYWORDS(char shortName,
                          const char *name,
                          const char *argumentHelp,
                          const char *description,
                          struct GNUNET_FS_Uri **topKeywords)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName = shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &getopt_set_keywords,
    .scls = (void *)topKeywords
  };

  return clo;
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
 * @return #GNUNET_OK on success
 */
static int
getopt_set_metadata(struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
                    void *scls,
                    const char *option,
                    const char *value)
{
  struct GNUNET_CONTAINER_MetaData **mm = scls;

#if HAVE_EXTRACTOR_H && HAVE_LIBEXTRACTOR
  enum EXTRACTOR_MetaType type;
  const char *typename;
  const char *typename_i18n;
#endif
  struct GNUNET_CONTAINER_MetaData *meta;
  char *tmp;

  meta = *mm;
  if (meta == NULL)
    {
      meta = GNUNET_CONTAINER_meta_data_create();
      *mm = meta;
    }

  /* Use GNUNET_STRINGS_get_utf8_args() in main() to acquire utf-8-encoded
   * commandline arguments, so that the following line is not needed.
   */
  /*tmp = GNUNET_STRINGS_to_utf8 (value, strlen (value), locale_charset ());*/
  tmp = GNUNET_strdup(value);
#if HAVE_EXTRACTOR_H && HAVE_LIBEXTRACTOR
  type = EXTRACTOR_metatype_get_max();
  while (type > 0)
    {
      type--;
      typename = EXTRACTOR_metatype_to_string(type);
      typename_i18n = dgettext(LIBEXTRACTOR_GETTEXT_DOMAIN, typename);
      if ((strlen(tmp) >= strlen(typename) + 1) &&
          (tmp[strlen(typename)] == ':') &&
          (0 == strncmp(typename, tmp, strlen(typename))))
        {
          GNUNET_CONTAINER_meta_data_insert(meta, "<gnunet>", type,
                                            EXTRACTOR_METAFORMAT_UTF8,
                                            "text/plain",
                                            &tmp[strlen(typename) + 1],
                                            strlen(&tmp[strlen(typename) + 1]) +
                                            1);
          GNUNET_free(tmp);
          tmp = NULL;
          break;
        }
      if ((strlen(tmp) >= strlen(typename_i18n) + 1) &&
          (tmp[strlen(typename_i18n)] == ':') &&
          (0 == strncmp(typename_i18n, tmp, strlen(typename_i18n))))
        {
          GNUNET_CONTAINER_meta_data_insert(meta, "<gnunet>", type,
                                            EXTRACTOR_METAFORMAT_UTF8,
                                            "text/plain",
                                            &tmp[strlen(typename_i18n) + 1],
                                            strlen(&tmp
                                                   [strlen(typename_i18n) + 1]) +
                                            1);
          GNUNET_free(tmp);
          tmp = NULL;
          break;
        }
    }
#endif

  if (NULL != tmp)
    {
      GNUNET_CONTAINER_meta_data_insert(meta, "<gnunet>",
                                        EXTRACTOR_METATYPE_UNKNOWN,
                                        EXTRACTOR_METAFORMAT_UTF8, "text/plain",
                                        tmp, strlen(tmp) + 1);
      GNUNET_free(tmp);
      printf(_
               ("Unknown metadata type in metadata option `%s'.  Using metadata type `unknown' instead.\n"),
             value);
    }
  return GNUNET_OK;
}

/**
 * Allow user to specify metadata.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] metadata set to the desired value
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_FS_GETOPT_METADATA(char shortName,
                          const char *name,
                          const char *argumentHelp,
                          const char *description,
                          struct GNUNET_CONTAINER_MetaData **meta)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName = shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &getopt_set_metadata,
    .scls = (void *)meta
  };

  return clo;
}




/* end of fs_getopt.c */
