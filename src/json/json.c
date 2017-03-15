/*
  This file is part of GNUnet
  Copyright (C) 2014-2017 GNUnet e.V.

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file json/json.c
 * @brief functions to parse JSON snippets
 * @author Florian Dold
 * @author Benedikt Mueller
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_json_lib.h"


/**
 * Navigate and parse data in a JSON tree.  Tries to parse the @a root
 * to find all of the values given in the @a spec.  If one of the
 * entries in @a spec cannot be found or parsed, the name of the JSON
 * field is returned in @a error_json_name, and the offset of the
 * entry in @a spec is returned in @a error_line.
 *
 * @param root the JSON node to start the navigation at.
 * @param spec parse specification array
 * @param[out] error_json_name which JSON field was problematic
 * @param[out] which index into @a spec did we encounter an error
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_JSON_parse (const json_t *root,
                   struct GNUNET_JSON_Specification *spec,
                   const char **error_json_name,
                   unsigned int *error_line)
{
  unsigned int i;
  json_t *pos;

  if (NULL == root)
    return GNUNET_SYSERR;
  for (i=0;NULL != spec[i].parser;i++)
  {
    if (NULL == spec[i].field)
      pos = (json_t *) root;
    else
      pos = json_object_get (root,
                             spec[i].field);
    if ( (NULL == pos) ||
         (GNUNET_OK !=
          spec[i].parser (spec[i].cls,
                          pos,
                          &spec[i])) )
    {
      if (NULL != error_json_name)
        *error_json_name = spec[i].field;
      if (NULL != error_line)
        *error_line = i;
      GNUNET_JSON_parse_free (spec);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK; /* all OK! */
}


/**
 * Frees all elements allocated during a #GNUNET_JSON_parse()
 * operation.
 *
 * @param spec specification of the parse operation
 */
void
GNUNET_JSON_parse_free (struct GNUNET_JSON_Specification *spec)
{
  for (unsigned int i=0;NULL != spec[i].parser;i++)
    if (NULL != spec[i].cleaner)
      spec[i].cleaner (spec[i].cls,
                       &spec[i]);
}


/**
 * Set an option with a JSON value from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'json_t *')
 * @param option name of the option
 * @param value actual value of the option as a string.
 * @return #GNUNET_OK if parsing the value worked
 */
static int
set_json (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
          void *scls,
          const char *option,
          const char *value)
{
  json_t **json = scls;
  json_error_t error;

  *json = json_loads (value,
                      JSON_REJECT_DUPLICATES,
                      &error);
  if (NULL == *json)
  {
    FPRINTF (stderr,
             _("Failed to parse JSON in option `%s': %s (%s)\n"),
             option,
             error.text,
             error.source);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Allow user to specify a JSON input value.
 *
 * @param shortName short name of the option
 * @param name long name of the option
 * @param argumentHelp help text for the option argument
 * @param description long help text for the option
 * @param[out] val set to the JSON specified at the command line
 */
struct GNUNET_GETOPT_CommandLineOption
GNUNET_JSON_getopt (char shortName,
                    const char *name,
                    const char *argumentHelp,
                    const char *description,
                    json_t **json)
{
  struct GNUNET_GETOPT_CommandLineOption clo = {
    .shortName =  shortName,
    .name = name,
    .argumentHelp = argumentHelp,
    .description = description,
    .require_argument = 1,
    .processor = &set_json,
    .scls = (void *) json
  };

  return clo;
}


/* end of json.c */
