/*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
  unsigned int i;

  for (i=0;NULL != spec[i].parser;i++)
    if (NULL != spec[i].cleaner)
      spec[i].cleaner (spec[i].cls,
                       &spec[i]);
}


/* end of json.c */
