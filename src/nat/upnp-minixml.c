/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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

/*
 * Code in this file is originally based on the miniupnp library.
 * Copyright (c) 2005-2009, Thomas BERNARD. All rights reserved.
 *
 * Original licence:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * The name of the author may not be used to endorse or promote products
 * 	   derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file nat/minixml.c
 * @brief Simple XML parser used by UPnP
 *
 * @author Milan Bouchet-Valat
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "upnp-minixml.h"

/**
 * Used to parse the argument list.
 *
 * @returns GNUNET_OK on success, or GNUNET_SYSERR if the end
 *   of the xmlbuffer is reached
 */
static int
parse_att (struct UPNP_xml_parser_ *p)
{
  const char *att_name;
  int att_name_len;
  const char *att_value;
  int att_value_len;
  while (p->xml < p->xml_end)
    {
      if (*p->xml == '/' || *p->xml == '>')
        return GNUNET_OK;
      if (!IS_WHITE_SPACE (*p->xml))
        {
          char sep;
          att_name = p->xml;
          att_name_len = 0;
          while (*p->xml != '=' && !IS_WHITE_SPACE (*p->xml))
            {
              att_name_len++;
              p->xml++;
              if (p->xml >= p->xml_end)
                return GNUNET_SYSERR;
            }
          while (*(p->xml++) != '=')
            {
              if (p->xml >= p->xml_end)
                return GNUNET_SYSERR;
            }
          while (IS_WHITE_SPACE (*p->xml))
            {
              p->xml++;
              if (p->xml >= p->xml_end)
                return GNUNET_SYSERR;
            }
          sep = *p->xml;
          if (sep == '\'' || sep == '\"')
            {
              p->xml++;
              if (p->xml >= p->xml_end)
                return GNUNET_SYSERR;
              att_value = p->xml;
              att_value_len = 0;
              while (*p->xml != sep)
                {
                  att_value_len++;
                  p->xml++;
                  if (p->xml >= p->xml_end)
                    return GNUNET_SYSERR;
                }
            }
          else
            {
              att_value = p->xml;
              att_value_len = 0;
              while (!IS_WHITE_SPACE (*p->xml)
                     && *p->xml != '>' && *p->xml != '/')
                {
                  att_value_len++;
                  p->xml++;
                  if (p->xml >= p->xml_end)
                    return GNUNET_SYSERR;
                }
            }

          if (p->att_func)
            p->att_func (p->cls, att_name, att_name_len, att_value,
                         att_value_len);
        }
      p->xml++;
    }
  return GNUNET_SYSERR;
}

/**
 * Parse the xml stream and call the callback
 * functions when needed...
 */
void
parse_elt (struct UPNP_xml_parser_ *p)
{
  int i;
  const char *element_name;
  while (p->xml < (p->xml_end - 1))
    {
      /* Element name */
      if ((p->xml)[0] == '<' && (p->xml)[1] != '?')
        {
          i = 0;
          element_name = ++p->xml;
          while (!IS_WHITE_SPACE (*p->xml)
                 && (*p->xml != '>') && (*p->xml != '/'))
            {
              i++;
              p->xml++;
              if (p->xml >= p->xml_end)
                return;
              /* to ignore namespace : */
              if (*p->xml == ':')
                {
                  i = 0;
                  element_name = ++p->xml;
                }
            }

          /* Start of element */
          if (i > 0)
            {
              if (p->start_elt_func)
                p->start_elt_func (p->cls, element_name, i);
              if (parse_att (p) != GNUNET_OK)
                return;
              if (*p->xml != '/')
                {
                  const char *data;
                  i = 0;
                  data = ++p->xml;
                  if (p->xml >= p->xml_end)
                    return;
                  while (IS_WHITE_SPACE (*p->xml))
                    {
                      p->xml++;
                      if (p->xml >= p->xml_end)
                        return;
                    }
                  while (*p->xml != '<')
                    {
                      i++;
                      p->xml++;
                      if (p->xml >= p->xml_end)
                        return;
                    }
                  if (i > 0 && p->data_func)
                    p->data_func (p->cls, data, i);
                }
            }
          /* End of element */
          else if (*p->xml == '/')
            {
              i = 0;
              element_name = ++p->xml;
              if (p->xml >= p->xml_end)
                return;
              while ((*p->xml != '>'))
                {
                  i++;
                  p->xml++;
                  if (p->xml >= p->xml_end)
                    return;
                }
              if (p->end_elt_func)
                p->end_elt_func (p->cls, element_name, i);
              p->xml++;
            }
        }
      else
        {
          p->xml++;
        }
    }
}

/**
 * Parse XML content according to the values stored in the parser struct.
 * The parser must be initialized before calling this function
 */
void
UPNP_parse_xml_ (struct UPNP_xml_parser_ *parser)
{
  parser->xml = parser->xml_start;
  parser->xml_end = parser->xml_start + parser->xml_size;
  parse_elt (parser);
}
