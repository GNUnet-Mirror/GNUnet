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
 * Code in this file is originally inspired by the miniupnp library.
 * Copyright (c) 2006, Thomas BERNARD. All rights reserved.
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
 * @file nat/upnp-reply-parse.c
 * @brief Parser for XML replies to UPnP commands
 *
 * @author Milan Bouchet-Valat
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "upnp-minixml.h"
#include "upnp-reply-parse.h"

static void
start_elt (void *d, const char *name, int l)
{
  struct UPNP_REPLY_NameValueList_ *data =
    (struct UPNP_REPLY_NameValueList_ *) d;

  if (l > 63)
    l = 63;

  memcpy (data->curelt, name, l);
  data->curelt[l] = '\0';
}

static void
get_data (void *d, const char *datas, int l)
{
  struct UPNP_REPLY_NameValueList_ *data =
    (struct UPNP_REPLY_NameValueList_ *) d;
  struct UPNP_REPLY_NameValue_ *nv;

  nv = malloc (sizeof (struct UPNP_REPLY_NameValue_));

  if (l > 63)
    l = 63;

  strncpy (nv->name, data->curelt, 64);
  nv->name[63] = '\0';
  memcpy (nv->value, datas, l);
  nv->value[l] = '\0';

  LIST_INSERT_HEAD (&(data->head), nv, entries);
}

void
UPNP_REPLY_parse_ (const char *buffer, int buf_size,
                   struct UPNP_REPLY_NameValueList_ *data)
{
  struct UPNP_xml_parser_ parser;

  LIST_INIT (&(data->head));

  /* Init xml_parser object */
  parser.xml_start = buffer;
  parser.xml_size = buf_size;
  parser.cls = data;
  parser.start_elt_func = start_elt;
  parser.end_elt_func = 0;
  parser.data_func = get_data;
  parser.att_func = 0;

  UPNP_parse_xml_ (&parser);
}

void
UPNP_REPLY_free_ (struct UPNP_REPLY_NameValueList_ *pdata)
{
  struct UPNP_REPLY_NameValue_ *nv;

  while ((nv = pdata->head.lh_first) != NULL)
    {
      LIST_REMOVE (nv, entries);
      GNUNET_free (nv);
    }
}

char *
UPNP_REPLY_get_value_ (struct UPNP_REPLY_NameValueList_ *pdata,
                       const char *Name)
{
  struct UPNP_REPLY_NameValue_ *nv;
  char *p = NULL;

  for (nv = pdata->head.lh_first;
       (nv != NULL) && (p == NULL); nv = nv->entries.le_next)
    {
      if (strcmp (nv->name, Name) == 0)
        p = nv->value;
    }

  return p;
}

#if DEBUG_UPNP
void
UPNP_REPLY_print_ (char *buffer, int buf_size)
{
  struct UPNP_REPLY_NameValueList_ pdata;
  struct UPNP_REPLY_NameValue_ *nv;

  UPNP_REPLY_parse_ (buffer, buf_size, &pdata);

  for (nv = pdata.head.lh_first; nv != NULL; nv = nv->entries.le_next)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                       "%s = %s", nv->name, nv->value);
    }

  UPNP_REPLY_free_ (&pdata);
}
#endif
