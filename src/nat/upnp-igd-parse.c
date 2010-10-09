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
 * Copyright (c) 2005-2008, Thomas BERNARD. All rights reserved.
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
 * @file nat/upnp-igd-parse.h
 * @brief Parser for XML descriptions of UPnP Internet Gateway Devices
 *
 * @author Milan Bouchet-Valat
 */
#include <stdio.h>
#include <string.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "upnp-minixml.h"
#include "upnp-igd-parse.h"

/**
 * Start element handler: update nesting level counter
 * and copy element name.
 */
static void
start_elt (void *d, const char *name, int l)
{
  struct UPNP_IGD_Data_ *datas = (struct UPNP_IGD_Data_ *) d;

  memcpy (datas->cur_elt_name, name, l);
  datas->cur_elt_name[l] = '\0';
  datas->level++;
  if ((l == 7) && !memcmp (name, "service", l))
    {
      datas->control_url_tmp[0] = '\0';
      datas->event_sub_url_tmp[0] = '\0';
      datas->scpd_url_tmp[0] = '\0';
      datas->service_type_tmp[0] = '\0';
    }
}

/**
 * End element handler: update nesting level counter
 * and update parser state if service element is parsed.
 */
static void
end_elt (void *d, const char *name, int l)
{
  struct UPNP_IGD_Data_ *datas = (struct UPNP_IGD_Data_ *) d;

  datas->level--;

  if ((l == 7) && !memcmp (name, "service", l))
    {
      if (0 == strcmp (datas->service_type_tmp,
                       "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1"))
        {
          memcpy (datas->control_url_CIF, datas->control_url_tmp,
                  MINIUPNPC_URL_MAXSIZE);
          memcpy (datas->event_sub_url_CIF, datas->event_sub_url_tmp,
                  MINIUPNPC_URL_MAXSIZE);
          memcpy (datas->scpd_url_CIF, datas->scpd_url_tmp,
                  MINIUPNPC_URL_MAXSIZE);
          memcpy (datas->service_type_CIF, datas->service_type_tmp,
                  MINIUPNPC_URL_MAXSIZE);
        }
      else if (0 == strcmp (datas->service_type_tmp,
                            "urn:schemas-upnp-org:service:WANIPConnection:1")
               || 0 == strcmp (datas->service_type_tmp,
                               "urn:schemas-upnp-org:service:WANPPPConnection:1"))
        {
          memcpy (datas->control_url, datas->control_url_tmp,
                  MINIUPNPC_URL_MAXSIZE);
          memcpy (datas->event_sub_url, datas->event_sub_url_tmp,
                  MINIUPNPC_URL_MAXSIZE);
          memcpy (datas->scpd_url, datas->scpd_url_tmp,
                  MINIUPNPC_URL_MAXSIZE);
          memcpy (datas->service_type, datas->service_type_tmp,
                  MINIUPNPC_URL_MAXSIZE);
        }
    }
}

/**
 * Data handler: copy data depending on the current
 * element name and state.
 */
static void
IGDdata (void *d, const char *data, int l)
{
  struct UPNP_IGD_Data_ *datas = (struct UPNP_IGD_Data_ *) d;
  char *dstmember = NULL;

  if (!strcmp (datas->cur_elt_name, "URLBase"))
    dstmember = datas->base_url;
  else if (!strcmp (datas->cur_elt_name, "serviceType"))
    dstmember = datas->service_type_tmp;
  else if (!strcmp (datas->cur_elt_name, "controlURL"))
    dstmember = datas->control_url_tmp;
  else if (!strcmp (datas->cur_elt_name, "eventSubURL"))
    dstmember = datas->event_sub_url_tmp;
  else if (!strcmp (datas->cur_elt_name, "SCPDURL"))
    dstmember = datas->scpd_url_tmp;

  /* Copy current element name into destination member */
  if (dstmember)
    {
      if (l >= MINIUPNPC_URL_MAXSIZE)
        l = MINIUPNPC_URL_MAXSIZE - 1;

      memcpy (dstmember, data, l);
      dstmember[l] = '\0';
    }
}

#ifdef DEBUG_UPNP
static void
print_IGD (struct UPNP_IGD_Data_ *d)
{
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                   "base_url = %s\n", d->base_url);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                   "WAN Device (Common interface config) :\n"
                   " sevice_type = %s\n"
                   " control_url = %s\n"
                   " event_sub_url = %s\n"
                   " scpd_url = %s\n",
                   d->service_type_CIF,
                   d->control_url_CIF, d->event_sub_url_CIF, d->scpd_url_CIF);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "UPnP",
                   "WAN Connection Device (IP or PPP Connection):\n"
                   " service_type = %s\n"
                   " control_url = %s\n"
                   " event_sub_url = %s\n"
                   " scpd_url = %s\n",
                   d->service_type,
                   d->control_url, d->event_sub_url, d->scpd_url);
}
#endif

/**
 * Parse XML description of an IGD device into a UPNP_IGD_Data_ struct.
 */
void
UPNP_IGD_parse_desc_ (const char *buffer, int buf_size,
                      struct UPNP_IGD_Data_ *data)
{
  struct UPNP_xml_parser_ parser;

  parser.xml_start = buffer;
  parser.xml_size = buf_size;
  parser.cls = data;
  parser.start_elt_func = start_elt;
  parser.end_elt_func = end_elt;
  parser.data_func = IGDdata;
  parser.att_func = 0;

  UPNP_parse_xml_ (&parser);

#ifdef DEBUG_UPNP
  print_IGD (data);
#endif
}
