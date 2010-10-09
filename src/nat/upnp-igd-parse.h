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
#ifndef UPNP_IGD_PARSE_H
#define UPNP_IGD_PARSE_H

#define MINIUPNPC_URL_MAXSIZE (128)

/**
 * Structure to store the result of the parsing of UPnP
 * descriptions of Internet Gateway Devices.
 */
struct UPNP_IGD_Data_
{
  char cur_elt_name[MINIUPNPC_URL_MAXSIZE];
  char base_url[MINIUPNPC_URL_MAXSIZE];
  int level;

  /* "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1" */
  char control_url_CIF[MINIUPNPC_URL_MAXSIZE];
  char event_sub_url_CIF[MINIUPNPC_URL_MAXSIZE];
  char scpd_url_CIF[MINIUPNPC_URL_MAXSIZE];
  char service_type_CIF[MINIUPNPC_URL_MAXSIZE];

  /* "urn:schemas-upnp-org:service:WANIPConnection:1"
   * "urn:schemas-upnp-org:service:WANPPPConnection:1" */
  char control_url[MINIUPNPC_URL_MAXSIZE];
  char event_sub_url[MINIUPNPC_URL_MAXSIZE];
  char scpd_url[MINIUPNPC_URL_MAXSIZE];
  char service_type[MINIUPNPC_URL_MAXSIZE];

  /* Used temporarily by the parser */
  char control_url_tmp[MINIUPNPC_URL_MAXSIZE];
  char event_sub_url_tmp[MINIUPNPC_URL_MAXSIZE];
  char scpd_url_tmp[MINIUPNPC_URL_MAXSIZE];
  char service_type_tmp[MINIUPNPC_URL_MAXSIZE];
};

/**
 * Parse UPnP IGD XML description to a UPNP_IGD_Data_ structure.
 */
void
UPNP_IGD_parse_desc_ (const char *buffer, int buf_size,
                      struct UPNP_IGD_Data_ *data);

#endif
