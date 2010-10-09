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
 * @file nat/upnp-reply-parse.h
 * @brief Parser for XML replies to UPnP commands
 *
 * @author Milan Bouchet-Valat
 */

#ifndef UPNP_PARSE_REPLY_H
#define UPNP_PARSE_REPLY_H

#include "bsdqueue.h"

  /**
   * Name-value pair used by UPNP_REPLY_NameValueList.
   */
struct UPNP_REPLY_NameValue_
{
  LIST_ENTRY (UPNP_REPLY_NameValue_) entries;
  char name[64];
  char value[64];
};

  /**
   * Name-value list to store data parsed from a UPnP reply.
   */
struct UPNP_REPLY_NameValueList_
{
  LIST_HEAD (listhead, UPNP_REPLY_NameValue_) head;
  char curelt[64];
};

  /**
   * Parse UPnP XML reply to a name-value list.
   */
void
UPNP_REPLY_parse_ (const char *buffer, int buf_size,
                   struct UPNP_REPLY_NameValueList_ *data);

  /**
   * Free name-value list obtained using UPNP_REPLY_parse().
   */
void UPNP_REPLY_free_ (struct UPNP_REPLY_NameValueList_ *pdata);

  /**
   * Get value corresponding to name from a name-value list.
   */
char *UPNP_REPLY_get_value_ (struct UPNP_REPLY_NameValueList_ *pdata,
                             const char *name);

#if DEBUG_UPNP
  /**
   * Parse a UPnP XMl reply and print the result as names-value pairs.
   */
void UPNP_REPLY_print_ (char *buffer, int buf_size);
#endif

#endif
