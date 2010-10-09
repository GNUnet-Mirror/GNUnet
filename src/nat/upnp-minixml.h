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
 * @file nat/upnp-minixml.h
 * @brief Simple XML parser used by UPnP
 *
 * @author Milan Bouchet-Valat
 */

#ifndef MINIXML_H
#define MINIXML_H

#define IS_WHITE_SPACE(c) ((c==' ') || (c=='\t') || (c=='\r') || (c=='\n'))

/**
 * Structure describing the contents and methods that should be
 * used when running parse_xml();
 *
 * If a callback function pointer is set to NULL, the function
 * is not called */
struct UPNP_xml_parser_
{
  /**
   * Pointer to the XML data to parse
   */
  const char *xml_start;

  /**
   * Pointer to the last character to parse (optional)
   */
  const char *xml_end;

  /**
   * Size of the data stored at xml_start
   */
  int xml_size;

  /**
   * Pointer to current character (private)
   */
  const char *xml;

  /**
   * Closure for user-provided callback functions
   */
  void *cls;

  /**
   * User function called when reaching the start of an XML element.
   */
  void (*start_elt_func) (void *cls, const char *elt, int elt_len);

  /**
   * User function called when reaching the end of an XML element.
   */
  void (*end_elt_func) (void *cls, const char *elt, int elt_len);

  /**
   * User function called when an XML element data is found.
   */
  void (*data_func) (void *cls, const char *data, int data_len);

  /**
   * User function called for every XML element attribute.
   */
  void (*att_func) (void *cls, const char *att_name, int att_name_len,
                    const char *att_value, int att_value_len);
};

/**
 * Parse data provided to the xml_parser structure, using
 * user-provided functions.
 *
 * The xmlparser structure must be initialized before the call;
 * the following structure members have to be set:
 * xml_start, xml_size, cls, *func.
 * The xml member is for internal usage, xml_end is computed
 * automatically.
 *
 * @param parser the structure used for parsing */
void UPNP_parse_xml_ (struct UPNP_xml_parser_ *parser);

#endif
