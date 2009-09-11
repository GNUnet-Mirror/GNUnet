/**
 * @file transport/upnp_util.h Utility Functions
 * @ingroup core
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @todo Rename the functions so that they live somewhere in the gaim
 *       namespace.
 */
#ifndef _GAIM_UTIL_H_
#define _GAIM_UTIL_H_

#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Unescapes HTML entities to their literal characters.
 * For example "&amp;" is replaced by '&' and so on.
 * Actually only "&amp;", "&quot;", "&lt;" and "&gt;" are currently
 * supported.
 *
 * @param html The string in which to unescape any HTML entities
 *
 * @return the text with HTML entities literalized
 */
  char *gaim_unescape_html (const char *html);

/**
 * Compares two strings to see if the first contains the second as
 * a proper prefix.
 *
 * @param s  The string to check.
 * @param p  The prefix in question.
 *
 * @return   TRUE if p is a prefix of s, otherwise FALSE.
 */
  int gaim_str_has_prefix (const char *s, const char *p);

  char *g_strdup_printf (const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
