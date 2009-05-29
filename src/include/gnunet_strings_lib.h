/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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

/**
 * @file include/gnunet_strings_lib.h
 * @brief strings and string handling functions (including malloc
 *        and string tokenizing)
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_STRINGS_LIB_H
#define GNUNET_STRINGS_LIB_H

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_time_lib.h"


/**
 * Convert a given filesize into a fancy human-readable format.
 */
char *GNUNET_STRINGS_byte_size_fancy (unsigned long long size);

/**
 * Convert the len characters long character sequence
 * given in input that is in the given charset
 * to UTF-8.
 *
 * @return the converted string (0-terminated)
 */
char *GNUNET_STRINGS_to_utf8 (const char *input,
                              size_t len, const char *charset);

/**
 * Complete filename (a la shell) from abbrevition.
 *
 * @param fil the name of the file, may contain ~/ or
 *        be relative to the current directory
 * @returns the full file name,
 *          NULL is returned on error
 */
char *GNUNET_STRINGS_filename_expand (const char *fil);

/**
 * Fill a buffer of the given size with
 * count 0-terminated strings (given as varargs).
 * If "buffer" is NULL, only compute the amount of
 * space required (sum of "strlen(arg)+1").
 *
 * Unlike using "snprintf" with "%s", this function
 * will add 0-terminators after each string.  The
 * "GNUNET_string_buffer_tokenize" function can be
 * used to parse the buffer back into individual
 * strings.
 *
 * @return number of bytes written to the buffer
 *         (or number of bytes that would have been written)
 */
unsigned int GNUNET_STRINGS_buffer_fill (char *buffer,
                                         unsigned int size,
                                         unsigned int count, ...);

/**
 * Given a buffer of a given size, find "count"
 * 0-terminated strings in the buffer and assign
 * the count (varargs) of type "const char**" to the
 * locations of the respective strings in the
 * buffer.
 *
 * @param buffer the buffer to parse
 * @param size size of the buffer
 * @param count number of strings to locate
 * @return offset of the character after the last 0-termination
 *         in the buffer, or 0 on error.
 */
unsigned int GNUNET_STRINGS_buffer_tokenize (const char *buffer,
                                             unsigned int size,
                                             unsigned int count, ...);



/**
 * "man ctime_r", except for GNUnet time; also, unlike ctime, the
 * return value does not include the newline character.
 */
char *GNUNET_STRINGS_absolute_time_to_string (struct GNUNET_TIME_Absolute t);


/**
 * Give relative time in human-readable fancy format.
 * @param delta time in milli seconds
 */
char *GNUNET_STRINGS_relative_time_to_string (struct GNUNET_TIME_Relative
                                              delta);
#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_UTIL_STRING_H */
#endif
/* end of gnunet_util_string.h */
