/*
 *  This file is part of GNUnet
 *  (C) 2012 Christian Grothoff (and other contributing authors)
 * 
 *  GNUnet is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation; either version 3, or (at your
 *  option) any later version.
 * 
 *  GNUnet is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with GNUnet; see the file COPYING.  If not, write to the
 *  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *  Boston, MA 02111-1307, USA.
 */
/**
 * @file src/regex/regex_test_lib.h
 * @brief library to read regexes representing IP networks from a file.
 *        and simplyfinying the into one big regex, in order to run
 *        tests (regex performance, mesh profiler).
 * @author Bertlomiej Polot
 *
 */

#ifndef GNUNET_REGEX_TEST_LIB_H
#define GNUNET_REGEX_TEST_LIB_H


#ifdef __cplusplus
extern "C"
{
  #if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Combine an array of regexes into a single prefix-shared regex.
 *
 * @param regexes A NULL-terminated array of regexes.
 *
 * @retrun A string with a single regex that matches any of the original regexes
 */
char *
GNUNET_REGEX_combine(char * const regexes[]);

/**
 * Read a set of regexes from a file, one per line and return them in an array
 * suitable for GNUNET_REGEX_combine.
 * The array must be free'd using GNUNET_REGEX_free_from_file.
 *
 * @param filename Name of the file containing the regexes.
 *
 * @return A newly allocated, NULL terminated array of regexes.
 */
char **
GNUNET_REGEX_read_from_file (const char *filename);


/**
 * Free all memory reserved for a set of regexes created by read_from_file.
 *
 * @param regexes NULL-terminated array of regexes.
 */
void
GNUNET_REGEX_free_from_file (char **regexes);

#if 0                           /* keep Emacsens' auto-indent happy */
{
  #endif
  #ifdef __cplusplus
}
#endif

/* end of gnunet_regex_lib.h */
#endif