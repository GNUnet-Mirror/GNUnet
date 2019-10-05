/*
     This file is part of GNUnet.
     Copyright (C)

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file rps/rps-test_util.h
 * @brief Some utils faciliating the view into the internals for the sampler
 *        needed for evaluation
 * @author Julius Bünger
 */

#ifndef RPS_TEST_UTIL_H
#define RPS_TEST_UTIL_H

#define TO_FILE 0


char *
auth_key_to_string (struct GNUNET_CRYPTO_AuthKey auth_key);

struct GNUNET_CRYPTO_AuthKey
string_to_auth_key (const char *str);


/**
 * @brief Get file handle
 *
 * If necessary, create file handle and store it with the other file handles.
 *
 * @param name Name of the file
 *
 * @return File handle
 */
struct GNUNET_DISK_FileHandle *
get_file_handle (const char *name);

/**
 * @brief Close all files that were opened with #get_file_handle
 *
 * @return Success of iterating over files
 */
int
close_all_files ();

/**
 * This function is used to facilitate writing important information to disk
 */
#ifdef TO_FILE
#define to_file(file_name, ...) do { \
    char tmp_buf[512] = ""; \
    int size; \
    if (NULL == file_name) break; \
    size = GNUNET_snprintf (tmp_buf, sizeof(tmp_buf), __VA_ARGS__); \
    if (0 > size) \
    { \
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, \
                  "Failed to create tmp_buf\n"); \
      break; \
    } \
    (void) strncat (tmp_buf, "\n", 512); \
    GNUNET_DISK_file_write (get_file_handle (file_name), \
                            tmp_buf, \
                            strnlen (tmp_buf, 512)); \
} while (0);


#define to_file_w_len(file_name, len, ...) do { char tmp_buf [len]; \
                                                int size; \
                                                memset (tmp_buf, 0, len); \
                                                size = GNUNET_snprintf (tmp_buf, \
                                                                        sizeof( \
                                                                          tmp_buf), \
                                                                        __VA_ARGS__); \
                                                if (0 > size) \
                                                { \
                                                  GNUNET_log ( \
                                                    GNUNET_ERROR_TYPE_WARNING, \
                                                    "Failed to create tmp_buf\n"); \
                                                  break; \
                                                } \
                                                (void) strncat (tmp_buf, "\n", \
                                                                len); \
                                                GNUNET_DISK_file_write ( \
                                                  get_file_handle (file_name), \
                                                  tmp_buf, \
                                                  strnlen ( \
                                                    tmp_buf, len)); \
} while (0);
#else /* TO_FILE */
#  define to_file(file_name, ...)
#  define to_file_w_len(file_name, len, ...)
#endif /* TO_FILE */

char *
store_prefix_file_name (const unsigned int index,
                        const char *prefix);

void
to_file_raw (const char *file_name, const char *buf, size_t size_buf);

void
to_file_raw_unaligned (const char *file_name,
                       const char *buf,
                       size_t size_buf,
                       unsigned bits_needed);


/**
 * @brief Factorial
 *
 * @param x Number of which to compute the factorial
 *
 * @return Factorial of @a x
 */
uint32_t fac (uint32_t x);


/**
 * @brief Binomial coefficient (n choose k)
 *
 * @param n
 * @param k
 *
 * @return Binomial coefficient of @a n and @a k
 */
uint32_t binom (uint32_t n, uint32_t k);

#endif /* RPS_TEST_UTIL_H */
/* end of gnunet-service-rps.c */
