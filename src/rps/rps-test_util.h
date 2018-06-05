/*
     This file is part of GNUnet.
     Copyright (C)

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file rps/rps-test_util.h
 * @brief Some utils faciliating the view into the internals for the sampler
 *        needed for evaluation
 * @author Julius Bünger
 */

#ifndef RPS_TEST_UTIL_H
#define RPS_TEST_UTIL_H

#ifndef TO_FILE
#define TO_FILE
#endif /* TO_FILE */


void
to_file_ (const char *file_name, char *line);

char *
auth_key_to_string (struct GNUNET_CRYPTO_AuthKey auth_key);

struct GNUNET_CRYPTO_AuthKey
string_to_auth_key (const char *str);

char * 
create_file (const char *name);

/**
 * This function is used to facilitate writing important information to disk
 */
#ifdef TO_FILE
#  define to_file(file_name, ...) do {char tmp_buf[512];\
    int size;\
    size = GNUNET_snprintf(tmp_buf,sizeof(tmp_buf),__VA_ARGS__);\
    if (0 > size)\
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,\
           "Failed to create tmp_buf\n");\
    else\
      to_file_(file_name,tmp_buf);\
  } while (0);
#  define to_file_w_len(file_name, len, ...) do {char tmp_buf[len];\
    int size;\
    size = GNUNET_snprintf(tmp_buf,sizeof(tmp_buf),__VA_ARGS__);\
    if (0 > size)\
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,\
           "Failed to create tmp_buf\n");\
    else\
      to_file_(file_name,tmp_buf);\
  } while (0);
#else /* TO_FILE */
#  define to_file(file_name, ...)
#  define to_file_w_len(file_name, len, ...)
#endif /* TO_FILE */

const char *
store_prefix_file_name (const struct GNUNET_PeerIdentity *peer,
    const char *prefix);

#endif /* RPS_TEST_UTIL_H */
/* end of gnunet-service-rps.c */
