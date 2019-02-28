/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

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
 * @file util/benchmark.h
 * @brief benchmarking for various operations
 * @author Florian Dold <flo@dold.me>
 */

#ifndef BENCHMARK_H_
#define BENCHMARK_H_

#include "gnunet_time_lib.h"

/**
 * Maximum length of URLs considered for benchmarking.
 * Shorter URLs are simply truncated.
 */
#define MAX_BENCHMARK_URL_LEN 128

#if ENABLE_BENCHMARK
#define BENCHMARK_START(opname) \
    struct GNUNET_TIME_Absolute _benchmark_##opname##_start = GNUNET_TIME_absolute_get ()
#define BENCHMARK_END(opname) do { \
  { \
    struct GNUNET_TIME_Absolute _benchmark_##opname##_end = GNUNET_TIME_absolute_get (); \
    struct BenchmarkData *bd = get_benchmark_data (); \
    bd->opname##_count++; \
    bd->opname##_time = \
        GNUNET_TIME_relative_add (bd->opname##_time, \
                                  GNUNET_TIME_absolute_get_difference (_benchmark_##opname##_start, \
                                                                       _benchmark_##opname##_end)); \
  } \
} while (0)
#else
#define BENCHMARK_START(opname) do { } while (0)
#define BENCHMARK_END(opname) do { } while (0)
#endif


/**
 * Struct for benchmark data for one URL.
 */
struct UrlRequestData
{
  /**
   * Request URL, truncated (but 0-terminated).
   */
  char request_url[MAX_BENCHMARK_URL_LEN];

  /**
   * HTTP status code.
   */
  unsigned int status;
  
  /**
   * How often was the URL requested?
   */
  uint64_t count;

  /**
   * How many bytes were sent in total to request the URL.
   */
  uint64_t bytes_sent;

  /**
   * How many bytes were received in total as response to requesting this URL.
   */
  uint64_t bytes_received;

  /**
   * Total time spent requesting this URL.
   */
  struct GNUNET_TIME_Relative time;

  /**
   * Slowest time to response.
   */
  struct GNUNET_TIME_Relative time_max;

  /**
   * Fastest time to response.
   */
  struct GNUNET_TIME_Relative time_min;
};

#define GNUNET_DECLARE_BENCHMARK_OP(opname) \
    uint64_t opname##_count; \
    struct GNUNET_TIME_Relative opname##_time

/**
 * Thread-local struct for benchmarking data.
 */
struct BenchmarkData
{
  GNUNET_DECLARE_BENCHMARK_OP (ecc_ecdh);
  GNUNET_DECLARE_BENCHMARK_OP (ecdh_eddsa);
  GNUNET_DECLARE_BENCHMARK_OP (ecdhe_key_create);
  GNUNET_DECLARE_BENCHMARK_OP (ecdhe_key_get_public);
  GNUNET_DECLARE_BENCHMARK_OP (ecdsa_ecdh);
  GNUNET_DECLARE_BENCHMARK_OP (ecdsa_key_create);
  GNUNET_DECLARE_BENCHMARK_OP (ecdsa_key_get_public);
  GNUNET_DECLARE_BENCHMARK_OP (ecdsa_sign);
  GNUNET_DECLARE_BENCHMARK_OP (ecdsa_verify);
  GNUNET_DECLARE_BENCHMARK_OP (eddsa_ecdh);
  GNUNET_DECLARE_BENCHMARK_OP (eddsa_key_create);
  GNUNET_DECLARE_BENCHMARK_OP (eddsa_key_get_public);
  GNUNET_DECLARE_BENCHMARK_OP (eddsa_sign);
  GNUNET_DECLARE_BENCHMARK_OP (eddsa_verify);
  GNUNET_DECLARE_BENCHMARK_OP (hash);
  GNUNET_DECLARE_BENCHMARK_OP (hash_context_finish);
  GNUNET_DECLARE_BENCHMARK_OP (hash_context_read);
  GNUNET_DECLARE_BENCHMARK_OP (hash_context_start);
  GNUNET_DECLARE_BENCHMARK_OP (hkdf);
  GNUNET_DECLARE_BENCHMARK_OP (rsa_blind);
  GNUNET_DECLARE_BENCHMARK_OP (rsa_private_key_create);
  GNUNET_DECLARE_BENCHMARK_OP (rsa_private_key_get_public);
  GNUNET_DECLARE_BENCHMARK_OP (rsa_sign_blinded);
  GNUNET_DECLARE_BENCHMARK_OP (rsa_unblind);
  GNUNET_DECLARE_BENCHMARK_OP (rsa_verify);

  struct UrlRequestData *urd;

  unsigned int urd_len;

  unsigned int urd_capacity;
};

#undef GNUNET_DECLARE_BENCHMARK_OP


/**
 * Acquire the benchmark data for the current thread, allocate if necessary.
 * Installs handler to collect the benchmark data on thread termination.
 *
 * @return benchmark data for the current thread
 */
struct BenchmarkData *
get_benchmark_data (void);

/**
 * Get benchmark data for a URL.  If the URL is too long, it's truncated
 * before looking up the correspoding benchmark data.
 *
 * Statistics are bucketed by URL and status code.
 *
 * @param url url to get request data for
 * @param status http status code
 */
struct UrlRequestData *
get_url_benchmark_data (char *url, unsigned int status);

#endif  /* BENCHMARK_H_ */
