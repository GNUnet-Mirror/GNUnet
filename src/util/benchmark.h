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
   * How often was the URL requested?
   */
  uint64_t count;

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

/**
 * Thread-local struct for benchmarking data.
 */
struct BenchmarkData
{
  /**
   * Number of eddsa_sign operations.
   */
  uint64_t eddsa_sign_count;

  /**
   * Time spent in eddsa_sign.
   */
  struct GNUNET_TIME_Relative eddsa_sign_time;

  struct UrlRequestData *urd;

  unsigned int urd_len;

  unsigned int urd_capacity;
};


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
 * @param url url to get request data for
 */
struct UrlRequestData *
get_url_benchmark_data (char *url);

#endif  /* BENCHMARK_H_ */
