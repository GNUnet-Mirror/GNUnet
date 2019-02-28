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
 * @file util/benchmark.c
 * @brief benchmarking for various operations
 * @author Florian Dold <flo@dold.me>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "benchmark.h"
#include <pthread.h>
#include <sys/syscall.h>

/**
 * Thread-local storage key for the benchmark data.
 */
static pthread_key_t key;

/**
 * One-time initialization marker for key.
 */
static pthread_once_t key_once = PTHREAD_ONCE_INIT;


/**
 * Write benchmark data to a file.
 *
 * @param bd the benchmark data
 */
static void
write_benchmark_data (struct BenchmarkData *bd)
{
  struct GNUNET_DISK_FileHandle *fh;
  pid_t pid = getpid ();
  pid_t tid = syscall (SYS_gettid);
  char *benchmark_dir;
  char *s;

  benchmark_dir = getenv ("GNUNET_BENCHMARK_DIR");

  if (NULL == benchmark_dir)
    return;

  if (GNUNET_OK != GNUNET_DISK_directory_create (benchmark_dir))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_asprintf (&s, "%s/gnunet-benchmark-ops-%s-%llu-%llu.txt",
                   benchmark_dir,
                   (pid == tid) ? "main" : "thread",
                   (unsigned long long) pid,
                   (unsigned long long) tid);

  fh = GNUNET_DISK_file_open (s,
                              (GNUNET_DISK_OPEN_WRITE |
                               GNUNET_DISK_OPEN_TRUNCATE |
                               GNUNET_DISK_OPEN_CREATE),
                              (GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_assert (NULL != fh);
  GNUNET_free (s);

#define WRITE_BENCHMARK_OP(opname) do { \
  GNUNET_asprintf (&s, "op " #opname " count %llu time_us %llu\n", \
                   (unsigned long long) bd->opname##_count, \
                   (unsigned long long) bd->opname##_time.rel_value_us); \
  GNUNET_assert (GNUNET_SYSERR != GNUNET_DISK_file_write_blocking (fh, s, strlen (s))); \
  GNUNET_free (s); \
} while (0)

  WRITE_BENCHMARK_OP (ecc_ecdh);
  WRITE_BENCHMARK_OP (ecdh_eddsa);
  WRITE_BENCHMARK_OP (ecdhe_key_create);
  WRITE_BENCHMARK_OP (ecdhe_key_get_public);
  WRITE_BENCHMARK_OP (ecdsa_ecdh);
  WRITE_BENCHMARK_OP (ecdsa_key_create);
  WRITE_BENCHMARK_OP (ecdsa_key_get_public);
  WRITE_BENCHMARK_OP (ecdsa_sign);
  WRITE_BENCHMARK_OP (ecdsa_verify);
  WRITE_BENCHMARK_OP (eddsa_ecdh);
  WRITE_BENCHMARK_OP (eddsa_key_create);
  WRITE_BENCHMARK_OP (eddsa_key_get_public);
  WRITE_BENCHMARK_OP (eddsa_sign);
  WRITE_BENCHMARK_OP (eddsa_verify);
  WRITE_BENCHMARK_OP (hash);
  WRITE_BENCHMARK_OP (hash_context_finish);
  WRITE_BENCHMARK_OP (hash_context_read);
  WRITE_BENCHMARK_OP (hash_context_start);
  WRITE_BENCHMARK_OP (hkdf);
  WRITE_BENCHMARK_OP (rsa_blind);
  WRITE_BENCHMARK_OP (rsa_private_key_create);
  WRITE_BENCHMARK_OP (rsa_private_key_get_public);
  WRITE_BENCHMARK_OP (rsa_sign_blinded);
  WRITE_BENCHMARK_OP (rsa_unblind);
  WRITE_BENCHMARK_OP (rsa_verify);

#undef WRITE_BENCHMARK_OP

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));

  GNUNET_asprintf (&s, "%s/gnunet-benchmark-urls-%s-%llu-%llu.txt",
                   benchmark_dir,
                   (pid == tid) ? "main" : "thread",
                   (unsigned long long) pid,
                   (unsigned long long) tid);

  fh = GNUNET_DISK_file_open (s,
                              (GNUNET_DISK_OPEN_WRITE |
                               GNUNET_DISK_OPEN_TRUNCATE |
                               GNUNET_DISK_OPEN_CREATE),
                              (GNUNET_DISK_PERM_USER_READ |
                               GNUNET_DISK_PERM_USER_WRITE));
  GNUNET_assert (NULL != fh);
  GNUNET_free (s);

  for (unsigned int i = 0; i < bd->urd_len; i++)
  {
    struct UrlRequestData *urd = &bd->urd[i];
    GNUNET_asprintf (&s, "url %s status %u count %llu time_us %llu time_us_max %llu bytes_sent %llu bytes_received %llu\n",
                     urd->request_url,
                     urd->status,
                     (unsigned long long) urd->count,
                     (unsigned long long) urd->time.rel_value_us,
                     (unsigned long long) urd->time_max.rel_value_us,
                     (unsigned long long) urd->bytes_sent,
                     (unsigned long long) urd->bytes_received);
    GNUNET_assert (GNUNET_SYSERR != GNUNET_DISK_file_write_blocking (fh, s, strlen (s)));
    GNUNET_free (s);
  }

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));
}


/**
 * Called when the main thread exits and benchmark data for it was created.
 */
static void
main_thread_destructor ()
{
  struct BenchmarkData *bd;

  bd = pthread_getspecific (key);
  if (NULL != bd)
    write_benchmark_data (bd);
}


/**
 * Called when a thread exits and benchmark data for it was created.
 *
 * @param cls closure
 */
static void
thread_destructor (void *cls)
{
  struct BenchmarkData *bd = cls;

  // main thread will be handled by atexit
  if (getpid () == (pid_t) syscall (SYS_gettid))
    return;
  
  GNUNET_assert (NULL != bd);
  write_benchmark_data (bd);
}


/**
 * Initialize the thread-local variable key for benchmark data.
 */
static void
make_key ()
{
  (void) pthread_key_create (&key, &thread_destructor);
}


/**
 * Acquire the benchmark data for the current thread, allocate if necessary.
 * Installs handler to collect the benchmark data on thread termination.
 *
 * @return benchmark data for the current thread
 */
struct BenchmarkData *
get_benchmark_data (void)
{
  struct BenchmarkData *bd;

  (void) pthread_once (&key_once, &make_key);

  if (NULL == (bd = pthread_getspecific (key)))
  {
    bd = GNUNET_new (struct BenchmarkData);
    (void) pthread_setspecific (key, bd);
    if (getpid () == (pid_t) syscall (SYS_gettid))
    {
      // We're the main thread!
      atexit (main_thread_destructor);
    }
  }
  return bd;
}


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
get_url_benchmark_data (char *url, unsigned int status)
{
  char trunc[MAX_BENCHMARK_URL_LEN];
  struct BenchmarkData *bd;

  if (NULL == url)
  {
    /* Should not happen unless curl barfs */
    GNUNET_break (0);
    url = "<empty>";
  }

  memcpy (trunc, url, MAX_BENCHMARK_URL_LEN);
  trunc[MAX_BENCHMARK_URL_LEN - 1] = 0;

  /* We're not interested in what's after the query string */
  for (size_t i = 0; i < strlen (trunc); i++)
  {
    if (trunc[i] == '?')
    {
      trunc[i] = 0;
      break;
    }
  }

  bd = get_benchmark_data ();

  GNUNET_assert (bd->urd_len <= bd->urd_capacity);

  for (unsigned int i = 0; i < bd->urd_len; i++)
  {
    if ( (0 == strcmp (trunc, bd->urd[i].request_url)) &&
         (bd->urd[i].status == status) )
      return &bd->urd[i];
  }

  {
    struct UrlRequestData urd = { 0 };

    memcpy (&urd.request_url, trunc, MAX_BENCHMARK_URL_LEN);
    urd.status = status;

    if (bd->urd_len == bd->urd_capacity)
    {
      bd->urd_capacity = 2 * (bd->urd_capacity + 1);
      bd->urd = GNUNET_realloc (bd->urd, bd->urd_capacity * sizeof (struct UrlRequestData));
    }

    bd->urd[bd->urd_len++] = urd;
    return &bd->urd[bd->urd_len - 1];
  }
}
