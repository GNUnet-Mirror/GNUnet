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
  char *s;

  GNUNET_asprintf (&s, "gnunet-benchmark-%llu-%llu.txt",
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

  GNUNET_asprintf (&s, "eddsa_sign_count %llu",
                   (unsigned long long) bd->eddsa_sign_count);
  GNUNET_assert (GNUNET_SYSERR != GNUNET_DISK_file_write_blocking (fh, s, strlen (s)));
  GNUNET_free (s);

  GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fh));

  GNUNET_asprintf (&s, "gnunet-benchmark-urls-%llu-%llu.txt",
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
    GNUNET_asprintf (&s, "url %s count %lld time_us %lld\n",
                     urd->request_url,
                     (unsigned long long) urd->count,
                     (unsigned long long) urd->time.rel_value_us);
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
}


/**
 * Initialize the thread-local variable key for benchmark data.
 */
static void
make_key()
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
 * @param url url to get request data for
 */
struct UrlRequestData *
get_url_benchmark_data (char *url)
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

  bd = get_benchmark_data ();

  GNUNET_assert (bd->urd_len <= brd->urd_capacity);

  for (unsigned int i = 0; i < bd->urd_len; i++)
  {
    if (0 == strcmp (trunc, bd->urd[i].request_url))
      return &bd->urd[i];
  }

  {
    struct UrlRequestData urd = { 0 };

    memcpy (&urd.request_url, trunc, MAX_BENCHMARK_URL_LEN);

    if (bd->urd_len == bd->urd_capacity)
    {
      bd->urd_capacity = 2 * (bd->urd_capacity + 1);
      bd->urd = GNUNET_realloc (bd->urd, bd->urd_capacity * sizeof (struct UrlRequestData));
    }

    bd->urd[bd->urd_len++] = urd;
    return &bd->urd[bd->urd_len - 1];
  }
}
