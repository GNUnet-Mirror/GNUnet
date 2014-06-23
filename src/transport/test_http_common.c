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
/**
 * @file transport/test_http_common.c
 * @brief base test case for common http functionality
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"
#include "plugin_transport_http_common.h"


static void
clean (struct SplittedHTTPAddress *addr)
{
  if (NULL == addr)
    return;
  GNUNET_free_non_null (addr->host);
  GNUNET_free_non_null (addr->path);
  GNUNET_free_non_null (addr->protocol);
  GNUNET_free (addr);
}


static int
check (struct SplittedHTTPAddress *addr,
       const char *protocol,
       const char *host,
       int port,
       const char *path)
{
  if (NULL == addr)
    return GNUNET_NO;
  if (((NULL == addr->protocol) && (NULL != protocol)) ||
      ((NULL != addr->protocol) && (NULL == protocol)))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  else if ((NULL != addr->protocol) && (NULL != protocol))
  {
    if (0 != strcmp(addr->protocol, protocol))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  }

  if (((NULL == addr->host) && (NULL != host)) ||
      ((NULL != addr->host) && (NULL == host)))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  else if ((NULL != addr->host) && (NULL != host))
  {
    if (0 != strcmp(addr->host, host))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  }

  if (((NULL == addr->path) && (NULL != path)) ||
      ((NULL != addr->path) && (NULL == path)))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  else if ((NULL != addr->path) && (NULL != path))
  {
    if (0 != strcmp(addr->path, path))
    {
      GNUNET_break (0);
      return GNUNET_NO;
    }
  }

  if ((addr->port != port))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


static int
check_pass (const char *src,
            const char *protocol,
            const char *host,
            int port,
            const char *path)
{
  struct SplittedHTTPAddress *spa;

  spa = http_split_address (src);
  if (NULL == spa)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != check(spa, protocol, host, port, path))
  {
    clean (spa);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  clean (spa);
  return GNUNET_OK;
}


static int
check_fail (const char *src)
{
  struct SplittedHTTPAddress * spa;

  spa = http_split_address (src);
  if (NULL != spa)
  {
    GNUNET_break (0);
    clean (spa);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
test_pass_hostname ()
{
  check_pass("http://test.local", "http", "test.local", HTTP_DEFAULT_PORT, "");
  check_pass("http://test.local/", "http", "test.local", HTTP_DEFAULT_PORT, "/");
  check_pass("http://test.local/path", "http", "test.local", HTTP_DEFAULT_PORT, "/path");
  check_pass("http://test.local/path/", "http", "test.local", HTTP_DEFAULT_PORT, "/path/");
  check_pass("http://test.local/path/more", "http", "test.local", HTTP_DEFAULT_PORT, "/path/more");
  check_pass("http://test.local:81", "http", "test.local", 81, "");
  check_pass("http://test.local:81/", "http", "test.local", 81, "/");
  check_pass("http://test.local:81/path", "http", "test.local", 81, "/path");
  check_pass("http://test.local:81/path/", "http", "test.local", 81, "/path/");
  check_pass("http://test.local:81/path/more", "http", "test.local", 81, "/path/more");

}


static void
test_pass_ipv4 ()
{
  check_pass("http://127.0.0.1", "http", "127.0.0.1", HTTP_DEFAULT_PORT, "");
  check_pass("http://127.0.0.1/", "http", "127.0.0.1", HTTP_DEFAULT_PORT, "/");
  check_pass("http://127.0.0.1/path", "http", "127.0.0.1", HTTP_DEFAULT_PORT, "/path");
  check_pass("http://127.0.0.1/path/", "http", "127.0.0.1", HTTP_DEFAULT_PORT, "/path/");
  check_pass("http://127.0.0.1:81", "http", "127.0.0.1", 81, "");
  check_pass("http://127.0.0.1:81/", "http", "127.0.0.1", 81, "/");
  check_pass("http://127.0.0.1:81/path", "http", "127.0.0.1", 81, "/path");
  check_pass("http://127.0.0.1:81/path/", "http", "127.0.0.1", 81, "/path/");
  check_pass("http://127.0.0.1:81/path/more", "http", "127.0.0.1", 81, "/path/more");
}


static void
test_fail_ipv6 ()
{
  check_pass("http://[::1]", "http", "[::1]", HTTP_DEFAULT_PORT, "");
  check_pass("http://[::1]/", "http", "[::1]", HTTP_DEFAULT_PORT, "/");
  check_pass("http://[::1]/path", "http", "[::1]", HTTP_DEFAULT_PORT, "/path");
  check_pass("http://[::1]/path/", "http", "[::1]", HTTP_DEFAULT_PORT, "/path/");
  check_pass("http://[::1]:81", "http", "[::1]", 81, "");
  check_pass("http://[::1]:81/", "http", "[::1]", 81, "/");
  check_pass("http://[::1]:81/path", "http", "[::1]", 81, "/path");
  check_pass("http://[::1]:81/path/", "http", "[::1]", 81, "/path/");
  check_pass("http://[::1]:81/path/more", "http", "[::1]", 81, "/path/more");
}


static void
test_fail ()
{
  if (GNUNET_SYSERR == check_fail (""))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("http"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("://"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("http://"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("//localhost"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("//:80"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("//:80/"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("//:80:"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("http://localhost:a/"))
    GNUNET_break (0);
  if (GNUNET_SYSERR == check_fail ("http://127.0.0.1:a/"))
    GNUNET_break (0);
}


int
main (int argc, char *argv[])
{
  int ret = 0;
  struct SplittedHTTPAddress * spa;

  GNUNET_log_setup ("test", "DEBUG", NULL);
  spa = http_split_address ("");
  if (NULL != spa)
  {
    clean (spa);
    GNUNET_break (0);
  }

  http_split_address ("http://");
  if (NULL != spa)
  {
    clean (spa);
    GNUNET_break (0);
  }

  http_split_address ("://");
  if (NULL != spa)
  {
    clean (spa);
    GNUNET_break (0);
  }

  test_pass_hostname ();
  test_pass_ipv4 ();
  test_fail_ipv6 ();
  test_fail ();

  return ret;
}

/* end of test_http_common.c */
