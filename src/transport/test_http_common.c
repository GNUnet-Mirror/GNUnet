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
 * @file transport/test_transport_api.c
 * @brief base test case for transport implementations
 *
 * This test case serves as a base for tcp, udp, and udp-nat
 * transport test cases.  Based on the executable being run
 * the correct test case will be performed.  Conservation of
 * C code apparently.
 */
#include "platform.h"
#include "gnunet_transport_service.h"
#include "transport-testing.h"
#include "plugin_transport_http_common.h"

struct SplittedHTTPAddress
{
	char *protocoll;
	char *host;
	char *port;
	char *path;
};

void
clean (struct SplittedHTTPAddress *addr)
{
	if (NULL != addr)
	{
		GNUNET_free_non_null (addr->host);
		GNUNET_free_non_null (addr->path);
		GNUNET_free_non_null (addr->port);
		GNUNET_free_non_null (addr->protocoll);
		GNUNET_free_non_null (addr);
	}
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  clean(http_split_address (""));
  clean(http_split_address ("http://"));
  clean(http_split_address ("http://test/path"));
  clean(http_split_address ("http://test:8999/path"));
  clean(http_split_address ("http://1.2.3.4:8999/path"));
  clean(http_split_address ("http://1.2.3.4:8999"));

  return ret;
}

/* end of test_transport_api.c */
