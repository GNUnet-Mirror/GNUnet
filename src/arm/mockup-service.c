/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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

#include <stdlib.h>
#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	/* Does nothing */
	int x = 0;
}


int main(int argc, char *const *argv)
{
	int ret;
	
	ret = (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                             argv,
                             "do-nothing", GNUNET_SERVICE_OPTION_NONE,
                             &run, NULL)) ? 0 : 1;
	
	return ret;
}