/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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

/**
 * @file arm/gnunet_service_arm_.h
 * @brief function prototypes for gnunet_service_arm.c, and gnunet_service_manager.c
 * @author Safey Abdel Halim
 */

#ifndef GNUNET_SERVICE_ARM__H
#define GNUNET_SERVICE_ARM__H

void start_service (struct GNUNET_SERVER_Client *client,
		    const char *servicename);

void stop_listening (const char *serviceName);

void prepareServices (const struct GNUNET_CONFIGURATION_Handle
		      *configurationHandle,
		      struct GNUNET_SCHEDULER_Handle *sched);

#endif
