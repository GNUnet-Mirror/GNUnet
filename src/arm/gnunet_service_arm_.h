/**
 * @file arm/gnunet_service_arm_.h
 * @brief function prototypes for gnunet_service_arm.c, and gnunet_service_manager.c
 * @author Safey Abdel Halim
 */

#ifndef GNUNET_SERVICE_ARM__H
#define GNUNET_SERVICE_ARM__H

void start_service (struct GNUNET_SERVER_Client *client,
		    const char *servicename);
void prepareServices (const struct GNUNET_CONFIGURATION_Handle
		      *configurationHandle,
		      struct GNUNET_SCHEDULER_Handle *sched);

#endif
