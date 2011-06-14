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
 * @file arm/gnunet-service-arm_interceptor.c
 * @brief listen to incoming connections from clients to services,
 * start services for which incoming an incoming connection occur,
 * and relay communication between the client and the service for 
 * that first incoming connection.
 *
 * @author Safey Abdel Halim
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_service_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_constants.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet-service-arm.h"


#define DEBUG_SERVICE_MANAGER GNUNET_NO

#define BUFFER_SIZE (64 * 1024)

/**
 * Problem forwarding from client to service.
 */
#define REASON_CLIENT_TO_SERVICE 1

/**
 * Problem forwarding from service to client.
 */
#define REASON_SERVICE_TO_CLIENT 2

/**
 * Problem in both directions.
 */
#define REASON_ERROR 3

struct ForwardedConnection;

/**
 *
 */
struct ServiceListeningInfo
{
  /**
   * This is a linked list.
   */
  struct ServiceListeningInfo *next;

  /**
   * This is a linked list.
   */
  struct ServiceListeningInfo *prev;

  /**
   * Name of the service being forwarded.
   */
  char *serviceName;

  /**
   *
   */
  struct sockaddr *service_addr;

  /**
   *
   */
  socklen_t service_addr_len;

  /**
   * Our listening socket.
   */
  struct GNUNET_NETWORK_Handle *listeningSocket;

  /**
   *
   */
  struct ForwardedConnection *fc;

  /**
   * Task doing the accepting.
   */
  GNUNET_SCHEDULER_TaskIdentifier acceptTask;
};

/**
 * Information of the connection: client-arm-service
 */
struct ForwardedConnection
{
  /**
   *
   */
  struct GNUNET_NETWORK_Handle *armClientSocket;

  /**
   *
   */
  struct GNUNET_NETWORK_Handle *armServiceSocket;

  /**
   *
   */
  struct ServiceListeningInfo *listen_info;

  /**
   *
   */
  char service_to_client_buffer[BUFFER_SIZE];

  /**
   *
   */
  char client_to_service_buffer[BUFFER_SIZE];

  /**
   *
   */
  char client_addr[32];

  /**
   *
   */
  const char *client_to_service_bufferPos;

  /**
   *
   */
  const char *service_to_client_bufferPos;

  /**
   * Timeout for forwarding.
   */
  struct GNUNET_TIME_Absolute timeout;
  
  /**
   * Current back-off value.
   */
  struct GNUNET_TIME_Relative back_off;
  
  /**
   * Task that tries to initiate forwarding.
   */
  GNUNET_SCHEDULER_TaskIdentifier start_task;

  /**
   *
   */
  GNUNET_SCHEDULER_TaskIdentifier client_to_service_task;

  /**
   *
   */
  GNUNET_SCHEDULER_TaskIdentifier service_to_client_task;

  /**
   *
   */
  ssize_t client_to_service_bufferDataLength;

  /**
   *
   */
  ssize_t service_to_client_bufferDataLength;

  /**
   *
   */
  socklen_t client_addr_len;

  /**
   * Have we ever successfully written data to the service?
   */
  int first_write_done;

};

/**
 * Array with the names of the services started by default.
 */
static char **defaultServicesList;

/**
 * Size of the defaultServicesList array.
 */
static unsigned int numDefaultServices;

/**
 *
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 *
 */
static struct ServiceListeningInfo *serviceListeningInfoList_head;

/**
 *
 */
static struct ServiceListeningInfo *serviceListeningInfoList_tail;


/**
 * Put the default services represented by a space separated string into an array of strings
 * 
 * @param services space separated string of default services
 */
static void
addDefaultServicesToList (const char *services)
{
  unsigned int i;
  const char *token;
  char *s;

  if (strlen (services) == 0)
    return;
  s = GNUNET_strdup (services);
  token = strtok (s, " ");
  while (NULL != token)
    {
      numDefaultServices++;
      token = strtok (NULL, " ");
    }
  GNUNET_free (s);

  defaultServicesList = GNUNET_malloc (numDefaultServices * sizeof (char *));
  i = 0;
  s = GNUNET_strdup (services);
  token = strtok (s, " ");
  while (NULL != token)
    {
      defaultServicesList[i++] = GNUNET_strdup (token);
      token = strtok (NULL, " ");
    }
  GNUNET_free (s);
  GNUNET_assert (i == numDefaultServices);
}

/**
 * Checks whether the serviceName is in the list of default services
 * 
 * @param serviceName string to check its existance in the list
 * @return GNUNET_YES if the service is started by default
 */
static int
isInDefaultList (const char *serviceName)
{
  unsigned int i;
  for (i = 0; i < numDefaultServices; i++)
    if (strcmp (serviceName, defaultServicesList[i]) == 0)
      return GNUNET_YES;    
  return GNUNET_NO;
}


/**
 * Close forwarded connection (partial or full).
 *
 * @param fc connection to close 
 * @param reason which direction to close
 */
static void
closeClientAndServiceSockets (struct ForwardedConnection *fc, 
			      int reason)
{
  if (0 != (REASON_SERVICE_TO_CLIENT & reason)) 
    {      
#if DEBUG_SERVICE_MANAGER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Stopping forwarding from service to client\n",
		  fc->listen_info->serviceName);
#endif
      if (fc->service_to_client_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (fc->service_to_client_task);
	  fc->service_to_client_task = GNUNET_SCHEDULER_NO_TASK;
	}
      if (fc->armClientSocket != NULL)
	GNUNET_NETWORK_socket_shutdown (fc->armClientSocket,
					SHUT_WR);
      if (fc->armServiceSocket != NULL)
	GNUNET_NETWORK_socket_shutdown (fc->armServiceSocket,
					SHUT_RD);
    }
  if (0 != (REASON_CLIENT_TO_SERVICE & reason)) 
    {
#if DEBUG_SERVICE_MANAGER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Stopping forwarding from client to service\n",
		  fc->listen_info->serviceName);
#endif
      if (fc->client_to_service_task != GNUNET_SCHEDULER_NO_TASK) 
	{
	  GNUNET_SCHEDULER_cancel (fc->client_to_service_task);
	  fc->client_to_service_task = GNUNET_SCHEDULER_NO_TASK;
	}
      if (fc->armClientSocket != NULL)
	GNUNET_NETWORK_socket_shutdown (fc->armClientSocket,
					SHUT_RD);
      if (fc->armServiceSocket != NULL)
	GNUNET_NETWORK_socket_shutdown (fc->armServiceSocket,
					SHUT_WR);
    }
  if ( (fc->client_to_service_task != GNUNET_SCHEDULER_NO_TASK) ||
       (fc->service_to_client_task != GNUNET_SCHEDULER_NO_TASK) )
    return;
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Closing forwarding connection (done with both directions)\n");
#endif
  if (fc->start_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (fc->start_task);
  if ( (NULL != fc->armClientSocket) &&
       (GNUNET_SYSERR ==
	GNUNET_NETWORK_socket_close (fc->armClientSocket)) )
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "close");
  if ( (NULL != fc->armServiceSocket) &&
       (GNUNET_SYSERR ==
	GNUNET_NETWORK_socket_close (fc->armServiceSocket)) )
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "close");
  GNUNET_free (fc->listen_info->serviceName);		   
  GNUNET_free (fc->listen_info->service_addr);
  GNUNET_free (fc->listen_info);	
  GNUNET_free (fc);
}


/**
 * Read data from the client and then forward it to the service.
 * 
 * @param cls callback data,   struct ForwardedConnection for the communication between client and service
 * @param tc context 
 */
static void
receiveFromClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Receive service messages sent by the service and forward it to client
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc scheduler context
 */
static void
receiveFromService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 *
 */
static void
start_forwarding (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc);



/**
 * Forward messages sent from service to client
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc context
 */
static void
forwardToClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;
  ssize_t numberOfBytesSent;

  fc->service_to_client_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES != GNUNET_NETWORK_fdset_isset (tc->write_ready,
						fc->armClientSocket))
    {
      fc->service_to_client_task = 
	GNUNET_SCHEDULER_add_write_net (
					GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armClientSocket,
					&forwardToClient, fc);
      return;
    }
  /* Forwarding service response to client */
  numberOfBytesSent =
    GNUNET_NETWORK_socket_send (fc->armClientSocket,
				fc->service_to_client_bufferPos,
				fc->service_to_client_bufferDataLength);
  if (numberOfBytesSent <= 0)
    {
      if ( (errno != EPIPE) &&
	   (errno != ECONNRESET) )
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    "Failed to forward %u bytes of data to client: %s\n",
		    fc->service_to_client_bufferDataLength,
		    STRERROR (errno));
      closeClientAndServiceSockets (fc,
				    REASON_SERVICE_TO_CLIENT);
      return;
    }
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarded %d bytes to client\n",
	      numberOfBytesSent);
#endif
  if (numberOfBytesSent < fc->service_to_client_bufferDataLength)
    {
      fc->service_to_client_bufferPos += numberOfBytesSent;
      fc->service_to_client_bufferDataLength -= numberOfBytesSent;
      fc->service_to_client_task = 
	GNUNET_SCHEDULER_add_write_net (
					GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armClientSocket,
					&forwardToClient, 
					fc);
      return;
    }
  fc->service_to_client_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armServiceSocket,
				   &receiveFromService, 
				   fc);
}


/**
 * Receive service messages sent by the service and forward it to client
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc scheduler context
 */
static void
receiveFromService (void *cls, 
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;
  struct GNUNET_TIME_Relative rem;

  fc->service_to_client_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)) &&
       (fc->first_write_done != GNUNET_YES) )
    {
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;
    }
  if (GNUNET_YES != GNUNET_NETWORK_fdset_isset (tc->read_ready,
						fc->armServiceSocket))
    {
      fc->service_to_client_task =
	GNUNET_SCHEDULER_add_read_net (
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       fc->armServiceSocket,
				       &receiveFromService, fc);
      return;
    }
  fc->service_to_client_bufferPos = fc->service_to_client_buffer;
  fc->service_to_client_bufferDataLength =
    GNUNET_NETWORK_socket_recv (fc->armServiceSocket,
				fc->service_to_client_buffer, 
				BUFFER_SIZE);
  if (fc->service_to_client_bufferDataLength <= 0)
    {
#if DEBUG_SERVICE_MANAGER
      if (fc->service_to_client_bufferDataLength == 0)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Service `%s' stopped sending data.\n",
		      fc->listen_info->serviceName);
	}
#endif
      if (fc->first_write_done != GNUNET_YES)
	{
	  fc->service_to_client_bufferDataLength = 0;
	  GNUNET_break (GNUNET_OK ==
			GNUNET_NETWORK_socket_close (fc->armServiceSocket));
	  fc->armServiceSocket = NULL;
	  if ( (fc->client_to_service_bufferDataLength > 0) &&
	       (fc->client_to_service_task != GNUNET_SCHEDULER_NO_TASK) )
	    {
	      GNUNET_SCHEDULER_cancel (fc->client_to_service_task);
	      fc->client_to_service_task = GNUNET_SCHEDULER_NO_TASK;
	    }
	  fc->back_off = GNUNET_TIME_relative_multiply (fc->back_off, 2);
#if DEBUG_SERVICE_MANAGER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Failed to connected to service `%s' at `%s', will try again in %llu ms\n",
		      fc->listen_info->serviceName,
		      GNUNET_a2s (fc->listen_info->service_addr,
				  fc->listen_info->service_addr_len),
		      (unsigned long long) GNUNET_TIME_relative_min (fc->back_off,
								     rem).rel_value);
#endif
	  rem = GNUNET_TIME_absolute_get_remaining (fc->timeout);
	  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == fc->start_task);
	  fc->start_task
	    = GNUNET_SCHEDULER_add_delayed (
					    GNUNET_TIME_relative_min (fc->back_off,
								      rem),
					    &start_forwarding,
					    fc);
	}
      else
	{
#if DEBUG_SERVICE_MANAGER
	  if (fc->service_to_client_bufferDataLength != 0)
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"Error receiving from service: %s\n", 
			STRERROR (errno));
#endif
	  closeClientAndServiceSockets (fc, REASON_SERVICE_TO_CLIENT);
	}
      return;
    }
  fc->first_write_done = GNUNET_YES;
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %d bytes for client\n",
	      fc->service_to_client_bufferDataLength);
#endif
  fc->service_to_client_task = 
    GNUNET_SCHEDULER_add_write_net (
				    GNUNET_TIME_UNIT_FOREVER_REL,
				    fc->armClientSocket,
				    &forwardToClient, fc);
}


/**
 * Forward client message to service
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc scheduler context
 */
static void
forwardToService (void *cls, 
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;
  ssize_t numberOfBytesSent;
  struct GNUNET_TIME_Relative rem;

  fc->client_to_service_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)) &&
       (fc->first_write_done != GNUNET_YES) )
    {
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;
    }
  if (GNUNET_YES != GNUNET_NETWORK_fdset_isset (tc->write_ready,
						fc->armServiceSocket))
    {
      fc->client_to_service_task = 
	GNUNET_SCHEDULER_add_write_net (
					GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armServiceSocket,
					&forwardToService, fc);
      return;
    }
  numberOfBytesSent =
    GNUNET_NETWORK_socket_send (fc->armServiceSocket,
				fc->client_to_service_bufferPos,
				fc->client_to_service_bufferDataLength);
  if (numberOfBytesSent <= 0)
    {
      if (GNUNET_YES != fc->first_write_done)
	{
	  GNUNET_break (GNUNET_OK ==
			GNUNET_NETWORK_socket_close (fc->armServiceSocket));
	  fc->armServiceSocket = NULL;
	  if ( (fc->service_to_client_bufferDataLength == 0) &&
	       (fc->service_to_client_task != GNUNET_SCHEDULER_NO_TASK) )
	    {
	      GNUNET_SCHEDULER_cancel (fc->service_to_client_task);
	      fc->service_to_client_task = GNUNET_SCHEDULER_NO_TASK;
	    }
	  fc->back_off = GNUNET_TIME_relative_multiply (fc->back_off, 2);
#if DEBUG_SERVICE_MANAGER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Failed to connect to service `%s' at `%s', will try again in %llu ms\n",
		      fc->listen_info->serviceName,
		      GNUNET_a2s (fc->listen_info->service_addr,
				  fc->listen_info->service_addr_len),
		      (unsigned long long) GNUNET_TIME_relative_min (fc->back_off,
								     rem).rel_value);
#endif
	  rem = GNUNET_TIME_absolute_get_remaining (fc->timeout);
	  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == fc->start_task);
	  fc->start_task 
	    = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_min (fc->back_off,
								      rem),
					    &start_forwarding,
					    fc);
	}
      else
	{
	  if ( (errno != EPIPE) &&
	       (errno != ECONNRESET) )
	    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			"Failed to forward data to service: %s\n",
			STRERROR (errno));
	  closeClientAndServiceSockets (fc,
					REASON_CLIENT_TO_SERVICE);
	}
      return;
    }
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarded %d bytes to service\n",
	      numberOfBytesSent);
#endif
  fc->first_write_done = GNUNET_YES;
  if (numberOfBytesSent < fc->client_to_service_bufferDataLength)
    {
      fc->client_to_service_bufferPos += numberOfBytesSent;
      fc->client_to_service_bufferDataLength -= numberOfBytesSent;
      fc->client_to_service_task = 
	GNUNET_SCHEDULER_add_write_net (
					GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armServiceSocket,
					&forwardToService, fc);
      return;
    }
  fc->client_to_service_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armClientSocket,
				   &receiveFromClient, fc);
}


/**
 * Read data from the client and then forward it to the service.
 * 
 * @param cls callback data,   struct ForwardedConnection for the communication between client and service
 * @param tc context 
 */
static void
receiveFromClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;

  fc->client_to_service_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES != GNUNET_NETWORK_fdset_isset (tc->read_ready,
						fc->armClientSocket))
    {
      fc->client_to_service_task =
	GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				       fc->armClientSocket,
				       &receiveFromClient, fc);
      return;
    }
  fc->client_to_service_bufferPos = fc->client_to_service_buffer;
  fc->client_to_service_bufferDataLength =
    GNUNET_NETWORK_socket_recv (fc->armClientSocket,
				fc->client_to_service_buffer, 
				BUFFER_SIZE);
  if (fc->client_to_service_bufferDataLength <= 0)
    {
      if (fc->client_to_service_bufferDataLength == 0)
	{
#if DEBUG_SERVICE_MANAGER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Client closed connection with service `%s'\n",
		      fc->listen_info->serviceName);
#endif
	}
      else
	{
#if DEBUG_SERVICE_MANAGER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Error receiving from client: %s\n",
		      STRERROR (errno));
#endif
	}
      closeClientAndServiceSockets (fc, REASON_CLIENT_TO_SERVICE);
      return;
    }
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %d bytes for service\n",
	      fc->client_to_service_bufferDataLength);
#endif
  if (fc->armServiceSocket != NULL)        
    fc->client_to_service_task = 
      GNUNET_SCHEDULER_add_write_net (
				      GNUNET_TIME_UNIT_FOREVER_REL,
				      fc->armServiceSocket,
				      &forwardToService, fc);
}


static void
fc_acceptConnection (void *cls, 
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceListeningInfo *sli = cls;
  struct ForwardedConnection *fc = sli->fc;

  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY))
    {
      GNUNET_assert (GNUNET_OK == GNUNET_NETWORK_socket_close (sli->listeningSocket));
      closeClientAndServiceSockets (fc, REASON_ERROR);
      GNUNET_free (sli);
      return;
    }
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connected to service, now starting forwarding\n");
#endif
  fc->armServiceSocket = sli->listeningSocket;
  GNUNET_free (fc->listen_info->service_addr);
  fc->listen_info->service_addr = sli->service_addr;
  fc->listen_info->service_addr_len = sli->service_addr_len;
  if (fc->client_to_service_task == GNUNET_SCHEDULER_NO_TASK)
    {
      if (fc->client_to_service_bufferDataLength == 0) 
	fc->client_to_service_task =
	  GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					 fc->armClientSocket,
					 &receiveFromClient, fc);
      else
	fc->client_to_service_task = 
	  GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
					  fc->armServiceSocket,
					  &forwardToService, fc);
    }
  if (fc->service_to_client_task == GNUNET_SCHEDULER_NO_TASK)
    {
      if (fc->service_to_client_bufferDataLength == 0) 
	fc->service_to_client_task =
	  GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					 fc->armServiceSocket,
					 &receiveFromService, fc);
      else
	fc->service_to_client_task = 
	  GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
					  fc->armClientSocket,
					  &forwardToClient, fc);
    }
  GNUNET_free (sli);
}


static struct ServiceListeningInfo *
service_try_to_connect (const struct sockaddr *addr, 
			int pf,
			socklen_t addrlen, 
			struct ForwardedConnection *fc)
{
  struct GNUNET_NETWORK_Handle *sock;
  struct ServiceListeningInfo *serviceListeningInfo;

  sock = GNUNET_NETWORK_socket_create (pf, SOCK_STREAM, 0);
  if (sock == NULL)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
      return NULL;
    }  
  if ( (GNUNET_SYSERR == GNUNET_NETWORK_socket_connect (sock, addr, addrlen)) &&
       (errno != EINPROGRESS) )
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "connect");
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      return NULL;
    }  
  serviceListeningInfo = GNUNET_malloc (sizeof (struct ServiceListeningInfo));
  serviceListeningInfo->serviceName = NULL;
  serviceListeningInfo->service_addr = GNUNET_malloc (addrlen);
  memcpy (serviceListeningInfo->service_addr,
	  addr,
	  addrlen);
  serviceListeningInfo->service_addr_len = addrlen;
  serviceListeningInfo->listeningSocket = sock;
  serviceListeningInfo->fc = fc;
  serviceListeningInfo->acceptTask =
    GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
				    serviceListeningInfo->listeningSocket,
				    &fc_acceptConnection, serviceListeningInfo);
  return serviceListeningInfo;
}


/**
 *
 */
static void
start_forwarding (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;
  struct ServiceListeningInfo *sc;
  struct sockaddr_in target_ipv4;
  struct sockaddr_in6 target_ipv6;
  const struct sockaddr_in *v4;
  const struct sockaddr_in6 *v6;
  char listen_address[INET6_ADDRSTRLEN];

  fc->start_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (NULL != tc) &&
       (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Unable to forward to service `%s': shutdown\n"),
		  fc->listen_info->serviceName);
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;
    }
  if (0 == GNUNET_TIME_absolute_get_remaining (fc->timeout).rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to forward to service `%s': timeout before connect\n"),
		  fc->listen_info->serviceName);
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;
    }
  switch (fc->listen_info->service_addr->sa_family)
    {
    case AF_UNSPEC:
      GNUNET_break (0);
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;      
    case AF_INET:
      v4 = (const struct sockaddr_in *) fc->listen_info->service_addr;
      inet_ntop (fc->listen_info->service_addr->sa_family, 
		 (const void *) &v4->sin_addr, 
		 listen_address,
		 INET_ADDRSTRLEN);
      if (0 == strncmp (listen_address, "0.0.0.0", 7))
	{
	  /* connect to [::1] and 127.0.0.1 instead of [::] and 0.0.0.0 */
	  memset (&target_ipv4, 0, sizeof (target_ipv4));
	  inet_pton (AF_INET, "127.0.0.1", &target_ipv4.sin_addr);
	  target_ipv4.sin_family = AF_INET;
	  target_ipv4.sin_port = v4->sin_port;
	  v4 = &target_ipv4;
	}
      sc = service_try_to_connect ((const struct sockaddr*) v4,
				   PF_INET,
				   sizeof (struct sockaddr_in), 
				   fc);
      break;
    case AF_INET6:
      v6 = (struct sockaddr_in6 *)fc->listen_info->service_addr;
      inet_ntop (fc->listen_info->service_addr->sa_family, 
		 (const void *) &v6->sin6_addr, 
		 listen_address, 
		 INET6_ADDRSTRLEN);
      if ( (strncmp (listen_address, "[::]:", 5) == 0) || (strncmp (listen_address, "::", 2) == 0) )
	{
	  memset (&target_ipv6, 0, sizeof (target_ipv6));
	  target_ipv6.sin6_addr = in6addr_loopback;
	  target_ipv6.sin6_family = AF_INET6;
	  target_ipv6.sin6_port = v6->sin6_port;
	  v6 = &target_ipv6;
	}
      sc = service_try_to_connect ((const struct sockaddr*) v6,
				   PF_INET6,
				   sizeof (struct sockaddr_in6), 
				   fc);
      break;
    case AF_UNIX:
      sc = service_try_to_connect (fc->listen_info->service_addr,
				   PF_UNIX,
				   fc->listen_info->service_addr_len,
				   fc);
      break;
    default:
      GNUNET_break (0);
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;
    }  
  if (NULL == sc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _ ("Unable to start service `%s': %s\n"),
		  fc->listen_info->serviceName,
		  STRERROR (errno));
      closeClientAndServiceSockets (fc, REASON_ERROR);
      return;
    }
}


/**
 *
 */
int
stop_listening (const char *serviceName)
{
  struct ServiceListeningInfo *pos;
  struct ServiceListeningInfo *next;
  int ret;
  
  ret = GNUNET_NO;
  next = serviceListeningInfoList_head;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if ( (serviceName != NULL) &&
	   (strcmp (pos->serviceName, serviceName) != 0) )
	continue;
      if (pos->acceptTask != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (pos->acceptTask);
      GNUNET_break (GNUNET_OK ==
		    GNUNET_NETWORK_socket_close (pos->listeningSocket));
      GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
				   serviceListeningInfoList_tail, 
				   pos);
      GNUNET_free (pos->serviceName);		   
      GNUNET_free (pos->service_addr);
      GNUNET_free (pos); 
      ret = GNUNET_OK;
    }
  return ret;
}

/**
 * First connection has come to the listening socket associated with the service,
 * create the service in order to relay the incoming connection to it
 * 
 * @param cls callback data, struct ServiceListeningInfo describing a listen socket
 * @param tc context 
 */
static void
acceptConnection (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
accept_and_forward (struct ServiceListeningInfo *serviceListeningInfo)
{
  struct ForwardedConnection *fc;

  fc = GNUNET_malloc (sizeof (struct ForwardedConnection));
  fc->listen_info = serviceListeningInfo;
  fc->service_to_client_bufferPos = fc->service_to_client_buffer;
  fc->client_to_service_bufferPos = fc->client_to_service_buffer;
  fc->client_addr_len = sizeof (fc->client_addr);
  fc->armClientSocket = GNUNET_NETWORK_socket_accept (serviceListeningInfo->listeningSocket,
						      (struct sockaddr*) fc->client_addr,
						      &fc->client_addr_len);
  if (NULL == fc->armClientSocket)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to accept connection for service `%s': %s\n"),
		  serviceListeningInfo->serviceName,
		  STRERROR (errno));
      GNUNET_free (fc);
      GNUNET_CONTAINER_DLL_insert (serviceListeningInfoList_head,
				   serviceListeningInfoList_tail, 
				   serviceListeningInfo); 
      serviceListeningInfo->acceptTask =
	GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, 
				       serviceListeningInfo->listeningSocket,
				       &acceptConnection,
				       serviceListeningInfo);
      return;
    }
  GNUNET_break (GNUNET_OK ==
		GNUNET_NETWORK_socket_close (serviceListeningInfo->listeningSocket));
  start_service (NULL, serviceListeningInfo->serviceName, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("Service `%s' started\n"),
	      fc->listen_info->serviceName);
  fc->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_SERVICE_TIMEOUT);
  fc->back_off = GNUNET_TIME_UNIT_MILLISECONDS;
  fc->client_to_service_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armClientSocket,
				   &receiveFromClient, fc);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == fc->start_task);
  fc->start_task 
    = GNUNET_SCHEDULER_add_now (&start_forwarding,
				fc);
}


/**
 * First connection has come to the listening socket associated with the service,
 * create the service in order to relay the incoming connection to it
 * 
 * @param cls callback data, struct ServiceListeningInfo describing a listen socket
 * @param tc context 
 */
static void
acceptConnection (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceListeningInfo *sli = cls;
  struct ServiceListeningInfo *pos;
  struct ServiceListeningInfo *next;
  int *lsocks;
  unsigned int ls;
  int use_lsocks;

  sli->acceptTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
			       serviceListeningInfoList_tail, 
			       sli);  
#ifndef MINGW
  use_lsocks = GNUNET_NO;
  if (GNUNET_YES == GNUNET_CONFIGURATION_have_value (cfg,
						     sli->serviceName,
						     "DISABLE_SOCKET_FORWARDING"))
    use_lsocks = GNUNET_CONFIGURATION_get_value_yesno (cfg,
						       sli->serviceName,
						       "DISABLE_SOCKET_FORWARDING");
#else
  use_lsocks = GNUNET_YES;
#endif
  if (GNUNET_NO != use_lsocks)
    {
      accept_and_forward (sli);
      return;
    }
  lsocks = NULL;
  ls = 0;
  next = serviceListeningInfoList_head;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if (0 == strcmp (pos->serviceName,
		       sli->serviceName))
	{
	  GNUNET_array_append (lsocks, ls, 
			       GNUNET_NETWORK_get_fd (pos->listeningSocket));	  
	  GNUNET_free (pos->listeningSocket); /* deliberately no closing! */
	  GNUNET_free (pos->service_addr);
	  GNUNET_free (pos->serviceName);
	  GNUNET_SCHEDULER_cancel (pos->acceptTask);
	  GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
				       serviceListeningInfoList_tail, 
				       pos);
	  GNUNET_free (pos);
	}
    }
  GNUNET_array_append (lsocks, ls, 
		       GNUNET_NETWORK_get_fd (sli->listeningSocket));
  GNUNET_free (sli->listeningSocket); /* deliberately no closing! */
  GNUNET_free (sli->service_addr);
  GNUNET_array_append (lsocks, ls, -1);
  start_service (NULL, 
		 sli->serviceName,
		 lsocks);
  ls = 0;
  while (lsocks[ls] != -1)
    GNUNET_break (0 == close (lsocks[ls++]));      
  GNUNET_array_grow (lsocks, ls, 0);
  GNUNET_free (sli->serviceName);
  GNUNET_free (sli); 
}


/**
 * Creating a listening socket for each of the service's addresses and
 * wait for the first incoming connection to it
 * 
 * @param sa address associated with the service
 * @param addr_len length of sa
 * @param serviceName the name of the service in question
 */
static void
createListeningSocket(struct sockaddr *sa, socklen_t addr_len,
                      const char *serviceName)
{
  const static int on = 1;
  struct GNUNET_NETWORK_Handle *sock;
  struct ServiceListeningInfo *serviceListeningInfo;

  switch (sa->sa_family)
    {
    case AF_INET:
      sock = GNUNET_NETWORK_socket_create (PF_INET, SOCK_STREAM, 0);
      break;
    case AF_INET6:
      sock = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
      break;
    case AF_UNIX:
      if (strcmp(GNUNET_a2s (sa, addr_len), "@") == 0) /* Do not bind to blank UNIX path! */
        return;
      sock = GNUNET_NETWORK_socket_create (PF_UNIX, SOCK_STREAM, 0);
      break;
    default:
      GNUNET_break (0);
      sock = NULL;
      errno = EAFNOSUPPORT;
      break;
    }
  if (NULL == sock)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to create socket for service `%s': %s\n"),
		  serviceName,
		  STRERROR (errno));
      GNUNET_free (sa);
      return;
    }
  if (GNUNET_NETWORK_socket_setsockopt
      (sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "setsockopt");
#ifdef IPV6_V6ONLY
  if ( (sa->sa_family == AF_INET6) &&
       (GNUNET_NETWORK_socket_setsockopt
	(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof (on)) != GNUNET_OK))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
			 "setsockopt");
#endif

  if (GNUNET_NETWORK_socket_bind
      (sock, (const struct sockaddr *) sa, addr_len) != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Unable to bind listening socket for service `%s' to address `%s': %s\n"),
		  serviceName,
		  GNUNET_a2s (sa, addr_len),
		  STRERROR (errno));
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      GNUNET_free (sa);
      return;
    }
  if (GNUNET_NETWORK_socket_listen (sock, 5) != GNUNET_OK)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
			   "listen");
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      GNUNET_free (sa);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("ARM now monitors connections to service `%s' at `%s'\n"),
	      serviceName,
	      GNUNET_a2s (sa, addr_len));
  serviceListeningInfo = GNUNET_malloc (sizeof (struct ServiceListeningInfo));
  serviceListeningInfo->serviceName = GNUNET_strdup (serviceName);
  serviceListeningInfo->service_addr = sa;
  serviceListeningInfo->service_addr_len = addr_len;
  serviceListeningInfo->listeningSocket = sock;
  serviceListeningInfo->acceptTask =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
				   &acceptConnection,
				   serviceListeningInfo);
  GNUNET_CONTAINER_DLL_insert (serviceListeningInfoList_head,
			       serviceListeningInfoList_tail,
			       serviceListeningInfo);
}


/**
 * Callback function, checks whether the current tokens are representing a service,
 * gets its addresses and create listening socket for it.
 * 
 * @param cls callback data, not used
 * @param section configuration section
 * @param option configuration option
 * @param value the option's value
 */
static void
checkPortNumberCB (void *cls,
		   const char *section, 
		   const char *option, 
		   const char *value)
{
  struct sockaddr **addrs;
  socklen_t *addr_lens;
  int ret;
  unsigned int i;
  
  if ( (strcasecmp (section, "arm") == 0) ||
       (strcasecmp (option, "AUTOSTART") != 0) ||
       (strcasecmp (value, "YES") != 0) ||
       (isInDefaultList (section) == GNUNET_YES) )
    return;
  if (0 >= (ret = GNUNET_SERVICE_get_server_addresses (section, cfg, &addrs,
						       &addr_lens)))
    return;
  /* this will free (or capture) addrs[i] */
  for (i = 0; i < ret; i++)
    createListeningSocket (addrs[i], addr_lens[i], section);
  GNUNET_free (addrs);
  GNUNET_free (addr_lens);
}


/**
 * Entry point to the Service Manager
 *
 * @param configurationHandle configuration to use to get services
 */
void
prepareServices (const struct GNUNET_CONFIGURATION_Handle
		 *configurationHandle)
{
  char *defaultServicesString;

  cfg = configurationHandle;
  /* Split the default services into a list */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "arm", "DEFAULTSERVICES",
					     &defaultServicesString))
    {
      addDefaultServicesToList (defaultServicesString);
      GNUNET_free (defaultServicesString);    
    }
  /* Spot the services from the configuration and create a listening
     socket for each */
  GNUNET_CONFIGURATION_iterate (cfg, &checkPortNumberCB, NULL);
}

/* end of gnunet-service-arm_interceptor.c */
