/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file arm/gnunet-service-manager.c
 * @brief listen to incoming connections from clients to services,
 * start services for which incoming an incoming connection occur,
 * and relay communication between the client and the service for 
 * that first incoming connection.
 * @author Safey Abdel Halim
 */

#include "platform.h"
#include "gnunet_service_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_service_arm_.h"


#define DEBUG_SERVICE_MANAGER GNUNET_NO
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define BUFFER_SIZE (63 * 1024)
#define REASON_CLIENT 1
#define REASON_SERVICE 2

static char **defaultServicesList;
static int numDefaultServices = 0;
static const struct GNUNET_CONFIGURATION_Handle *cfg;
static struct GNUNET_SCHEDULER_Handle *scheduler;

struct StartedService
{
  const char *serviceName;
  struct StartedService *next;
};

static struct StartedService *startedServices = NULL;


/* Functions prototypes */
static void
receiveFromClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);
static void
receiveFromService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


struct ServiceListeningInfo
{
  struct ServiceListeningInfo *next;
  struct ServiceListeningInfo *prev;
  const char *serviceName;
  struct sockaddr *service_addr;
  socklen_t service_addr_len;
  struct sockaddr client_addr;
  socklen_t client_addr_len;
  struct GNUNET_NETWORK_Handle *listeningSocket;
  GNUNET_SCHEDULER_TaskIdentifier acceptTask;
};

static struct ServiceListeningInfo *serviceListeningInfoList_head;
static struct ServiceListeningInfo *serviceListeningInfoList_tail;

/**
 * Information of the connection: client-arm-service
 */
struct ServiceInfo
{
  const char *serviceName;
  struct GNUNET_NETWORK_Handle *armClientSocket;
  struct GNUNET_NETWORK_Handle *armServiceSocket;
  struct sockaddr *service_addr;
  socklen_t service_addr_len;
  char clientBuffer[BUFFER_SIZE];
  ssize_t clientBufferDataLength;
  char *clientBufferPos;
  char serviceBuffer[BUFFER_SIZE];
  ssize_t serviceBufferDataLength;
  char *serviceBufferPos;
  GNUNET_SCHEDULER_TaskIdentifier clientReceivingTask;
  GNUNET_SCHEDULER_TaskIdentifier serviceReceivingTask;
  GNUNET_SCHEDULER_TaskIdentifier acceptTask;
};


static struct ServiceInfo *
newServiceInfo (const char *serviceName, struct sockaddr *service_addr,
		socklen_t service_addr_len)
{
  struct ServiceInfo *serviceInfo =
    GNUNET_malloc (sizeof (struct ServiceInfo));
  serviceInfo->serviceName = serviceName;
  serviceInfo->service_addr = service_addr;
  serviceInfo->service_addr_len = service_addr_len;
  serviceInfo->serviceBufferPos = serviceInfo->serviceBuffer;
  serviceInfo->clientBufferPos = serviceInfo->clientBuffer;
  return serviceInfo;
}


static struct ServiceListeningInfo *
newServiceListeningInfo (const char *serviceName,
			 struct sockaddr *sa, socklen_t service_addr_len,
			 struct GNUNET_NETWORK_Handle *listeningSocket)
{
  struct ServiceListeningInfo *serviceListeningInfo =
    GNUNET_malloc (sizeof (struct ServiceListeningInfo));

  serviceListeningInfo->client_addr_len =
    sizeof (serviceListeningInfo->client_addr);
  serviceListeningInfo->serviceName = serviceName;
  serviceListeningInfo->service_addr = sa;
  serviceListeningInfo->service_addr_len = service_addr_len;
  serviceListeningInfo->listeningSocket = listeningSocket;
  GNUNET_CONTAINER_DLL_insert (serviceListeningInfoList_head,
			       serviceListeningInfoList_tail,
			       serviceListeningInfo);
  return serviceListeningInfo;
}


#if DEBUG_SERVICE_MANAGER
static void
printDefaultServicesList ()
{
  int i;
  for (i = 0; i < numDefaultServices; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Service: %s\n",
		defaultServicesList[i]);
}
#endif


/**
 * Put the default services represented by a space separated string into an array of strings
 * 
 * @param services space separated string of default services
 */
static void
addDefaultServicesToList (char *services)
{
  int i = 0;
  char *token;

  /* How many services are there */
  while (services[i] != '\0')
    {
      if (services[i] == ' ')
	{
	  numDefaultServices++;
	}
      i++;
    }
  numDefaultServices++;
  defaultServicesList = GNUNET_malloc (numDefaultServices * sizeof (char *));
  token = strtok ((char *) services, " ");

  i = 0;
  while (NULL != token)
    {
      defaultServicesList[i++] = token;
      token = strtok (NULL, " ");
    }
}

/**
 * Checks whether the serviceName is in the list of default services
 * 
 * @param serviceName string to check its existance in the list
 */
static int
isInDefaultList (const char *serviceName)
{
  int i;
  for (i = 0; i < numDefaultServices; i++)
    {
      if (strcmp (serviceName, defaultServicesList[i]) == 0)
	return GNUNET_YES;
    }
  return GNUNET_NO;
}


static int
isServiceAlreadyStarted (const char *serviceName)
{
  struct StartedService *service;
  service = startedServices;
  while (NULL != service)
    {
      if (strcmp (service->serviceName, serviceName) == 0)
	return GNUNET_OK;
      service = service->next;
    }
  return GNUNET_NO;
}


static void
setStartedService (const char *serviceName)
{
  if (startedServices == NULL)
    {
      startedServices = GNUNET_malloc (sizeof (struct StartedService));
      startedServices->serviceName = GNUNET_strdup (serviceName);
      startedServices->next = NULL;
    }
  else
    {
      struct StartedService *service =
	GNUNET_malloc (sizeof (struct StartedService));
      service->serviceName = GNUNET_strdup (serviceName);
      service->next = startedServices;
      startedServices = service;
    }
}


static void
closeClientAndServiceSockets (struct ServiceInfo *serviceInfo, int reason)
{
  if (NULL != serviceInfo->armClientSocket)
    {
      if (0 != (REASON_SERVICE & reason))
	GNUNET_SCHEDULER_cancel (scheduler, serviceInfo->clientReceivingTask);
      if (GNUNET_SYSERR ==
	  GNUNET_NETWORK_socket_close (serviceInfo->armClientSocket))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "close");
      serviceInfo->armClientSocket = NULL;
    }
  if (NULL != serviceInfo->armServiceSocket)
    {
      if (0 != (REASON_CLIENT & reason))
	GNUNET_SCHEDULER_cancel (scheduler,
				 serviceInfo->serviceReceivingTask);

      if (GNUNET_SYSERR ==
	  GNUNET_NETWORK_socket_close (serviceInfo->armServiceSocket))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "close");
      serviceInfo->armServiceSocket = NULL;
    }

  GNUNET_free (serviceInfo);
}


/**
 * Forward messages sent from service to client
 * 
 * @param cls callback data, for the communication between client and service
 * @param tc context
 */
static void
forwardToClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceInfo *serviceInfo = cls;
  ssize_t numberOfBytesSent;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Ignore shutdown signal, reschedule yourself */
      GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				      serviceInfo->armClientSocket,
				      &forwardToClient, serviceInfo);
      return;
    }

  /* Forwarding service response to client */
  numberOfBytesSent =
    GNUNET_NETWORK_socket_send (serviceInfo->armClientSocket,
				serviceInfo->serviceBufferPos,
				serviceInfo->serviceBufferDataLength);
  if ((numberOfBytesSent == GNUNET_SYSERR) || (numberOfBytesSent == 0))
    {
      /* Error occured or connection closed by client */
      closeClientAndServiceSockets (serviceInfo,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  else if (numberOfBytesSent < serviceInfo->serviceBufferDataLength)
    {
      /* Not all service data were sent to client */
      serviceInfo->serviceBufferPos += numberOfBytesSent;
      serviceInfo->serviceBufferDataLength =
	serviceInfo->serviceBufferDataLength - numberOfBytesSent;

      /* Scheduling writing again for completing the remaining data to be sent */
      GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				      serviceInfo->armClientSocket,
				      &forwardToClient, serviceInfo);
    }
  else
    {
      /* Data completely sent */
      serviceInfo->serviceBufferPos = serviceInfo->serviceBuffer;
    }

  /* Now we are ready to receive more data, rescheduling receiving from Service */
  serviceInfo->serviceReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				   serviceInfo->armServiceSocket,
				   &receiveFromService, serviceInfo);
}


/**
 * Receive service messages sent by the service and forward it to client
 * 
 * @param cls callback data, serviceInfo struct for the communication between client and service
 * @param tc context
 */
static void
receiveFromService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  struct ServiceInfo *serviceInfo = cls;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Neglect shutdown signal, reschedule yourself */
      serviceInfo->serviceReceivingTask =
	GNUNET_SCHEDULER_add_read_net (scheduler,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       serviceInfo->armServiceSocket,
				       &receiveFromService, serviceInfo);
      return;
    }

  serviceInfo->serviceBufferDataLength =
    GNUNET_NETWORK_socket_recv (serviceInfo->armServiceSocket,
				serviceInfo->serviceBuffer, BUFFER_SIZE);

  if (serviceInfo->serviceBufferDataLength <= 0)
    {
      /* The service has closed the connection or an error occured */
      if (serviceInfo->serviceBufferDataLength == 0)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    _("Service `%s' closed connection! \n"),
		    serviceInfo->serviceName);
      else
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Error receiving from service:%d\n"), errno);
	}
      closeClientAndServiceSockets (serviceInfo, REASON_SERVICE);
      return;
    }

  /* Forwarding Service data to Client */
  GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				  serviceInfo->armClientSocket,
				  &forwardToClient, serviceInfo);
}


/**
 * Forward client message to service
 * 
 * @param cls callback data, serviceInfo struct for the communication between client and service
 * @param tc context
 */
static void
forwardToService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceInfo *serviceInfo = cls;
  ssize_t numberOfBytesSent;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Neglect shutdown signal, reschedule yourself */
      GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				      serviceInfo->armServiceSocket,
				      &forwardToService, serviceInfo);
      return;
    }


  /* Forwarding client's message to service */
  numberOfBytesSent =
    GNUNET_NETWORK_socket_send (serviceInfo->armServiceSocket,
				serviceInfo->clientBufferPos,
				serviceInfo->clientBufferDataLength);
  if ((numberOfBytesSent == GNUNET_SYSERR) || (numberOfBytesSent == 0))
    {
      /* Error occured or connection closed by service */
      closeClientAndServiceSockets (serviceInfo,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  else if (numberOfBytesSent < serviceInfo->clientBufferDataLength)
    {
      /* Not all client data were sent to the service */
      serviceInfo->clientBufferPos += numberOfBytesSent;
      serviceInfo->clientBufferDataLength =
	serviceInfo->clientBufferDataLength - numberOfBytesSent;

      /* Scheduling writing again for completing the remaining data to be sent */
      GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				      serviceInfo->armServiceSocket,
				      &forwardToService, serviceInfo);
    }
  else
    {
      /* Data completely sent */
      serviceInfo->clientBufferPos = serviceInfo->clientBuffer;
    }

  /* Now, we are ready to receive more data. Rescheduling the receiving from client */
  serviceInfo->clientReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				   serviceInfo->armClientSocket,
				   &receiveFromClient, serviceInfo);
}



/**
 * Message sent from client to service (faked by ARM, since it's the first connection),
 * ARM will receive the message and forward it to the running service
 * 
 * @param cls callback data, serviceInfo struct for the communication between client and service
 * @param tc context 
 */
static void
receiveFromClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceInfo *serviceInfo = cls;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Neglect the shutdown signal, schedule yourself */
      serviceInfo->clientReceivingTask =
	GNUNET_SCHEDULER_add_read_net (scheduler,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       serviceInfo->armClientSocket,
				       &receiveFromClient, serviceInfo);
      return;
    }

  /* Receive client's message */
  serviceInfo->clientBufferDataLength =
    GNUNET_NETWORK_socket_recv (serviceInfo->armClientSocket,
				serviceInfo->clientBuffer, BUFFER_SIZE);

  if (serviceInfo->clientBufferDataLength <= 0)
    {
      /* The client has closed the connection or and error occured */
      if (serviceInfo->clientBufferDataLength == 0)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    _("Client closed connection with service:`%s'\n"),
		    serviceInfo->serviceName);
      else
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("Error receiving from client!:%d \n"), errno);
      closeClientAndServiceSockets (serviceInfo, REASON_CLIENT);
      return;
    }

  /* Forwarding request to service */
  GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				  serviceInfo->armServiceSocket,
				  &forwardToService, serviceInfo);
}


/**
 * ARM connects to the just created service, 
 * starts the processes for relaying messages between the client and the service
 * 
 * @param cls callback data, serviceInfo struct for the communication between client and service
 * @param tc context
 */
static void
connectToService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceInfo *serviceInfo = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
    {
      /* Service is not up. Unable to proceed */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': timeout\n"),
		  serviceInfo->serviceName);
      closeClientAndServiceSockets (serviceInfo,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': shutdown\n"),
		  serviceInfo->serviceName);
      closeClientAndServiceSockets (serviceInfo,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  GNUNET_break (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Service `%s' started\n"),
	      serviceInfo->serviceName);

  /* Now service is up and running, connect to it */
  serviceInfo->armServiceSocket =
    GNUNET_NETWORK_socket_create (serviceInfo->service_addr->sa_family,
				  SOCK_STREAM, 0);
  if (NULL == serviceInfo->armServiceSocket)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _
		  ("Unable to start service `%s': failed to create socket\n"),
		  serviceInfo->serviceName);
      closeClientAndServiceSockets (serviceInfo,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }

  if ((GNUNET_SYSERR ==
       GNUNET_NETWORK_socket_connect (serviceInfo->armServiceSocket,
				      serviceInfo->service_addr,
				      serviceInfo->service_addr_len))
      && (EINPROGRESS != errno))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': failed to connect\n"),
		  serviceInfo->serviceName);
      closeClientAndServiceSockets (serviceInfo,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  /* Handling requests from client to service */
  serviceInfo->clientReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				   serviceInfo->armClientSocket,
				   &receiveFromClient, serviceInfo);

  /* Handling service responses to client */
  serviceInfo->serviceReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				   serviceInfo->armServiceSocket,
				   &receiveFromService, serviceInfo);
}


static void
stopServiceListeningSockets (struct ServiceListeningInfo
			     *serviceListeningInfo)
{
  struct ServiceListeningInfo *pos = serviceListeningInfoList_head;
  struct ServiceListeningInfo *tmp;

  while (NULL != pos)
    {
      if ((strcmp (pos->serviceName, serviceListeningInfo->serviceName) == 0)
	  && (pos != serviceListeningInfo))
	{
	  GNUNET_SCHEDULER_cancel (scheduler, pos->acceptTask);
	  GNUNET_NETWORK_socket_close (pos->listeningSocket);
	  tmp = pos;
	  pos = pos->next;
	  GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
				       serviceListeningInfoList_tail, tmp);
	  GNUNET_free (tmp->service_addr);
	  GNUNET_free (tmp);
	  continue;
	}
      pos = pos->next;
    }
}


/**
 * First connection has come to the listening socket associated with the service,
 * create the service in order to relay the incoming connection to it
 * 
 * @param cls callback data, serviceInfo struct for the communication between client and service
 * @param tc context 
 */
static void
acceptConnection (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceListeningInfo *serviceListeningInfo = cls;
  struct ServiceInfo *serviceInfo;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;

  if ((NULL == startedServices)
      || (GNUNET_NO ==
	  isServiceAlreadyStarted (serviceListeningInfo->serviceName)))
    {
      /* First request to receive at all, or first request to connect to that service */
      /* Accept client's connection */
      serviceInfo =
	newServiceInfo (serviceListeningInfo->serviceName,
			serviceListeningInfo->service_addr,
			serviceListeningInfo->service_addr_len);
      serviceInfo->armClientSocket =
	GNUNET_NETWORK_socket_accept (serviceListeningInfo->listeningSocket,
				      &(serviceListeningInfo->client_addr),
				      &(serviceListeningInfo->
					client_addr_len));
      if (NULL == serviceInfo->armClientSocket)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _
		      ("Unable to accept connection for service `%s': Invalid socket\n"),
		      serviceListeningInfo->serviceName);
	  return;
	}


      /* 
       * Close listening socket, start service, 
       * and stop all listening sockets associated with that service 
       * and free their correspondent ServiceInfo objects
       */
      GNUNET_NETWORK_socket_close (serviceListeningInfo->listeningSocket);
      start_service (NULL, serviceListeningInfo->serviceName);
      setStartedService (serviceListeningInfo->serviceName);
      stopServiceListeningSockets (serviceListeningInfo);

      /* Notify me when the service is up and running */
      GNUNET_CLIENT_service_test (scheduler,
				  serviceListeningInfo->serviceName, cfg,
				  TIMEOUT, &connectToService, serviceInfo);
    }
}


/**
 * Creating a listening socket for each of the service's addresses and wait for the first incoming connection to it
 * 
 * @param addrs list of addresses associated with the service
 * @param addr_lens list containing length for each of the addresses in addrs
 * @param numOfAddresses length of the addr_lens array
 * @param serviceName the name of the service in question
 */
static void
createListeningSocket (struct sockaddr **addrs, socklen_t * addr_lens,
		       int numOfAddresses, char *serviceName)
{
  int i;
  struct GNUNET_NETWORK_Handle *socket;
  struct sockaddr *sa;
  socklen_t addr_len;
  struct ServiceListeningInfo *serviceListeningInfo;

  for (i = 0; i < numOfAddresses; i++)
    {
      sa = addrs[i];
      addr_len = addr_lens[i];
      switch (sa->sa_family)
	{
	case AF_INET:
	  socket = GNUNET_NETWORK_socket_create (PF_INET, SOCK_STREAM, 0);
	  break;
	case AF_INET6:
	  socket = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
	  break;
	default:
	  socket = NULL;
	  break;
	}
      if (NULL == socket)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      "Unable to create socket for service %s", serviceName);
	  continue;
	}

      /* Bind */
      if (GNUNET_NETWORK_socket_bind
	  (socket, (const struct sockaddr *) sa, addr_len) != GNUNET_OK)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Unable to bind listening socket for service `%s'\n"),
		      serviceName);
	  continue;
	}

      /* Listen */
      if (GNUNET_NETWORK_socket_listen (socket, 5) != GNUNET_OK)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Error listening socket for service `%s'\n"),
		      serviceName);
	}

      serviceListeningInfo =
	newServiceListeningInfo (serviceName, sa, addr_len, socket);
      serviceListeningInfo->listeningSocket = socket;
      serviceListeningInfo->serviceName = serviceName;
      serviceListeningInfo->service_addr = sa;
      serviceListeningInfo->service_addr_len = addr_len;

      /* Wait for the first incoming connection */
      serviceListeningInfo->acceptTask =
	GNUNET_SCHEDULER_add_read_net (scheduler,
				       GNUNET_TIME_UNIT_FOREVER_REL, socket,
				       &acceptConnection,
				       serviceListeningInfo);
    }
}

/**
 * Callback function, checks whether the current tokens are representing a service,
 * gets its addresses and create listening socket for it.
 * 
 * @param cls callback data, not used
 * @param section configuration section
 * @param option configuration option
 * @param the option's value
 */
static void
checkPortNumberCB (void *cls,
		   const char *section, const char *option, const char *value)
{
  /* The service shouldn't be a default service */
  if ((strcmp (section, "arm") != 0)
      && (strcmp (option, "PORT") == 0)
      && (isInDefaultList (section) == GNUNET_NO))
    {
      /* then the section is representing a service */
      struct sockaddr **addrs;
      socklen_t *addr_lens;
      int ret;

      ret =
	GNUNET_SERVICE_get_server_addresses (section, cfg, &addrs,
					     &addr_lens);
      if (ret == GNUNET_SYSERR)
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("Unable to resolve host name for service `%s'\n"),
		    section);
      else if (ret != GNUNET_NO)
	{
	  /* Addresses found for service */
	  createListeningSocket (addrs, addr_lens, ret, (char *) section);
	}
      else
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    _("No addresses for service `%s' in configuration\n"),
		    section);
    }
}

/**
 * Entry point to the Service Manager
 *
 * @param configurationHandle configuration to use to get services
 * @param sched scheduler to handle clients and services communications
 */
void
prepareServices (const struct GNUNET_CONFIGURATION_Handle
		 *configurationHandle, struct GNUNET_SCHEDULER_Handle *sched)
{
  char *defaultServicesString;
  scheduler = sched;
  cfg = configurationHandle;

  /* Split the default services into a list */
  GNUNET_CONFIGURATION_get_value_string (cfg, "arm", "DEFAULTSERVICES",
					 &defaultServicesString);
  addDefaultServicesToList (defaultServicesString);

#if DEBUG_SERVICE_MANAGER
  printDefaultServicesList ();
#endif

  /* Spot the services from the configuration and create a listening socket for each */
  GNUNET_CONFIGURATION_iterate (cfg, &checkPortNumberCB, NULL);
}
