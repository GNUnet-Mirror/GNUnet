/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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


struct ServiceListeningInfo
{
  struct ServiceListeningInfo *next;

  struct ServiceListeningInfo *prev;

  char *serviceName;

  struct sockaddr *service_addr;

  socklen_t service_addr_len;

  struct GNUNET_NETWORK_Handle *listeningSocket;

  GNUNET_SCHEDULER_TaskIdentifier acceptTask;
};

/**
 * Information of the connection: client-arm-service
 */
struct ForwardedConnection
{
  struct GNUNET_NETWORK_Handle *armClientSocket;

  struct GNUNET_NETWORK_Handle *armServiceSocket;

  struct ServiceListeningInfo *listen_info;

  char serviceBuffer[BUFFER_SIZE];

  char clientBuffer[BUFFER_SIZE];

  char client_addr[32];

  char *clientBufferPos;

  char *serviceBufferPos;

  GNUNET_SCHEDULER_TaskIdentifier clientReceivingTask;

  GNUNET_SCHEDULER_TaskIdentifier serviceReceivingTask;

  ssize_t clientBufferDataLength;

  ssize_t serviceBufferDataLength;

  socklen_t client_addr_len;

};


static char **defaultServicesList;

static unsigned int numDefaultServices;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_SCHEDULER_Handle *scheduler;

static struct ServiceListeningInfo *serviceListeningInfoList_head;

static struct ServiceListeningInfo *serviceListeningInfoList_tail;


#if DEBUG_SERVICE_MANAGER
static void
printDefaultServicesList ()
{
  unsigned int i;
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
addDefaultServicesToList (const char *services)
{
  unsigned int i = 0;
  char *token;
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


static void
closeClientAndServiceSockets (struct ForwardedConnection *fc, int reason)
{
  if ( (0 != (REASON_SERVICE & reason)) &&
       (fc->clientReceivingTask != GNUNET_SCHEDULER_NO_TASK) )
    {
      GNUNET_SCHEDULER_cancel (scheduler, fc->clientReceivingTask);    
      fc->clientReceivingTask = GNUNET_SCHEDULER_NO_TASK;
    }
  if ( (0 != (REASON_CLIENT & reason)) &&
       (fc->serviceReceivingTask != GNUNET_SCHEDULER_NO_TASK) )
    {
      GNUNET_SCHEDULER_cancel (scheduler,
			       fc->serviceReceivingTask);
      fc->serviceReceivingTask = GNUNET_SCHEDULER_NO_TASK;
    }
  if ( (fc->clientReceivingTask != GNUNET_SCHEDULER_NO_TASK) ||
       (fc->serviceReceivingTask != GNUNET_SCHEDULER_NO_TASK) )
    return;
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Closing forwarding connection (done with both directions)\n");
#endif
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


static void
receiveFromClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
receiveFromService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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

  fc->serviceReceivingTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Ignore shutdown signal, reschedule yourself */
      fc->serviceReceivingTask = 
	GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armClientSocket,
					&forwardToClient, fc);
      return;
    }

  /* Forwarding service response to client */
  numberOfBytesSent =
    GNUNET_NETWORK_socket_send (fc->armClientSocket,
				fc->serviceBufferPos,
				fc->serviceBufferDataLength);
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarded %d bytes to client\n",
	      numberOfBytesSent);
#endif
  if ((numberOfBytesSent == GNUNET_SYSERR) || (numberOfBytesSent == 0))
    {
      /* Error occured or connection closed by client */
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  else if (numberOfBytesSent < fc->serviceBufferDataLength)
    {
      /* Not all service data were sent to client */
      fc->serviceBufferPos += numberOfBytesSent;
      fc->serviceBufferDataLength -= numberOfBytesSent;

      /* Scheduling writing again for completing the remaining data to be sent */
      fc->serviceReceivingTask = 
	GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armClientSocket,
					&forwardToClient, fc);
    }
  else
    {
      /* Data completely sent */
      fc->serviceBufferPos = fc->serviceBuffer;
    }

  /* Now we are ready to receive more data, rescheduling receiving from Service */
  fc->serviceReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armServiceSocket,
				   &receiveFromService, fc);
}


/**
 * Receive service messages sent by the service and forward it to client
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc context
 */
static void
receiveFromService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;

  fc->serviceReceivingTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Neglect shutdown signal, reschedule yourself */
      fc->serviceReceivingTask =
	GNUNET_SCHEDULER_add_read_net (scheduler,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       fc->armServiceSocket,
				       &receiveFromService, fc);
      return;
    }

  fc->serviceBufferDataLength =
    GNUNET_NETWORK_socket_recv (fc->armServiceSocket,
				fc->serviceBuffer, BUFFER_SIZE);

#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %d bytes for client\n",
	      fc->serviceBufferDataLength);
#endif
  if (fc->serviceBufferDataLength <= 0)
    {
      /* The service has closed the connection or an error occured */
      if (fc->serviceBufferDataLength == 0)
	{
#if DEBUG_SERVICE_MANAGER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      _("Service `%s' closed connection! \n"),
		      fc->listen_info->serviceName);
#endif
	}
      else
	{	  
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Error receiving from service: %s\n"), 
		      STRERROR (errno));
	}
      closeClientAndServiceSockets (fc, REASON_SERVICE);
      return;
    }

  /* Forwarding Service data to Client */
  fc->serviceReceivingTask = 
    GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				    fc->armClientSocket,
				    &forwardToClient, fc);
}


/**
 * Forward client message to service
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc context
 */
static void
forwardToService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;
  ssize_t numberOfBytesSent;

  fc->clientReceivingTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Neglect shutdown signal, reschedule ourself */
      fc->clientReceivingTask = 
	GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armServiceSocket,
					&forwardToService, fc);
      return;
    }


  /* Forwarding client's message to service */
  numberOfBytesSent =
    GNUNET_NETWORK_socket_send (fc->armServiceSocket,
				fc->clientBufferPos,
				fc->clientBufferDataLength);
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarded %d bytes to service\n",
	      numberOfBytesSent);
#endif
  if ((numberOfBytesSent == GNUNET_SYSERR) || (numberOfBytesSent == 0))
    {
      /* Error occured or connection closed by service */
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  if (numberOfBytesSent < fc->clientBufferDataLength)
    {
      /* Not all client data were sent to the service */
      fc->clientBufferPos += numberOfBytesSent;
      fc->clientBufferDataLength -= numberOfBytesSent;

      /* Scheduling writing again for completing the remaining data to be sent */
      fc->clientReceivingTask = 
	GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
					fc->armServiceSocket,
					&forwardToService, fc);
    }
  else
    {
      /* Data completely sent */
      fc->clientBufferPos = fc->clientBuffer;
    }

  /* Now, we are ready to receive more data. Rescheduling the receiving from client */
  fc->clientReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armClientSocket,
				   &receiveFromClient, fc);
}



/**
 * Message sent from client to service (faked by ARM, since it's the first connection),
 * ARM will receive the message and forward it to the running service
 * 
 * @param cls callback data,   struct ForwardedConnection for the communication between client and service
 * @param tc context 
 */
static void
receiveFromClient (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;

  fc->clientReceivingTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      /* Neglect the shutdown signal, schedule ourselves */
      fc->clientReceivingTask =
	GNUNET_SCHEDULER_add_read_net (scheduler,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       fc->armClientSocket,
				       &receiveFromClient, fc);
      return;
    }

  /* Receive client's message */
  fc->clientBufferDataLength =
    GNUNET_NETWORK_socket_recv (fc->armClientSocket,
				fc->clientBuffer, BUFFER_SIZE);
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %d bytes for service\n",
	      fc->clientBufferDataLength);
#endif
  if (fc->clientBufferDataLength <= 0)
    {
      /* The client has closed the connection or and error occured */
      if (fc->clientBufferDataLength == 0)
	{
#if DEBUG_SERVICE_MANAGER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      _("Client closed connection with service:`%s'\n"),
		      fc->listen_info->serviceName);
#endif
	}
      else
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Error receiving from client: %s \n"),
		      STRERROR (errno));
	}
      closeClientAndServiceSockets (fc, REASON_CLIENT);
      return;
    }

  /* Forwarding request to service */
  fc->clientReceivingTask = 
    GNUNET_SCHEDULER_add_write_net (scheduler, GNUNET_TIME_UNIT_FOREVER_REL,
				    fc->armServiceSocket,
				    &forwardToService, fc);
}


static void
start_forwarding (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
    {
      /* Service is not up. Unable to proceed */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': timeout\n"),
		  fc->listen_info->serviceName);
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
#if DEBUG_SERVICE_MANAGER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      _("Connection to service to start forwarding\n"));
#endif
  fc->armServiceSocket =
    GNUNET_NETWORK_socket_create (fc->listen_info->service_addr->sa_family,
				  SOCK_STREAM, 0);
  if (NULL == fc->armServiceSocket)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _ ("Unable to start service `%s': %s\n"),
		  fc->listen_info->serviceName,
		  STRERROR (errno));
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  if ((GNUNET_SYSERR ==
       GNUNET_NETWORK_socket_connect (fc->armServiceSocket,
				      fc->listen_info->service_addr,
				      fc->listen_info->service_addr_len))
      && (EINPROGRESS != errno))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': failed to connect\n"),
		  fc->listen_info->serviceName);
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  fc->clientReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler,
				   GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armClientSocket,
				   &receiveFromClient, fc);
  fc->serviceReceivingTask =
    GNUNET_SCHEDULER_add_read_net (scheduler,
				   GNUNET_TIME_UNIT_FOREVER_REL,
				   fc->armServiceSocket,
				   &receiveFromService, fc);
}


/**
 * ARM connects to the just created service, 
 * starts the processes for relaying messages between the client and the service
 * 
 * @param cls callback data, struct ForwardedConnection for the communication between client and service
 * @param tc context
 */
static void
connectToService (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedConnection *fc = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': shutdown\n"),
		  fc->listen_info->serviceName);
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
    {
      /* Service is not up. Unable to proceed */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to start service `%s': timeout\n"),
		  fc->listen_info->serviceName);
      closeClientAndServiceSockets (fc,
				    (REASON_CLIENT & REASON_SERVICE));
      return;
    }
  GNUNET_break (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("Service `%s' started\n"),
	      fc->listen_info->serviceName);
  GNUNET_CLIENT_service_test (scheduler,
			      fc->listen_info->serviceName,
			      cfg,
			      TIMEOUT,
			      &start_forwarding,
			      fc);
}


void stop_listening (const char *serviceName)
{
  struct ServiceListeningInfo *pos;
  struct ServiceListeningInfo *next;

  next = serviceListeningInfoList_head;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if ( (serviceName != NULL) &&
	   (strcmp (pos->serviceName, serviceName) != 0) )
	continue;
      GNUNET_SCHEDULER_cancel (scheduler, pos->acceptTask);
      GNUNET_break (GNUNET_OK ==
		    GNUNET_NETWORK_socket_close (pos->listeningSocket));
      GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
				   serviceListeningInfoList_tail, 
				   pos);
      GNUNET_free (pos->serviceName);		   
      GNUNET_free (pos->service_addr);
      GNUNET_free (pos);	
    }
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
  struct ServiceListeningInfo *serviceListeningInfo = cls;
  struct ForwardedConnection *fc;

  serviceListeningInfo->acceptTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  fc = GNUNET_malloc (sizeof (struct ForwardedConnection));
  fc->listen_info = serviceListeningInfo;
  fc->serviceBufferPos = fc->serviceBuffer;
  fc->clientBufferPos = fc->clientBuffer;
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
      serviceListeningInfo->acceptTask =
	GNUNET_SCHEDULER_add_read_net (scheduler,
				       GNUNET_TIME_UNIT_FOREVER_REL, 
				       serviceListeningInfo->listeningSocket,
				       &acceptConnection,
				       serviceListeningInfo);
      return;
    }
  GNUNET_break (GNUNET_OK ==
		GNUNET_NETWORK_socket_close (serviceListeningInfo->listeningSocket));
  GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
			       serviceListeningInfoList_tail, 
			       serviceListeningInfo);
  start_service (NULL, serviceListeningInfo->serviceName);
  GNUNET_CLIENT_service_test (scheduler,
			      serviceListeningInfo->serviceName, 
			      cfg,
			      TIMEOUT,
			      &connectToService,
			      fc);    
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
createListeningSocket (struct sockaddr *sa, 
		       socklen_t addr_len,
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
    default:
      sock = NULL;
      break;
    }
  if (NULL == sock)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to create socket for service `%s'"),
		  serviceName);
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
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
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
    GNUNET_SCHEDULER_add_read_net (scheduler,
				   GNUNET_TIME_UNIT_FOREVER_REL, sock,
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
  /* this will free (or capture) addrs[i] for i in 0..ret */
  for (i = 0; i < ret; i++)
    createListeningSocket (addrs[i], addr_lens[i], section);
  GNUNET_free (addrs);
  GNUNET_free (addr_lens);
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
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "arm", "DEFAULTSERVICES",
					     &defaultServicesString))
    {
      addDefaultServicesToList (defaultServicesString);
      GNUNET_free (defaultServicesString);    
#if DEBUG_SERVICE_MANAGER
      printDefaultServicesList ();
#endif
    }
  /* Spot the services from the configuration and create a listening
     socket for each */
  GNUNET_CONFIGURATION_iterate (cfg, &checkPortNumberCB, NULL);
}

/* end of gnunet-service-manager.c */
