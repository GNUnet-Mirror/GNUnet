/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_hosts.c
 * @brief API for manipulating 'hosts' controlled by the GNUnet testing service;
 *        allows parsing hosts files, starting, stopping and communicating (via
 *        SSH/stdin/stdout) with the remote (or local) processes
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_transport_service.h"

#include "testbed_api.h"
#include "testbed_api_hosts.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "testbed-api-hosts", __VA_ARGS__);

/**
 * Number of extra elements we create space for when we grow host list
 */
#define HOST_LIST_GROW_STEP 10


/**
 * A list entry for registered controllers list
 */
struct RegisteredController
{
  /**
   * The controller at which this host is registered
   */
  const struct GNUNET_TESTBED_Controller *controller;

  /**
   * The next ptr for DLL
   */
  struct RegisteredController *next;

  /**
   * The prev ptr for DLL
   */
  struct RegisteredController *prev;
};


/**
 * Opaque handle to a host running experiments managed by the testing framework.
 * The master process must be able to SSH to this host without password (via
 * ssh-agent).
 */
struct GNUNET_TESTBED_Host
{

  /**
   * The next pointer for DLL
   */
  struct GNUNET_TESTBED_Host *next;

  /**
   * The prev pointer for DLL
   */
  struct GNUNET_TESTBED_Host *prev;

  /**
   * The hostname of the host; NULL for localhost
   */
  const char *hostname;

  /**
   * The username to be used for SSH login
   */
  const char *username;

  /**
   * The head for the list of controllers where this host is registered
   */
  struct RegisteredController *rc_head;

  /**
   * The tail for the list of controllers where this host is registered
   */
  struct RegisteredController *rc_tail;

  /**
   * Global ID we use to refer to a host on the network
   */
  uint32_t id;

  /**
   * The port which is to be used for SSH
   */
  uint16_t port;

};


/**
 * Array of available hosts
 */
static struct GNUNET_TESTBED_Host **host_list;

/**
 * The size of the available hosts list
 */
static unsigned int host_list_size;


/**
 * Lookup a host by ID.
 *
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @return handle to the host, NULL if host not found
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_lookup_by_id_ (uint32_t id)
{
  if (host_list_size <= id)
    return NULL;
  return host_list[id];
}


/**
 * Create a host by ID; given this host handle, we could not
 * run peers at the host, but we can talk about the host
 * internally.
 *
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_by_id_ (uint32_t id)
{
  return GNUNET_TESTBED_host_create_with_id (id, NULL, NULL, 0);
}


/**
 * Obtain the host's unique global ID.
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return id global host ID assigned to the host (0 is
 *         'localhost', but then obviously not globally unique)
 */
uint32_t
GNUNET_TESTBED_host_get_id_ (const struct GNUNET_TESTBED_Host * host)
{
  return host->id;
}


/**
 * Obtain the host's hostname.
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return hostname of the host
 */
const char *
GNUNET_TESTBED_host_get_hostname (const struct GNUNET_TESTBED_Host *host)
{
  return host->hostname;
}


/**
 * Obtain the host's username
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return username to login to the host
 */
const char *
GNUNET_TESTBED_host_get_username_ (const struct GNUNET_TESTBED_Host *host)
{
  return host->username;
}


/**
 * Obtain the host's ssh port
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return username to login to the host
 */
uint16_t
GNUNET_TESTBED_host_get_ssh_port_ (const struct GNUNET_TESTBED_Host * host)
{
  return host->port;
}


/**
 * Create a host to run peers and controllers on.
 *
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_with_id (uint32_t id, const char *hostname,
                                    const char *username, uint16_t port)
{
  struct GNUNET_TESTBED_Host *host;
  unsigned int new_size;

  if ((id < host_list_size) && (NULL != host_list[id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Host with id: %u already created\n", id);
    return NULL;
  }
  host = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Host));
  host->hostname = (NULL != hostname) ? GNUNET_strdup (hostname) : NULL;
  host->username = (NULL != username) ? GNUNET_strdup (username) : NULL;
  host->id = id;
  host->port = (0 == port) ? 22 : port;
  new_size = host_list_size;
  while (id >= new_size)
    new_size += HOST_LIST_GROW_STEP;
  if (new_size != host_list_size)
    GNUNET_array_grow (host_list, host_list_size, new_size);
  GNUNET_assert (id < host_list_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding host with id: %u\n", host->id);
  host_list[id] = host;
  return host;
}


/**
 * Create a host to run peers and controllers on.
 *
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create (const char *hostname, const char *username,
                            uint16_t port)
{
  static uint32_t uid_generator;

  if (NULL == hostname)
    return GNUNET_TESTBED_host_create_with_id (0, hostname, username, port);
  return GNUNET_TESTBED_host_create_with_id (++uid_generator, hostname,
                                             username, port);
}


/**
 * Load a set of hosts from a configuration file.
 *
 * @param filename file with the host specification
 * @param hosts set to the hosts found in the file; caller must free this if
 *          number of hosts returned is greater than 0
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
GNUNET_TESTBED_hosts_load_from_file (const char *filename,
                                     struct GNUNET_TESTBED_Host ***hosts)
{
  //struct GNUNET_TESTBED_Host **host_array;
  struct GNUNET_TESTBED_Host *starting_host;
  char *data;
  char *buf;
  char username[256];
  char hostname[256];
  uint64_t fs;
  short int port;
  int ret;
  unsigned int offset;
  unsigned int count;


  GNUNET_assert (NULL != filename);
  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, _("Hosts file %s not found\n"), filename);
    return 0;
  }
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename, &fs, GNUNET_YES, GNUNET_YES))
    fs = 0;
  if (0 == fs)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, _("Hosts file %s has no data\n"), filename);
    return 0;
  }
  data = GNUNET_malloc (fs);
  if (fs != GNUNET_DISK_fn_read (filename, data, fs))
  {
    GNUNET_free (data);
    LOG (GNUNET_ERROR_TYPE_WARNING, _("Hosts file %s cannot be read\n"),
         filename);
    return 0;
  }
  buf = data;
  offset = 0;
  starting_host = NULL;
  count = 0;
  while (offset < (fs - 1))
  {
    offset++;
    if (((data[offset] == '\n')) && (buf != &data[offset]))
    {
      data[offset] = '\0';
      ret =
          SSCANF (buf, "%255[a-zA-Z0-9_]@%255[a-zA-Z0-9.]:%5hd", username,
                  hostname, &port);
      if (3 == ret)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Successfully read host %s, port %d and user %s from file\n",
                    hostname, port, username);
        /* We store hosts in a static list; hence we only require the starting
         * host pointer in that list to access the newly created list of hosts */
        if (NULL == starting_host)
          starting_host = GNUNET_TESTBED_host_create (hostname, username, port);
        else
          (void) GNUNET_TESTBED_host_create (hostname, username, port);
        count++;
      }
      else
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Error reading line `%s' in hostfile\n", buf);
      buf = &data[offset + 1];
    }
    else if ((data[offset] == '\n') || (data[offset] == '\0'))
      buf = &data[offset + 1];
  }
  GNUNET_free (data);
  if (NULL == starting_host)
    return 0;
  *hosts = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Host *) * count);
  memcpy (*hosts, &host_list[GNUNET_TESTBED_host_get_id_ (starting_host)],
          sizeof (struct GNUNET_TESTBED_Host *) * count);
  return count;
}


/**
 * Destroy a host handle.  Must only be called once everything
 * running on that host has been stopped.
 *
 * @param host handle to destroy
 */
void
GNUNET_TESTBED_host_destroy (struct GNUNET_TESTBED_Host *host)
{
  struct RegisteredController *rc;
  uint32_t id;

  GNUNET_assert (host->id < host_list_size);
  GNUNET_assert (host_list[host->id] == host);
  host_list[host->id] = NULL;
  /* clear registered controllers list */
  for (rc = host->rc_head; NULL != rc; rc = host->rc_head)
  {
    GNUNET_CONTAINER_DLL_remove (host->rc_head, host->rc_tail, rc);
    GNUNET_free (rc);
  }
  GNUNET_free_non_null ((char *) host->username);
  GNUNET_free_non_null ((char *) host->hostname);
  GNUNET_free (host);
  while (host_list_size >= HOST_LIST_GROW_STEP)
  {
    for (id = host_list_size - 1; id > host_list_size - HOST_LIST_GROW_STEP;
         id--)
      if (NULL != host_list[id])
        break;
    if (id != host_list_size - HOST_LIST_GROW_STEP)
      break;
    if (NULL != host_list[id])
      break;
    host_list_size -= HOST_LIST_GROW_STEP;
  }
  host_list =
      GNUNET_realloc (host_list,
                      sizeof (struct GNUNET_TESTBED_Host *) * host_list_size);
}


/**
 * Marks a host as registered with a controller
 *
 * @param host the host to mark
 * @param controller the controller at which this host is registered
 */
void
GNUNET_TESTBED_mark_host_registered_at_ (struct GNUNET_TESTBED_Host *host,
                                         const struct GNUNET_TESTBED_Controller
                                         *const controller)
{
  struct RegisteredController *rc;

  for (rc = host->rc_head; NULL != rc; rc = rc->next)
  {
    if (controller == rc->controller)   /* already registered at controller */
    {
      GNUNET_break (0);
      return;
    }
  }
  rc = GNUNET_malloc (sizeof (struct RegisteredController));
  rc->controller = controller;
  GNUNET_CONTAINER_DLL_insert_tail (host->rc_head, host->rc_tail, rc);
}


/**
 * Checks whether a host has been registered
 *
 * @param host the host to check
 * @param controller the controller at which host's registration is checked
 * @return GNUNET_YES if registered; GNUNET_NO if not
 */
int
GNUNET_TESTBED_is_host_registered_ (const struct GNUNET_TESTBED_Host *host,
                                    const struct GNUNET_TESTBED_Controller
                                    *const controller)
{
  struct RegisteredController *rc;

  for (rc = host->rc_head; NULL != rc; rc = rc->next)
  {
    if (controller == rc->controller)   /* already registered at controller */
    {
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


/**
 * The handle for whether a host is habitable or not
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle
{
  /**
   * The host to check
   */
  const struct GNUNET_TESTBED_Host *host;

  /* /\** */
  /*  * the configuration handle to lookup the path of the testbed helper */
  /*  *\/ */
  /* const struct GNUNET_CONFIGURATION_Handle *cfg; */

  /**
   * The callback to call once we have the status
   */
  GNUNET_TESTBED_HostHabitableCallback cb;

  /**
   * The callback closure
   */
  void *cb_cls;

  /**
   * The process handle for the SSH process
   */
  struct GNUNET_OS_Process *auxp;

  /**
   * The SSH destination address string
   */
  char *ssh_addr;

  /**
   * The destination port string
   */
  char *portstr;

  /**
   * The path for hte testbed helper binary
   */
  char *helper_binary_path;

  /**
   * Task id for the habitability check task
   */
  GNUNET_SCHEDULER_TaskIdentifier habitability_check_task;

  /**
   * How long we wait before checking the process status. Should grow
   * exponentially
   */
  struct GNUNET_TIME_Relative wait_time;

};


/**
 * Task for checking whether a host is habitable or not
 *
 * @param cls GNUNET_TESTBED_HostHabitableCheckHandle
 * @param tc the scheduler task context
 */
static void
habitability_check (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTBED_HostHabitableCheckHandle *h = cls;
  void *cb_cls;
  GNUNET_TESTBED_HostHabitableCallback cb;
  const struct GNUNET_TESTBED_Host *host;
  unsigned long code;
  enum GNUNET_OS_ProcessStatusType type;
  int ret;

  h->habitability_check_task = GNUNET_SCHEDULER_NO_TASK;
  ret = GNUNET_OS_process_status (h->auxp, &type, &code);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_break (0);
    ret = GNUNET_NO;
    goto call_cb;
  }
  if (GNUNET_NO == ret)
  {
    h->wait_time = GNUNET_TIME_STD_BACKOFF (h->wait_time);
    h->habitability_check_task =
        GNUNET_SCHEDULER_add_delayed (h->wait_time, &habitability_check, h);
    return;
  }
  GNUNET_OS_process_destroy (h->auxp);
  h->auxp = NULL;
  ret = (0 != code) ? GNUNET_NO : GNUNET_YES;

call_cb:
  GNUNET_free (h->ssh_addr);
  GNUNET_free (h->portstr);
  GNUNET_free (h->helper_binary_path);
  if (NULL != h->auxp)
    GNUNET_OS_process_destroy (h->auxp);
  cb = h->cb;
  cb_cls = h->cb_cls;
  host = h->host;
  GNUNET_free (h);
  if (NULL != cb)
    cb (cb_cls, host, ret);
}


/**
 * Checks whether a host can be used to start testbed service
 *
 * @param host the host to check
 * @param config the configuration handle to lookup the path of the testbed
 *          helper
 * @param cb the callback to call to inform about habitability of the given host
 * @param cb_cls the closure for the callback
 * @return NULL upon any error or a handle which can be passed to
 *           GNUNET_TESTBED_is_host_habitable_cancel()
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle *
GNUNET_TESTBED_is_host_habitable (const struct GNUNET_TESTBED_Host *host,
                                  const struct GNUNET_CONFIGURATION_Handle
                                  *config,
                                  GNUNET_TESTBED_HostHabitableCallback cb,
                                  void *cb_cls)
{
  struct GNUNET_TESTBED_HostHabitableCheckHandle *h;
  char *remote_args[11];
  const char *hostname;
  unsigned int argp;

  h = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_HostHabitableCheckHandle));
  h->cb = cb;
  h->cb_cls = cb_cls;
  h->host = host;
  hostname = (NULL == host->hostname) ? "127.0.0.1" : host->hostname;
  if (NULL == host->username)
    h->ssh_addr = GNUNET_strdup (hostname);
  else
    GNUNET_asprintf (&h->ssh_addr, "%s@%s", host->username, hostname);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (config, "testbed",
                                             "HELPER_BINARY_PATH",
                                             &h->helper_binary_path))
    h->helper_binary_path =
        GNUNET_OS_get_libexec_binary_path (HELPER_TESTBED_BINARY);
  argp = 0;
  remote_args[argp++] = "ssh";
  GNUNET_asprintf (&h->portstr, "%u", host->port);
  remote_args[argp++] = "-p";
  remote_args[argp++] = h->portstr;
  remote_args[argp++] = "-o";
  remote_args[argp++] = "BatchMode=yes";
  remote_args[argp++] = "-o";
  remote_args[argp++] = "NoHostAuthenticationForLocalhost=yes";
  remote_args[argp++] = h->ssh_addr;
  remote_args[argp++] = "stat";
  remote_args[argp++] = h->helper_binary_path;
  remote_args[argp++] = NULL;
  GNUNET_assert (argp == 11);
  h->auxp =
      GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ERR, NULL,
                                   NULL, "ssh", remote_args);
  if (NULL == h->auxp)
  {
    GNUNET_break (0);           /* Cannot exec SSH? */
    GNUNET_free (h->ssh_addr);
    GNUNET_free (h->portstr);
    GNUNET_free (h->helper_binary_path);
    GNUNET_free (h);
    return NULL;
  }
  h->wait_time = GNUNET_TIME_STD_BACKOFF (h->wait_time);
  h->habitability_check_task =
      GNUNET_SCHEDULER_add_delayed (h->wait_time, &habitability_check, h);
  return h;
}


/**
 * Function to cancel a request started using GNUNET_TESTBED_is_host_habitable()
 *
 * @param handle the habitability check handle
 */
void
GNUNET_TESTBED_is_host_habitable_cancel (struct
                                         GNUNET_TESTBED_HostHabitableCheckHandle
                                         *handle)
{
  GNUNET_SCHEDULER_cancel (handle->habitability_check_task);
  (void) GNUNET_OS_process_kill (handle->auxp, SIGTERM);
  (void) GNUNET_OS_process_wait (handle->auxp);
  GNUNET_OS_process_destroy (handle->auxp);
  GNUNET_free (handle->ssh_addr);
  GNUNET_free (handle->portstr);
  GNUNET_free (handle->helper_binary_path);
  GNUNET_free (handle);
}

/* end of testbed_api_hosts.c */
