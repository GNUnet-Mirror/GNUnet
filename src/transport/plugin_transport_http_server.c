/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http.c
 * @brief http transport service plugin
 * @author Matthias Wachs
 */

#include "plugin_transport_http.h"

static void
server_log (void *arg, const char *fmt, va_list ap)
{
  char text[1024];

  vsnprintf (text, sizeof (text), fmt, ap);
  va_end (ap);
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "server: %s\n", text);
}

/**
 * Check if incoming connection is accepted.
 * NOTE: Here every connection is accepted
 * @param cls plugin as closure
 * @param addr address of incoming connection
 * @param addr_len address length of incoming connection
 * @return MHD_YES if connection is accepted, MHD_NO if connection is rejected
 *
 */
static int
server_accept_cb (void *cls, const struct sockaddr *addr, socklen_t addr_len)
{
  return 0;
}


/**
 * Callback called by MHD when it needs data to send
 * @param cls current session
 * @param pos position in buffer
 * @param buf the buffer to write data to
 * @param max max number of bytes available in buffer
 * @return bytes written to buffer
 */
#if 0
static ssize_t
server_send_cb (void *cls, uint64_t pos, char *buf, size_t max)
{

  return 0;
}
#endif


#if BUILD_HTTPS
static char *
server_load_file (const char *file)
{
  struct GNUNET_DISK_FileHandle *gn_file;
  struct stat fstat;
  char *text = NULL;

  if (0 != STAT (file, &fstat))
    return NULL;
  text = GNUNET_malloc (fstat.st_size + 1);
  gn_file =
      GNUNET_DISK_file_open (file, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_USER_READ);
  if (gn_file == NULL)
  {
    GNUNET_free (text);
    return NULL;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_file_read (gn_file, text, fstat.st_size))
  {
    GNUNET_free (text);
    GNUNET_DISK_file_close (gn_file);
    return NULL;
  }
  text[fstat.st_size] = '\0';
  GNUNET_DISK_file_close (gn_file);
  return text;
}
#endif


#if BUILD_HTTPS

static int
server_load_certificate (struct Plugin *plugin)
{
  int res = GNUNET_OK;

  char *key_file;
  char *cert_file;

  /* Get crypto init string from config
   * If not present just use default values */
  GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                         "CRYPTO_INIT", &plugin->crypto_init);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg, plugin->name,
                                               "KEY_FILE", &key_file))
  {
    key_file = "https_key.key";
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg, plugin->name,
                                               "CERT_FILE", &cert_file))
  {
    cert_file = "https_cert.crt";
  }

  /* read key & certificates from file */
#if VERBOSE_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loading TLS certificate from key-file `%s' cert-file`%s'\n",
              key_file, cert_file);
#endif

  plugin->key = server_load_file (key_file);
  plugin->cert = server_load_file (cert_file);

  if ((plugin->key == NULL) || (plugin->cert == NULL))
  {
    struct GNUNET_OS_Process *cert_creation;

    GNUNET_free_non_null (plugin->key);
    plugin->key = NULL;
    GNUNET_free_non_null (plugin->cert);
    plugin->cert = NULL;

#if VERBOSE_SERVER
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No usable TLS certificate found, creating certificate\n");
#endif
    errno = 0;
    cert_creation =
        GNUNET_OS_start_process (NULL, NULL,
                                 "gnunet-transport-certificate-creation",
                                 "gnunet-transport-certificate-creation",
                                 key_file, cert_file, NULL);
    if (cert_creation == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                       _
                       ("Could not create a new TLS certificate, program `gnunet-transport-certificate-creation' could not be started!\n"));
      GNUNET_free (key_file);
      GNUNET_free (cert_file);

      GNUNET_free_non_null (plugin->key);
      GNUNET_free_non_null (plugin->cert);
      GNUNET_free_non_null (plugin->crypto_init);

      return GNUNET_SYSERR;
    }
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (cert_creation));
    GNUNET_OS_process_close (cert_creation);

    plugin->key = server_load_file (key_file);
    plugin->cert = server_load_file (cert_file);
  }

  if ((plugin->key == NULL) || (plugin->cert == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _
                     ("No usable TLS certificate found and creating one failed!\n"),
                     "transport-https");
    GNUNET_free (key_file);
    GNUNET_free (cert_file);

    GNUNET_free_non_null (plugin->key);
    GNUNET_free_non_null (plugin->cert);
    GNUNET_free_non_null (plugin->crypto_init);

    return GNUNET_SYSERR;
  }
  GNUNET_free (key_file);
  GNUNET_free (cert_file);
#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TLS certificate loaded\n");
#endif

  return res;
}
#endif


/**
 * Process GET or PUT request received via MHD.  For
 * GET, queue response that will send back our pending
 * messages.  For PUT, process incoming data and send
 * to GNUnet core.  In either case, check if a session
 * already exists and create a new one if not.
 */
static int
server_access_cb (void *cls, struct MHD_Connection *mhd_connection,
                  const char *url, const char *method, const char *version,
                  const char *upload_data, size_t * upload_data_size,
                  void **httpSessionCache)
{
  return 0;
}

static void
server_disconnect_cb (void *cls, struct MHD_Connection *connection,
                      void **httpSessionCache)
{
}

int
server_disconnect (struct Session *s)
{
  return GNUNET_OK;
}

int
server_send (struct Session *s, const char *msgbuf, size_t msgbuf_size)
{
  return GNUNET_OK;
}

int
server_start (struct Plugin *plugin)
{
  int res = GNUNET_OK;

#if BUILD_HTTPS
  res = server_load_certificate (plugin);
  if (res == GNUNET_SYSERR)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TABORT\n");
    return res;
  }
#endif

  plugin->server_v4 = NULL;
  if (plugin->ipv4 == GNUNET_YES)
  {
    plugin->server_v4 = MHD_start_daemon (
#if VERBOSE_SERVER
                                           MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
                                           MHD_USE_SSL |
#endif
                                           MHD_NO_FLAG, plugin->port,
                                           &server_accept_cb, plugin,
                                           &server_access_cb, plugin,
                                           //MHD_OPTION_SOCK_ADDR,
                                           //(struct sockaddr_in *)
                                           //plugin->bind4_address,
                                           MHD_OPTION_CONNECTION_LIMIT,
                                           (unsigned int)
                                           plugin->max_connections,
#if BUILD_HTTPS
                                           MHD_OPTION_HTTPS_PRIORITIES,
                                           plugin->crypto_init,
                                           MHD_OPTION_HTTPS_MEM_KEY,
                                           plugin->key,
                                           MHD_OPTION_HTTPS_MEM_CERT,
                                           plugin->cert,
#endif
                                           MHD_OPTION_CONNECTION_TIMEOUT,
                                           (unsigned int) 3,
                                           MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                           (size_t) (2 *
                                                     GNUNET_SERVER_MAX_MESSAGE_SIZE),
                                           MHD_OPTION_NOTIFY_COMPLETED,
                                           &server_disconnect_cb, plugin,
                                           MHD_OPTION_EXTERNAL_LOGGER,
                                           server_log, NULL, MHD_OPTION_END);
    if (plugin->server_v4 == NULL)
      res = GNUNET_SYSERR;
  }
  plugin->server_v6 = NULL;
  if (plugin->ipv6 == GNUNET_YES)
  {
    plugin->server_v6 = MHD_start_daemon (
#if VERBOSE_SERVER
                                           MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
                                           MHD_USE_SSL |
#endif
                                           MHD_USE_IPv6, plugin->port,
                                           &server_accept_cb, plugin,
                                           &server_access_cb, plugin,
                                           //MHD_OPTION_SOCK_ADDR,
                                           //tmp,
                                           MHD_OPTION_CONNECTION_LIMIT,
                                           (unsigned int)
                                           plugin->max_connections,
#if BUILD_HTTPS
                                           MHD_OPTION_HTTPS_PRIORITIES,
                                           plugin->crypto_init,
                                           MHD_OPTION_HTTPS_MEM_KEY,
                                           plugin->key,
                                           MHD_OPTION_HTTPS_MEM_CERT,
                                           plugin->cert,
#endif
                                           MHD_OPTION_CONNECTION_TIMEOUT,
                                           (unsigned int) 3,
                                           MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                           (size_t) (2 *
                                                     GNUNET_SERVER_MAX_MESSAGE_SIZE),
                                           MHD_OPTION_NOTIFY_COMPLETED,
                                           &server_disconnect_cb, plugin,
                                           MHD_OPTION_EXTERNAL_LOGGER,
                                           server_log, NULL, MHD_OPTION_END);

    if (plugin->server_v6 == NULL)
      res = GNUNET_SYSERR;
  }

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component started on port %u\n", plugin->name,
                   plugin->port);
#endif
  return res;
}

void
server_stop (struct Plugin *plugin)
{

  if (plugin->server_v4 != NULL)
  {
    MHD_stop_daemon (plugin->server_v4);
    plugin->server_v4 = NULL;
  }
  if (plugin->server_v6 != NULL)
  {
    MHD_stop_daemon (plugin->server_v6);
    plugin->server_v6 = NULL;
  }

#if BUILD_HTTPS
  GNUNET_free_non_null (plugin->crypto_init);
  GNUNET_free_non_null (plugin->cert);
  GNUNET_free_non_null (plugin->key);
#endif

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component stopped\n", plugin->name);
#endif
}



/* end of plugin_transport_http.c */
