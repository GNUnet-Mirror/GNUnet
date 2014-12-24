/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-bcd.c
 * @author Christian Grothoff
 * @brief HTTP server to create GNS business cards
 */

#include "platform.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"

/**
 * Error page to display if submitted GNS key is invalid.
 */
#define INVALID_GNSKEY "<html><head><title>Error</title><body>Invalid GNS public key given.</body></html>"

/**
 * Error page to display on 404.
 */
#define NOT_FOUND "<html><head><title>Error</title><body>404 not found</body></html>"

/**
 * Handle to the HTTP server as provided by libmicrohttpd
 */
static struct MHD_Daemon *daemon_handle;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our primary task for the HTTPD.
 */
static struct GNUNET_SCHEDULER_Task * http_task;

/**
 * Our main website.
 */
static struct MHD_Response *main_response;

/**
 * Error: invalid gns key.
 */
static struct MHD_Response *invalid_gnskey_response;

/**
 * Error: 404
 */
static struct MHD_Response *not_found_response;

/**
 * Absolute name of the 'gns-bcd.tex' file.
 */
static char *resfile;

/**
 * Port number.
 */
static unsigned int port = 8888;


struct Entry
{
  const char *formname;
  const char *texname;
};


/**
 * Main request handler.
 */
static int
access_handler_callback (void *cls, struct MHD_Connection *connection,
                         const char *url, const char *method,
                         const char *version, const char *upload_data,
                         size_t * upload_data_size, void **con_cls)
{
  static int dummy;
  static const struct Entry map[] = {
    { "prefix", "prefix" },
    { "name", "name" },
    { "suffix", "suffix" },
    { "street", "street" },
    { "city", "city" },
    { "phone", "phone" },
    { "fax", "fax" },
    { "email", "email"},
    { "homepage", "homepage" },
    { "orga", "orga"},
    { "departmenti18n", "departmentde"},
    { "departmenten", "departmenten"},
    { "subdepartmenti18n", "subdepartmentde"},
    { "subdepartmenten", "subdepartmenten"},
    { "jobtitlei18n", "jobtitlegerman"},
    { "jobtitleen", "jobtitleenglish"},
    { "subdepartmenten", "subdepartmenten"},
    { NULL, NULL }
  };

  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Refusing `%s' request to HTTP server\n"),
                method);
    return MHD_NO;
  }
  if (NULL == *con_cls)
  {
    (*con_cls) = &dummy;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending 100 CONTINUE reply\n");
    return MHD_YES;             /* send 100 continue */
  }
  if (0 == strcasecmp (url, "/"))
    return MHD_queue_response (connection,
                               MHD_HTTP_OK,
                               main_response);
  if (0 == strcasecmp (url, "/submit.pdf"))
  {
    unsigned int i;
    char *p;
    char *tmp;
    char *deffile;
    struct GNUNET_CRYPTO_EcdsaPublicKey pub;
    size_t slen;
    FILE *f;
    struct stat st;
    struct MHD_Response *response;
    int fd;
    int ret;

    const char *gpg_fp = MHD_lookup_connection_value (connection,
                                                      MHD_GET_ARGUMENT_KIND,
                                                      "gpgfingerprint");
    const char *gns_nick = MHD_lookup_connection_value (connection,
                                                        MHD_GET_ARGUMENT_KIND,
                                                        "gnsnick");
    const char *gnskey = MHD_lookup_connection_value (connection,
                                                      MHD_GET_ARGUMENT_KIND,
                                                      "gnskey");
    if ( (NULL == gnskey) ||
         (GNUNET_OK !=
          GNUNET_CRYPTO_ecdsa_public_key_from_string (gnskey,
                                                      strlen (gnskey),
                                                      &pub)))
    {
      return MHD_queue_response (connection,
                                 MHD_HTTP_OK,
                                 invalid_gnskey_response);
    }
    tmp = GNUNET_DISK_mkdtemp (gnskey);
    if (NULL == tmp)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "mktemp", gnskey);
      return MHD_NO;
    }
    GNUNET_asprintf (&deffile,
                     "%s%s%s",
                     tmp, DIR_SEPARATOR_STR, "def.tex");
    f = FOPEN (deffile, "w");
    if (NULL == f)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", deffile);
      GNUNET_free (deffile);
      GNUNET_DISK_directory_remove (tmp);
      GNUNET_free (tmp);
      return MHD_NO;
    }
    for (i=0; NULL != map[i].formname; i++)
    {
      const char *val =  MHD_lookup_connection_value (connection,
                                                      MHD_GET_ARGUMENT_KIND,
                                                      map[i].formname);
      if (NULL != val)
        FPRINTF (f,
                 "\\def\\%s{%s}\n",
                 map[i].texname, val);
      else
        FPRINTF (f,
                 "\\def\\%s{}\n",
                 map[i].texname);
    }
    if (NULL != gpg_fp)
    {
      char *gpg1;
      char *gpg2;

      slen = strlen (gpg_fp);
      gpg1 = GNUNET_strndup (gpg_fp, slen / 2);
      gpg2 = GNUNET_strdup (&gpg_fp[slen / 2]);
      FPRINTF (f,
               "\\def\\gpglineone{%s}\n\\def\\gpglinetwo{%s}\n",
               gpg1, gpg2);
      GNUNET_free (gpg2);
      GNUNET_free (gpg1);
    }
    FPRINTF (f,
             "\\def\\gns{%s/%s}\n",
             gnskey,
             (NULL == gns_nick) ? "" : gns_nick);
    FCLOSE (f);
    GNUNET_asprintf (&p,
                     "cd %s; cp %s gns-bcd.tex | pdflatex --enable-write18 gns-bcd.tex > /dev/null 2> /dev/null",
                     tmp,
                     resfile);
    GNUNET_free (deffile);
    ret = system (p);
    if (WIFSIGNALED (ret) || (0 != WEXITSTATUS(ret)))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "system",
                                p);
    GNUNET_asprintf (&deffile,
                     "%s%s%s",
                     tmp, DIR_SEPARATOR_STR, "gns-bcd.pdf");
    fd = OPEN (deffile, O_RDONLY);
    if (-1 == fd)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "open",
                                deffile);
      GNUNET_free (deffile);
      GNUNET_free (p);
      GNUNET_DISK_directory_remove (tmp);
      GNUNET_free (tmp);
      return MHD_NO;
    }
    GNUNET_break (0 == STAT (deffile, &st));
    if (NULL == (response = MHD_create_response_from_fd ((size_t) st.st_size, fd)))
    {
      GNUNET_break (0);
      GNUNET_break (0 == CLOSE (fd));
      GNUNET_free (deffile);
      GNUNET_free (p);
      GNUNET_DISK_directory_remove (tmp);
      GNUNET_free (tmp);
      return MHD_NO;
    }
    (void) MHD_add_response_header (response,
                                    MHD_HTTP_HEADER_CONTENT_TYPE,
                                    "application/pdf");
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
    GNUNET_free (deffile);
    GNUNET_free (p);
    GNUNET_DISK_directory_remove (tmp);
    GNUNET_free (tmp);
    return ret;
  }
  return MHD_queue_response (connection,
                             MHD_HTTP_NOT_FOUND,
                             not_found_response);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static struct GNUNET_SCHEDULER_Task *
prepare_daemon (struct MHD_Daemon *daemon_handle);


/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void
run_daemon (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MHD_Daemon *daemon_handle = cls;

  http_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  http_task = prepare_daemon (daemon_handle);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static struct GNUNET_SCHEDULER_Task *
prepare_daemon (struct MHD_Daemon *daemon_handle)
{
  struct GNUNET_SCHEDULER_Task * ret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  int max;
  MHD_UNSIGNED_LONG_LONG timeout;
  int haveto;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES == MHD_get_fdset (daemon_handle, &rs, &ws, &es, &max));
  haveto = MHD_get_timeout (daemon_handle, &timeout);
  if (haveto == MHD_YES)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  ret =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
				   tv, wrs, wws,
                                   &run_daemon, daemon_handle);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  return ret;
}


/**
 * Start server offering our hostlist.
 *
 * @return #GNUNET_OK on success
 */
static int
server_start ()
{
  if ((0 == port) || (port > UINT16_MAX))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Invalid port number %llu.  Exiting.\n"),
                port);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Businesscard HTTP server starts on %llu\n"),
              port);
  daemon_handle = MHD_start_daemon (MHD_USE_DUAL_STACK | MHD_USE_DEBUG,
                                    (uint16_t) port,
                                    NULL /* accept_policy_callback */, NULL,
                                    &access_handler_callback, NULL,
                                    MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 512,
                                    MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 2,
                                    MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 60,
                                    MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                    MHD_OPTION_END);
  if (NULL == daemon_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not start businesscard HTTP server on port %u\n"),
                (unsigned short) port);
    return GNUNET_SYSERR;
  }
  http_task = prepare_daemon (daemon_handle);
  return GNUNET_OK;
}


/**
 * Stop HTTP server.
 */
static void
server_stop (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "HTTP server shutdown\n");
  if (NULL != http_task)
  {
    GNUNET_SCHEDULER_cancel (http_task);
    http_task = NULL;
  }
  if (NULL != daemon_handle)
  {
    MHD_stop_daemon (daemon_handle);
    daemon_handle = NULL;
  }
  if (NULL != main_response)
  {
    MHD_destroy_response (main_response);
    main_response = NULL;
  }
  if (NULL != invalid_gnskey_response)
  {
    MHD_destroy_response (invalid_gnskey_response);
    invalid_gnskey_response = NULL;
  }
  if (NULL != not_found_response)
  {
    MHD_destroy_response (not_found_response);
    not_found_response = NULL;
  }
  if (NULL != resfile)
  {
    GNUNET_free (resfile);
    resfile = NULL;
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct stat st;
  char *dir;
  char *fn;
  int fd;

  cfg = c;
  dir = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  GNUNET_assert (NULL != dir);
  GNUNET_asprintf (&fn,
                   "%s%s%s",
                   dir,
                   DIR_SEPARATOR_STR,
                   "gns-bcd.html");
  GNUNET_asprintf (&resfile,
                   "%s%s%s",
                   dir,
                   DIR_SEPARATOR_STR,
                   "gns-bcd.tex");
  GNUNET_free (dir);
  fd = OPEN (fn, O_RDONLY);
  if (-1 == fd)
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "open",
                              fn);
    GNUNET_free (fn);
    return;
  }
  if (0 != STAT (fn, &st))
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "open",
                              fn);
    GNUNET_free (fn);
    CLOSE (fd);
    return;
  }
  GNUNET_free (fn);
  if (NULL == (main_response = MHD_create_response_from_fd ((size_t) st.st_size, fd)))
  {
    GNUNET_break (0);
    GNUNET_break (0 == CLOSE (fd));
    return;
  }
  (void) MHD_add_response_header (main_response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/html");
  invalid_gnskey_response = MHD_create_response_from_buffer (strlen (INVALID_GNSKEY),
                                                             INVALID_GNSKEY,
                                                             MHD_RESPMEM_PERSISTENT);
  (void) MHD_add_response_header (invalid_gnskey_response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/html");
  not_found_response = MHD_create_response_from_buffer (strlen (NOT_FOUND),
                                                        NOT_FOUND,
                                                        MHD_RESPMEM_PERSISTENT);
  (void) MHD_add_response_header (not_found_response,
                                  MHD_HTTP_HEADER_CONTENT_TYPE,
                                  "text/html");
  if (GNUNET_OK !=
      server_start ())
    return;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &server_stop,
                                NULL);
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'p', "port", "PORT",
      gettext_noop ("Run HTTP serve on port PORT (default is 8888)"), 1,
      &GNUNET_GETOPT_set_uint, &port},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  GNUNET_log_setup ("gnunet-bcd", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-bcd",
                           _("GNUnet HTTP server to create business cards"),
			   options,
                           &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}


/* end of gnunet-bcd.c */
