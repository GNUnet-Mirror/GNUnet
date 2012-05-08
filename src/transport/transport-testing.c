/*
     This file is part of GNUnet.
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport-testing.c
 * @brief testing lib for transport service
 *
 * @author Matthias Wachs
 */

#include "transport-testing.h"

#define HOSTKEYFILESIZE 914

static const char *
get_host_key (struct GNUNET_TRANSPORT_TESTING_handle *tth)
{
  if (tth->hostkey_data == NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                     "No precomputed hostkeys available\n");
    return NULL;
  }
  if (tth->hostkeys_total > tth->hostkeys_last)
  {
    tth->hostkeys_last++;
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                     "Used hostkey %u of %u available hostkeys\n",
                     tth->hostkeys_last, tth->hostkeys_total);
    return &tth->hostkey_data[(tth->hostkeys_last - 1) * HOSTKEYFILESIZE];
  }
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "No hostkey available (%u of %u already used)\n",
                   tth->hostkeys_last, tth->hostkeys_total);
  return NULL;
}


static struct PeerContext *
find_peer_context (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                   const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (tth != NULL);
  struct PeerContext *t = tth->p_head;

  while (t != NULL)
  {
    if (0 == memcmp (&t->id, peer, sizeof (struct GNUNET_PeerIdentity)))
      break;
    t = t->next;
  }

  return t;
}


static struct ConnectingContext *
find_connecting_context (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                         struct PeerContext *p1, struct PeerContext *p2)
{
  GNUNET_assert (tth != NULL);
  struct ConnectingContext *cc = tth->cc_head;

  while (cc != NULL)
  {
    if ((cc->p1 == p1) && (cc->p2 == p2))
      break;
    if ((cc->p1 == p2) && (cc->p2 == p1))
      break;
    cc = cc->next;
  }

  return cc;
}


static void
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct PeerContext *p = cls;

  /* Find PeerContext */
  GNUNET_assert (p != 0);
  GNUNET_assert (p->tth != NULL);
  struct PeerContext *p2 = find_peer_context (p->tth, peer);

  if (p == NULL)
    return;
  if (p->nc != NULL)
    p->nc (p->cb_cls, peer, ats, ats_count);

  char *p2_s;

  if (p2 != NULL)
    GNUNET_asprintf (&p2_s, "%u (`%s')", p2->no, GNUNET_i2s (&p2->id));
  else
    GNUNET_asprintf (&p2_s, "`%s'", GNUNET_i2s (peer));
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Peers %s connected to peer %u (`%s')\n", p2_s, p->no,
                   GNUNET_i2s (&p->id));
  GNUNET_free (p2_s);

  /* Find ConnectingContext */
  struct ConnectingContext *cc = find_connecting_context (p->tth, p, p2);

  if (cc == NULL)
    return;

  if (p == cc->p1)
    cc->p1_c = GNUNET_YES;

  if (p == cc->p2)
    cc->p2_c = GNUNET_YES;

  if ((cc->p1_c == GNUNET_YES) && (cc->p2_c == GNUNET_YES))
  {
    cc->cb (cc->p1, cc->p2, cc->cb_cls);
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (p->tth, cc);
  }
}


static void
notify_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;

  /* Find PeerContext */
  int no = 0;
  struct PeerContext *p2 = NULL;

  if (p != NULL)
  {
    GNUNET_assert (p->tth != NULL);
    p2 = find_peer_context (p->tth, peer);
    no = p->no;
  }

  char *p2_s;

  if (p2 != NULL)
    GNUNET_asprintf (&p2_s, "%u (`%s')", p2->no, GNUNET_i2s (&p2->id));
  else
    GNUNET_asprintf (&p2_s, "`%s'", GNUNET_i2s (peer));
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Peers %s disconnected from peer %u (`%s')\n", p2_s, no,
                   GNUNET_i2s (&p->id));
  GNUNET_free (p2_s);

  if (p == NULL)
    return;
  if (p->nd != NULL)
    p->nd (p->cb_cls, peer);
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message,
                const struct GNUNET_ATS_Information *ats, uint32_t ats_count)
{
  struct PeerContext *p = cls;

  if (p == NULL)
    return;
  if (p->rec != NULL)
    p->rec (p->cb_cls, peer, message, ats, ats_count);
}


static void
get_hello (void *cb_cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cb_cls;

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &p->id));
  GNUNET_free_non_null (p->hello);
  p->hello = (struct GNUNET_HELLO_Message *) GNUNET_copy_message (message);

  if (p->start_cb != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                     "Peer %u (`%s') successfully started\n", p->no,
                     GNUNET_i2s (&p->id));

    p->start_cb (p, p->cb_cls);
    p->start_cb = NULL;
  }
}


static void
try_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectingContext *cc = cls;
  struct PeerContext *p1 = cc->p1;
  struct PeerContext *p2 = cc->p2;

  cc->tct = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  GNUNET_assert (cc != NULL);
  GNUNET_assert (cc->p1 != NULL);
  GNUNET_assert (cc->p2 != NULL);

  char *p2_s = GNUNET_strdup (GNUNET_i2s (&p2->id));

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Asking peer %u (`%s') to connect peer %u (`%s'), providing HELLO with %u bytes\n",
                   p1->no, GNUNET_i2s (&p1->id), p2->no, p2_s,
                   GNUNET_HELLO_size (cc->p2->hello));
  GNUNET_free (p2_s);

  GNUNET_TRANSPORT_offer_hello (cc->th_p1,
                                (const struct GNUNET_MessageHeader *) cc->
                                p2->hello, NULL, NULL);
  GNUNET_TRANSPORT_try_connect (cc->th_p1, &p2->id);

  cc->tct =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &try_connect, cc);
}


/**
 * Start a peer with the given configuration
 * @param tth the testing handle
 * @param cfgname configuration file
 * @param peer_id the peer_id
 * @param rec receive callback
 * @param nc connect callback
 * @param nd disconnect callback
 * @param start_cb start callback
 * @param cb_cls closure for callback
 * @return the peer context
 */
struct PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (struct GNUNET_TRANSPORT_TESTING_handle
                                     *tth, const char *cfgname, int peer_id,
                                     GNUNET_TRANSPORT_ReceiveCallback rec,
                                     GNUNET_TRANSPORT_NotifyConnect nc,
                                     GNUNET_TRANSPORT_NotifyDisconnect nd,
                                     GNUNET_TRANSPORT_TESTING_start_cb start_cb,
                                     void *cb_cls)
{
  const char *hostkey = NULL;
  struct GNUNET_DISK_FileHandle *fn;

  GNUNET_assert (tth != NULL);
  if (GNUNET_DISK_file_test (cfgname) == GNUNET_NO)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "transport-testing",
                     "File not found: `%s' \n", cfgname);
    return NULL;
  }

  struct PeerContext *p = GNUNET_malloc (sizeof (struct PeerContext));

  p->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));

  if (GNUNET_CONFIGURATION_have_value (p->cfg, "PATHS", "SERVICEHOME"))
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONFIGURATION_get_value_string (p->cfg, "PATHS",
                                                          "SERVICEHOME",
                                                          &p->servicehome));

  if (NULL != p->servicehome)
    GNUNET_DISK_directory_remove (p->servicehome);

  hostkey = get_host_key (tth);
  if (hostkey != NULL)
  {

    GNUNET_asprintf (&p->hostkeyfile, "%s/.hostkey", p->servicehome);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_DISK_directory_create_for_file (p->hostkeyfile));
    fn = GNUNET_DISK_file_open (p->hostkeyfile,
                                GNUNET_DISK_OPEN_READWRITE |
                                GNUNET_DISK_OPEN_CREATE,
                                GNUNET_DISK_PERM_USER_READ |
                                GNUNET_DISK_PERM_USER_WRITE);
    GNUNET_assert (fn != NULL);
    GNUNET_assert (HOSTKEYFILESIZE ==
                   GNUNET_DISK_file_write (fn, hostkey, HOSTKEYFILESIZE));
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fn));
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                     "Wrote hostkey to file: `%s' \n", p->hostkeyfile);
  }

  p->arm_proc =
      GNUNET_OS_start_process (GNUNET_YES,
			       NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm", "-c", cfgname,
                               "-L", "ERROR",
                               NULL);

  p->no = peer_id;
  p->tth = tth;
  p->nc = nc;
  p->nd = nd;
  p->rec = rec;
  p->start_cb = start_cb;
  if (cb_cls != NULL)
    p->cb_cls = cb_cls;
  else
    p->cb_cls = p;

  p->th =
      GNUNET_TRANSPORT_connect (p->cfg, NULL, p, &notify_receive,
                                &notify_connect, &notify_disconnect);
  GNUNET_assert (p->th != NULL);

  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &get_hello, p);
  GNUNET_assert (p->ghh != NULL);

  GNUNET_CONTAINER_DLL_insert (tth->p_head, tth->p_tail, p);
  return p;
}

/**
* Restart the given peer
* @param tth testing handle
* @param p the peer
* @param cfgname the cfg file used to restart
* @param restart_cb callback to call when restarted
* @param cb_cls callback closure
* @return GNUNET_OK in success otherwise GNUNET_SYSERR
*/
int
GNUNET_TRANSPORT_TESTING_restart_peer (struct GNUNET_TRANSPORT_TESTING_handle
                                       *tth, struct PeerContext *p,
                                       const char *cfgname,
                                       GNUNET_TRANSPORT_TESTING_start_cb
                                       restart_cb, void *cb_cls)
{
  struct GNUNET_DISK_FileHandle *fn;

  GNUNET_assert (tth != NULL);
  GNUNET_assert (p != NULL);
  GNUNET_assert (p->hostkeyfile != NULL);
  GNUNET_assert (p->servicehome != NULL);

  /* shutdown */
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Stopping peer %u (`%s')\n", p->no, GNUNET_i2s (&p->id));
  if (p->ghh != NULL)
    GNUNET_TRANSPORT_get_hello_cancel (p->ghh);
  p->ghh = NULL;

  if (p->th != NULL)
    GNUNET_TRANSPORT_disconnect (p->th);

  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (p->arm_proc);
    GNUNET_OS_process_destroy (p->arm_proc);
    p->arm_proc = NULL;
  }
  if (p->hello != NULL)
    GNUNET_free (p->hello);
  p->hello = NULL;

  if (p->cfg != NULL)
    GNUNET_CONFIGURATION_destroy (p->cfg);
  p->cfg = NULL;


  /* start */
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Restarting peer %u (`%s')\n", p->no, GNUNET_i2s (&p->id));
  sleep (5);                    // YUCK!

  if (GNUNET_DISK_file_test (cfgname) == GNUNET_NO)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "transport-testing",
                     "File not found: `%s' \n", cfgname);
    goto fail;
  }

  p->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (p->cfg, cfgname));

  if (!GNUNET_CONFIGURATION_have_value (p->cfg, "PATHS", "SERVICEHOME"))
    goto fail;

  fn = GNUNET_DISK_file_open (p->hostkeyfile,
                              GNUNET_DISK_OPEN_READWRITE |
                              GNUNET_DISK_OPEN_CREATE,
                              GNUNET_DISK_PERM_USER_READ |
                              GNUNET_DISK_PERM_USER_WRITE);
  if (fn == NULL)
    goto fail;
  if (GNUNET_OK != GNUNET_DISK_file_close (fn))
    goto fail;

  p->arm_proc =
      GNUNET_OS_start_process (GNUNET_YES, 
			       NULL, NULL, "gnunet-service-arm",
                               "gnunet-service-arm", "-c", cfgname,
                               "-L", "ERROR",
                               NULL);

  p->th =
      GNUNET_TRANSPORT_connect (p->cfg, NULL, p, &notify_receive,
                                &notify_connect, &notify_disconnect);
  GNUNET_assert (p->th != NULL);

  p->start_cb = restart_cb;
  p->cb_cls = cb_cls;

  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &get_hello, p);
  GNUNET_assert (p->ghh != NULL);
  return GNUNET_OK;

fail:
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Restarting peer %u (`%s') failed, removing peer\n", p->no,
                   GNUNET_i2s (&p->id));
  GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
  return GNUNET_SYSERR;
}


/**
 * shutdown the given peer
 * @param tth testing handle
 * @param p the peer
 */
void
GNUNET_TRANSPORT_TESTING_stop_peer (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                    struct PeerContext *p)
{
  GNUNET_assert (p != NULL);
  if (p->ghh != NULL)
  {
    GNUNET_TRANSPORT_get_hello_cancel (p->ghh);
    p->ghh = NULL;
  }
  if (p->th != NULL)
    GNUNET_TRANSPORT_disconnect (p->th);
  if (NULL != p->arm_proc)
  {
    if (0 != GNUNET_OS_process_kill (p->arm_proc, SIGTERM))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    GNUNET_OS_process_wait (p->arm_proc);
    GNUNET_OS_process_destroy (p->arm_proc);
    p->arm_proc = NULL;
  }
  if (p->hostkeyfile != NULL)
  {
    GNUNET_DISK_directory_remove (p->hostkeyfile);
    GNUNET_free (p->hostkeyfile);
  }
  if (p->servicehome != NULL)
  {
    GNUNET_DISK_directory_remove (p->servicehome);
    GNUNET_free (p->servicehome);
  }
  if (p->hello != NULL)
  {
    GNUNET_free (p->hello);
    p->hello = NULL;
  }
  if (p->cfg != NULL)
  {
    GNUNET_CONFIGURATION_destroy (p->cfg);
    p->cfg = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (tth->p_head, tth->p_tail, p);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Peer %u (`%s') stopped \n", p->no,
                   GNUNET_i2s (&p->id));
  GNUNET_free (p);
}


/**
 * Connect the given peers and call the callback when both peers report the
 * inbound connection. Remarks: start_peer's notify_connect callback can be called
 * before.
 *
 * @param tth transport testing handle
 * @param p1 peer 1
 * @param p2 peer 2
 * @param cb the callback to call when both peers notified that they are connected
 * @param cls callback cls
 * @return a connect request handle
 */
GNUNET_TRANSPORT_TESTING_ConnectRequest
GNUNET_TRANSPORT_TESTING_connect_peers (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                        struct PeerContext *p1,
                                        struct PeerContext *p2,
                                        GNUNET_TRANSPORT_TESTING_connect_cb cb,
                                        void *cls)
{
  GNUNET_assert (tth != NULL);

  struct ConnectingContext *cc =
      GNUNET_malloc (sizeof (struct ConnectingContext));

  GNUNET_assert (p1 != NULL);
  GNUNET_assert (p2 != NULL);
  cc->p1 = p1;
  cc->p2 = p2;
  cc->cb = cb;
  if (cls != NULL)
    cc->cb_cls = cls;
  else
    cc->cb_cls = cc;
  cc->th_p1 = p1->th;
  cc->th_p2 = p2->th;
  GNUNET_assert (cc->th_p1 != NULL);
  GNUNET_assert (cc->th_p2 != NULL);
  GNUNET_CONTAINER_DLL_insert (tth->cc_head, tth->cc_tail, cc);
  cc->tct = GNUNET_SCHEDULER_add_now (&try_connect, cc);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "New connect request %X\n", cc);

  return cc;
}


/**
 * Cancel the request to connect two peers
 * Tou MUST cancel the request if you stop the peers before the peers connected succesfully
 *
 * @param tth transport testing handle
 * @param ccr a connect request handle
 */
void
GNUNET_TRANSPORT_TESTING_connect_peers_cancel (struct
                                               GNUNET_TRANSPORT_TESTING_handle
                                               *tth,
                                               GNUNET_TRANSPORT_TESTING_ConnectRequest
                                               ccr)
{
  struct ConnectingContext *cc = ccr;

  GNUNET_assert (tth != NULL);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                   "Canceling connect request %X!\n", cc);

  if (cc->tct != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (cc->tct);
  cc->tct = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_CONTAINER_DLL_remove (tth->cc_head, tth->cc_tail, cc);
  GNUNET_free (cc);
}


/**
 * Clean up the transport testing
 * @param tth transport testing handle
 */
void
GNUNET_TRANSPORT_TESTING_done (struct GNUNET_TRANSPORT_TESTING_handle *tth)
{
  struct ConnectingContext *cc = tth->cc_head;
  struct ConnectingContext *ct = NULL;
  struct PeerContext *p = tth->p_head;
  struct PeerContext *t = NULL;

  GNUNET_assert (tth != NULL);

  while (cc != tth->cc_tail)
  {
    ct = cc->next;
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "transport-testing",
                     "Developer forgot to cancel connect request %X!\n", cc);
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = ct;
  }

  while (p != NULL)
  {
    t = p->next;
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "transport-testing",
                     "Developer forgot to stop peer!\n");
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
    p = t;
  }

  GNUNET_free_non_null (tth->hostkey_data);

  GNUNET_free (tth);
  tth = NULL;
}


/**
 * Initialize the transport testing
 * @return transport testing handle
 */
struct GNUNET_TRANSPORT_TESTING_handle *
GNUNET_TRANSPORT_TESTING_init ()
{
  struct GNUNET_TRANSPORT_TESTING_handle *tth;
  struct GNUNET_DISK_FileHandle *fd;
  uint64_t fs;
  uint64_t total_hostkeys;


  /* prepare hostkeys */
  tth = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_TESTING_handle));
  tth->hostkey_data = NULL;
  const char *hostkeys_file = "../../contrib/testing_hostkeys.dat";

  if (GNUNET_YES != GNUNET_DISK_file_test (hostkeys_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not read hostkeys file!\n"));
  }
  else
  {
    /* Check hostkey file size, read entire thing into memory */
    fd = GNUNET_DISK_file_open (hostkeys_file, GNUNET_DISK_OPEN_READ,
                                GNUNET_DISK_PERM_NONE);
    if (NULL == fd)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open", hostkeys_file);
      GNUNET_free (tth);
      return NULL;
    }

    if (GNUNET_OK != GNUNET_DISK_file_size (hostkeys_file, &fs, GNUNET_YES, GNUNET_YES))
      fs = 0;

    if (0 != (fs % HOSTKEYFILESIZE))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "transport-testing",
                       "File size %llu seems incorrect for hostkeys...\n", fs);
    }
    else
    {
      total_hostkeys = fs / HOSTKEYFILESIZE;
      tth->hostkey_data = GNUNET_malloc_large (fs);
      GNUNET_assert (fs == GNUNET_DISK_file_read (fd, tth->hostkey_data, fs));
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-testing",
                       "Read %llu hostkeys from file\n", total_hostkeys);
      tth->hostkeys_total = total_hostkeys;
    }
    GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));
  }

  return tth;
}


/*
 * Some utility functions
 */

/**
 * Removes all directory separators from absolute filename
 * @param file the absolute file name, e.g. as found in argv[0]
 * @return extracted file name, has to be freed by caller
 */
static char *
extract_filename (const char *file)
{
  char *pch = GNUNET_strdup (file);
  char *backup = pch;
  char *filename = NULL;
  char *res;

  if (NULL != strstr (pch, "/"))
  {
    pch = strtok (pch, "/");
    while (pch != NULL)
    {
      pch = strtok (NULL, "/");
      if (pch != NULL)
      {
        filename = pch;
      }
    }
  }
  else
    filename = pch;

  res = GNUNET_strdup (filename);
  GNUNET_free (backup);
  return res;
}


/**
 * Extracts the test filename from an absolute file name and removes the extension
 * @param file absolute file name
 * @param dest where to store result
 */
void
GNUNET_TRANSPORT_TESTING_get_test_name (const char *file, char **dest)
{
  char *filename = extract_filename (file);
  char *backup = filename;
  char *dotexe;

  if (filename == NULL)
    goto fail;

  /* remove "lt-" */
  filename = strstr (filename, "tes");
  if (filename == NULL)
    goto fail;

  /* remove ".exe" */
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';

  goto suc;

fail:
  (*dest) = NULL;
  return;

suc:
  /* create filename */
  GNUNET_asprintf (dest, "%s", filename);
  GNUNET_free (backup);
}


/**
 * Extracts the filename from an absolute file name and removes the extension
 * @param file absolute file name
 * @param dest where to store result
 */
void
GNUNET_TRANSPORT_TESTING_get_test_source_name (const char *file, char **dest)
{
  char *src = extract_filename (file);
  char *split;

  split = strstr (src, ".");
  if (split != NULL)
  {
    split[0] = '\0';
  }
  GNUNET_asprintf (dest, "%s", src);
  GNUNET_free (src);
}


/**
 * Extracts the plugin name from an absolute file name and the test name
 *
 * @param file absolute file name
 * @param test test name
 * @param dest where to store result
 */
void
GNUNET_TRANSPORT_TESTING_get_test_plugin_name (const char *file,
                                               const char *test, char **dest)
{
  char *filename;
  char *dotexe;
  char *e = extract_filename (file);
  char *t = extract_filename (test);

  if (NULL == e)
    goto fail;
  /* remove "lt-" */
  filename = strstr (e, "tes");
  if (NULL == filename)
    goto fail;
  /* remove ".exe" */
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';

  /* find last _ */
  filename = strstr (filename, t);
  if (NULL == filename)
    goto fail;
  /* copy plugin */
  filename += strlen (t);
  if ('\0' != *filename)
    filename++;
  GNUNET_asprintf (dest, "%s", filename);
  goto suc;
fail:
  (*dest) = NULL;
suc:
  GNUNET_free (t);
  GNUNET_free (e);
}


/**
 * This function takes the filename (e.g. argv[0), removes a "lt-"-prefix and
 * if existing ".exe"-prefix and adds the peer-number
 *
 * @param file filename of the test, e.g. argv[0]
 * @param dest where to write the filename
 * @param count peer number
 */
void
GNUNET_TRANSPORT_TESTING_get_config_name (const char *file, char **dest,
                                          int count)
{
  char *filename = extract_filename (file);
  char *backup = filename;
  char *dotexe;

  if (NULL == filename)
    goto fail;
  /* remove "lt-" */
  filename = strstr (filename, "tes");
  if (NULL == filename)
    goto fail;
  /* remove ".exe" */
  if (NULL != (dotexe = strstr (filename, ".exe")))
    dotexe[0] = '\0';
  GNUNET_asprintf (dest, "%s_peer%u.conf", filename, count);
  GNUNET_free (backup);
  return;
fail:
  (*dest) = NULL;
  GNUNET_free (backup);
}



/* end of transport-testing.c */
