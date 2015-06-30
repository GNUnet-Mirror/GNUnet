/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file transport-testing.c
 * @brief testing lib for transport service
 *
 * @author Matthias Wachs
 */
#include "transport-testing.h"


#define LOG(kind,...) GNUNET_log_from(kind, "transport-testing", __VA_ARGS__)


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
notify_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerContext *p = cls;
  char *p2_s;
  struct PeerContext *p2;

  GNUNET_assert (NULL != p);
  GNUNET_assert (NULL != p->tth);
  p2 = find_peer_context (p->tth, peer);
  if (p->nc != NULL)
    p->nc (p->cb_cls, peer);

  if (p2 != NULL)
    GNUNET_asprintf (&p2_s, "%u (`%s')", p2->no, GNUNET_i2s (&p2->id));
  else
    GNUNET_asprintf (&p2_s, "`%s'", GNUNET_i2s (peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peers %s connected to peer %u (`%s')\n",
       p2_s,
       p->no,
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peers %s disconnected from peer %u (`%s')\n",
       p2_s,
       no,
       GNUNET_i2s (&p->id));
  GNUNET_free (p2_s);

  if (p == NULL)
    return;
  if (p->nd != NULL)
    p->nd (p->cb_cls, peer);
}


static void
notify_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cls;

  if (p == NULL)
    return;
  if (p->rec != NULL)
    p->rec (p->cb_cls, peer, message);
}


static void
get_hello (void *cb_cls, const struct GNUNET_MessageHeader *message)
{
  struct PeerContext *p = cb_cls;
  struct GNUNET_PeerIdentity hello_id;

  GNUNET_assert (message != NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *)
                                      message, &hello_id));
  GNUNET_assert (0 == memcmp (&hello_id, &p->id, sizeof (hello_id)));
  GNUNET_free_non_null (p->hello);
  p->hello = (struct GNUNET_HELLO_Message *) GNUNET_copy_message (message);

  if (NULL != p->start_cb)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
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

  cc->tct = NULL;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  GNUNET_assert (cc != NULL);
  GNUNET_assert (cc->p1 != NULL);
  GNUNET_assert (cc->p2 != NULL);

  char *p2_s = GNUNET_strdup (GNUNET_i2s (&p2->id));

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asking peer %u (`%s') to connect peer %u (`%s'), providing HELLO with %u bytes\n",
       p1->no, GNUNET_i2s (&p1->id), p2->no, p2_s,
       GNUNET_HELLO_size (cc->p2->hello));
  GNUNET_free (p2_s);

  GNUNET_TRANSPORT_offer_hello (cc->th_p1,
                                (const struct GNUNET_MessageHeader *) cc->
                                p2->hello, NULL, NULL);
  GNUNET_TRANSPORT_try_connect (cc->th_p1, &p2->id, NULL, NULL); /*FIXME TRY_CONNECT change */

  cc->tct =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &try_connect, cc);
}


/**
 * Start a peer with the given configuration
 * @param tth the testing handle
 * @param cfgname configuration file
 * @param peer_id a unique number to identify the peer
 * @param rec receive callback
 * @param nc connect callback
 * @param nd disconnect callback
 * @param start_cb start callback
 * @param cb_cls closure for callback
 * @return the peer context
 */
struct PeerContext *
GNUNET_TRANSPORT_TESTING_start_peer (struct GNUNET_TRANSPORT_TESTING_handle *tth,
                                     const char *cfgname, int peer_id,
                                     GNUNET_TRANSPORT_ReceiveCallback rec,
                                     GNUNET_TRANSPORT_NotifyConnect nc,
                                     GNUNET_TRANSPORT_NotifyDisconnect nd,
                                     GNUNET_TRANSPORT_TESTING_start_cb start_cb,
                                     void *cb_cls)
{
  char *emsg = NULL;
  struct GNUNET_PeerIdentity *dummy;

  GNUNET_assert (NULL != tth);
  GNUNET_assert (NULL != tth->tl_system);

  if (GNUNET_DISK_file_test (cfgname) == GNUNET_NO)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "File not found: `%s'\n",
         cfgname);
    return NULL;
  }

  struct PeerContext *p = GNUNET_new (struct PeerContext);
  GNUNET_CONTAINER_DLL_insert (tth->p_head, tth->p_tail, p);

  /* Create configuration and call testing lib to modify it */
  p->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (p->cfg, cfgname));
  if (GNUNET_SYSERR == GNUNET_TESTING_configuration_create (tth->tl_system, p->cfg))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         cfgname);
    GNUNET_free (p);
    return NULL;
  }

  p->no = peer_id;
  /* Configure peer with configuration */
  p->peer = GNUNET_TESTING_peer_configure (tth->tl_system, p->cfg, p->no, NULL, &emsg);
  if (NULL == p->peer)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
    GNUNET_free_non_null (emsg);
    return NULL;
  }
  GNUNET_free_non_null (emsg);
  if (GNUNET_OK != GNUNET_TESTING_peer_start (p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         cfgname);
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
    return NULL;
  }

  memset(&dummy, '\0', sizeof (dummy));
  GNUNET_TESTING_peer_get_identity (p->peer, &p->id);
  if (0 == memcmp (&dummy, &p->id, sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to obtain peer identity for peer %u\n",
         p->no);
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
    return NULL;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Peer %u configured with identity `%s'\n",
         p->no,
         GNUNET_i2s_full (&p->id));
  }

  p->tth = tth;
  p->nc = nc;
  p->nd = nd;
  p->rec = rec;
  p->start_cb = start_cb;
  if (cb_cls != NULL)
    p->cb_cls = cb_cls;
  else
    p->cb_cls = p;

  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL, p,
                                    &notify_receive,
                                    &notify_connect, &notify_disconnect);
  if (NULL == p->th)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to transport service for peer  `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
    return NULL;
  }

  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &get_hello, p);
  GNUNET_assert (p->ghh != NULL);

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
  GNUNET_assert (tth != NULL);
  GNUNET_assert (p != NULL);
  GNUNET_assert (NULL != p->peer);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Restarting peer %u (`%s')\n",
       p->no,
       GNUNET_i2s (&p->id));

  /* shutdown */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stopping peer %u (`%s')\n",
       p->no,
       GNUNET_i2s (&p->id));
  if (NULL != p->ghh)
    GNUNET_TRANSPORT_get_hello_cancel (p->ghh);
  p->ghh = NULL;

  if (NULL != p->th)
    GNUNET_TRANSPORT_disconnect (p->th);

  if (GNUNET_SYSERR == GNUNET_TESTING_peer_stop(p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to stop peer %u (`%s')\n",
         p->no,
         GNUNET_i2s (&p->id));
    return GNUNET_SYSERR;
  }

  sleep (5); // YUCK!

  /* restart */
  if (GNUNET_SYSERR == GNUNET_TESTING_peer_start(p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to restart peer %u (`%s')\n",
         p->no, GNUNET_i2s (&p->id));
    return GNUNET_SYSERR;
  }

  GNUNET_assert (p->th != NULL);
  GNUNET_assert (p->start_cb == NULL);
  p->start_cb = restart_cb;
  p->cb_cls = cb_cls;

  p->th = GNUNET_TRANSPORT_connect (p->cfg, NULL, p,
                                    &notify_receive,
                                    &notify_connect,
                                    &notify_disconnect);
  GNUNET_assert (NULL != p->th);

  p->ghh = GNUNET_TRANSPORT_get_hello (p->th, &get_hello, p);
  GNUNET_assert (p->ghh != NULL);
  return GNUNET_OK;
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
  {
    GNUNET_TRANSPORT_disconnect (p->th);
    p->th = NULL;
  }

  if (p->peer != NULL)
  {
    if (GNUNET_OK != GNUNET_TESTING_peer_stop (p->peer))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Testing lib failed to stop peer %u (`%s') \n", p->no,
           GNUNET_i2s (&p->id));
    }
    GNUNET_TESTING_peer_destroy (p->peer);
    p->peer = NULL;
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %u (`%s') stopped \n", p->no,
       GNUNET_i2s (&p->id));
  GNUNET_free (p);
}


/**
 * Initiate a connection from p1 to p2 by offering p1 p2's HELLO message
 *
 * Remarks: start_peer's notify_connect callback can be called before.
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
      GNUNET_new (struct ConnectingContext);

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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New connect request %p\n",
       cc);

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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling connect request %p!\n",
       cc);

  if (cc->tct != NULL)
    GNUNET_SCHEDULER_cancel (cc->tct);
  cc->tct = NULL;

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
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Developer forgot to cancel connect request %p!\n",
         cc);
    GNUNET_TRANSPORT_TESTING_connect_peers_cancel (tth, cc);
    cc = ct;
  }

  while (p != NULL)
  {
    t = p->next;
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Developer forgot to stop peer!\n");
    GNUNET_TRANSPORT_TESTING_stop_peer (tth, p);
    p = t;
  }

  GNUNET_TESTING_system_destroy (tth->tl_system, GNUNET_YES);

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

  /* prepare hostkeys */
  tth = GNUNET_new (struct GNUNET_TRANSPORT_TESTING_handle);

  /* Init testing the testing lib */
  tth->tl_system = GNUNET_TESTING_system_create ("transport-testing", NULL,
                                                 NULL, NULL);
  if (NULL == tth->tl_system)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to initialize testing library!\n"));
    GNUNET_free (tth);
    return NULL;
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
#if WINDOWS
  if ((strlen (pch) >= 3) && pch[1] == ':')
  {
    if (NULL != strstr (pch, "\\"))
    {
      pch = strtok (pch, "\\");
      while (pch != NULL)
      {
        pch = strtok (NULL, "\\");
        if (pch != NULL)
          filename = pch;
      }
    }
  }
  if (filename != NULL)
    pch = filename; /* If we miss the next condition, filename = pch will
                     * not harm us.
                     */
#endif
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
