/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_normalization.c
 * @brief ats service address: management of ATS properties and preferences normalization
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_normalization.h"



/**
 * Preference client
 */
struct PreferenceClient
{
  /**
   * Next in DLL
   */
  struct PreferenceClient *prev;

  /**
   * Next in DLL
   */

  struct PreferenceClient *next;

  /**
   * Client handle
   */
  void *client;

  /**
   * Total preference for this peer
   */
  double f_total[GNUNET_ATS_PreferenceCount];

  /**
   * List of peer preferences for this client
   */

  /**
   * Head of peer list
   */
  struct PreferencePeer *p_head;

  /**
   * Tail of peer list
   */
  struct PreferencePeer *p_tail;
};


/**
 * Preference peer
 */
struct PreferencePeer
{
  /**
   * Next in DLL
   */
  struct PreferencePeer *next;

  /**
   * Previous in DLL
   */
  struct PreferencePeer *prev;

  /**
   * Client
   */
  struct PreferenceClient *client;

  /**
   * Peer id
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Preference Values
   */
  double f[GNUNET_ATS_PreferenceCount];

  /**
   * Relative Preference Values
   */
  double f_rel[GNUNET_ATS_PreferenceCount];

  /**
   * Relative Total Preference Value
   */
  double f_rel_total;

  GNUNET_SCHEDULER_TaskIdentifier aging_task;
};



struct PreferenceClient *pc_head;
struct PreferenceClient *pc_tail;

static void
preference_aging (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

}

/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param client the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score the normalized score
 */
float
GAS_normalization_change_preference (void *src,
                                   	 const struct GNUNET_PeerIdentity *peer,
                                   	 enum GNUNET_ATS_PreferenceKind kind,
                                   	 float score_abs)
{
	float score_rel = 1.0;
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;
  int i;


  GNUNET_assert (NULL != src);
  GNUNET_assert (NULL != peer);
/*
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client %p changes preference for peer `%s' %s %f\n",
                                src,
                                GNUNET_i2s (peer),
                                GNUNET_ATS_print_preference_type (kind),
                                score_abs);
*/
  if (kind >= GNUNET_ATS_PreferenceCount)
  {
      GNUNET_break (0);
      return 0.0;
  }

  /* Find preference client */
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
  {
      if (src == c_cur->client)
        break;
  }
  /* Not found: create new preference client */
  if (NULL == c_cur)
  {
    c_cur = GNUNET_malloc (sizeof (struct PreferenceClient));
    c_cur->client = src;
    GNUNET_CONTAINER_DLL_insert (pc_head, pc_tail, c_cur);
  }

  /* Find entry for peer */
  for (p_cur = c_cur->p_head; NULL != p_cur; p_cur = p_cur->next)
    if (0 == memcmp (&p_cur->id, peer, sizeof (p_cur->id)))
        break;

  /* Not found: create new peer entry */
  if (NULL == p_cur)
  {
      p_cur = GNUNET_malloc (sizeof (struct PreferencePeer));
      p_cur->client = c_cur;
      p_cur->id = (*peer);
      for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
      {
        /* Default value per peer absolut preference for a quality:
         * No value set, so absolute preference 0 */
        p_cur->f[i] = DEFAULT_ABS_PREFERENCE;
        /* Default value per peer relative preference for a quality: 1.0 */
        p_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
      }
      p_cur->aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL, &preference_aging, p_cur);
      GNUNET_CONTAINER_DLL_insert (c_cur->p_head, c_cur->p_tail, p_cur);
  }
//  update_preference (p_cur, kind, score);
  return score_rel;
}

void
GAS_normalization_start ()
{
	return;
}

void
GAS_normalization_stop ()
{
  struct PreferenceClient *pc;
  struct PreferenceClient *next_pc;
  struct PreferencePeer *p;
  struct PreferencePeer *next_p;

  next_pc = pc_head;
  while (NULL != (pc = next_pc))
  {
      next_pc = pc->next;
      GNUNET_CONTAINER_DLL_remove (pc_head, pc_tail, pc);
      next_p = pc->p_head;
      while (NULL != (p = next_p))
      {
          next_p = p->next;
          if (GNUNET_SCHEDULER_NO_TASK != p->aging_task)
          {
          	GNUNET_SCHEDULER_cancel(p->aging_task);
          	p->aging_task = GNUNET_SCHEDULER_NO_TASK;
          }
          GNUNET_CONTAINER_DLL_remove (pc->p_head, pc->p_tail, p);
          GNUNET_free (p);
      }
      GNUNET_free (pc);
  }
	return;
}

/* end of gnunet-service-ats_normalization.c */
