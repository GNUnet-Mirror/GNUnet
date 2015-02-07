/*
     This file is part of GNUnet
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file src/regex/regex_internal.c
 * @brief library to create Deterministic Finite Automatons (DFAs) from regular
 * expressions (regexes).
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_regex_service.h"
#include "regex_internal_lib.h"
#include "regex_internal.h"


/**
 * Set this to GNUNET_YES to enable state naming. Used to debug NFA->DFA
 * creation. Disabled by default for better performance.
 */
#define REGEX_DEBUG_DFA GNUNET_NO

/**
 * Set of states using MDLL API.
 */
struct REGEX_INTERNAL_StateSet_MDLL
{
  /**
   * MDLL of states.
   */
  struct REGEX_INTERNAL_State *head;

  /**
   * MDLL of states.
   */
  struct REGEX_INTERNAL_State *tail;

  /**
   * Length of the MDLL.
   */
  unsigned int len;
};


/**
 * Append state to the given StateSet '
 *
 * @param set set to be modified
 * @param state state to be appended
 */
static void
state_set_append (struct REGEX_INTERNAL_StateSet *set,
		  struct REGEX_INTERNAL_State *state)
{
  if (set->off == set->size)
    GNUNET_array_grow (set->states, set->size, set->size * 2 + 4);
  set->states[set->off++] = state;
}


/**
 * Compare two strings for equality. If either is NULL they are not equal.
 *
 * @param str1 first string for comparison.
 * @param str2 second string for comparison.
 *
 * @return 0 if the strings are the same or both NULL, 1 or -1 if not.
 */
static int
nullstrcmp (const char *str1, const char *str2)
{
  if ((NULL == str1) != (NULL == str2))
    return -1;
  if ((NULL == str1) && (NULL == str2))
    return 0;

  return strcmp (str1, str2);
}


/**
 * Adds a transition from one state to another on 'label'. Does not add
 * duplicate states.
 *
 * @param ctx context
 * @param from_state starting state for the transition
 * @param label transition label
 * @param to_state state to where the transition should point to
 */
static void
state_add_transition (struct REGEX_INTERNAL_Context *ctx,
                      struct REGEX_INTERNAL_State *from_state, const char *label,
                      struct REGEX_INTERNAL_State *to_state)
{
  struct REGEX_INTERNAL_Transition *t;
  struct REGEX_INTERNAL_Transition *oth;

  if (NULL == from_state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not create Transition.\n");
    return;
  }

  /* Do not add duplicate state transitions */
  for (t = from_state->transitions_head; NULL != t; t = t->next)
  {
    if (t->to_state == to_state && 0 == nullstrcmp (t->label, label) &&
        t->from_state == from_state)
      return;
  }

  /* sort transitions by label */
  for (oth = from_state->transitions_head; NULL != oth; oth = oth->next)
  {
    if (0 < nullstrcmp (oth->label, label))
      break;
  }

  t = GNUNET_new (struct REGEX_INTERNAL_Transition);
  if (NULL != ctx)
    t->id = ctx->transition_id++;
  if (NULL != label)
    t->label = GNUNET_strdup (label);
  else
    t->label = NULL;
  t->to_state = to_state;
  t->from_state = from_state;

  /* Add outgoing transition to 'from_state' */
  from_state->transition_count++;
  GNUNET_CONTAINER_DLL_insert_before (from_state->transitions_head,
                                      from_state->transitions_tail, oth, t);
}


/**
 * Remove a 'transition' from 'state'.
 *
 * @param state state from which the to-be-removed transition originates.
 * @param transition transition that should be removed from state 'state'.
 */
static void
state_remove_transition (struct REGEX_INTERNAL_State *state,
                         struct REGEX_INTERNAL_Transition *transition)
{
  if (NULL == state || NULL == transition)
    return;

  if (transition->from_state != state)
    return;

  GNUNET_free_non_null (transition->label);

  state->transition_count--;
  GNUNET_CONTAINER_DLL_remove (state->transitions_head, state->transitions_tail,
                               transition);

  GNUNET_free (transition);
}


/**
 * Compare two states. Used for sorting.
 *
 * @param a first state
 * @param b second state
 *
 * @return an integer less than, equal to, or greater than zero
 *         if the first argument is considered to be respectively
 *         less than, equal to, or greater than the second.
 */
static int
state_compare (const void *a, const void *b)
{
  struct REGEX_INTERNAL_State **s1 = (struct REGEX_INTERNAL_State **) a;
  struct REGEX_INTERNAL_State **s2 = (struct REGEX_INTERNAL_State **) b;

  return (*s1)->id - (*s2)->id;
}


/**
 * Get all edges leaving state 's'.
 *
 * @param s state.
 * @param edges all edges leaving 's', expected to be allocated and have enough
 *        space for s->transitions_count elements.
 *
 * @return number of edges.
 */
static unsigned int
state_get_edges (struct REGEX_INTERNAL_State *s, struct REGEX_BLOCK_Edge *edges)
{
  struct REGEX_INTERNAL_Transition *t;
  unsigned int count;

  if (NULL == s)
    return 0;

  count = 0;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (NULL != t->to_state)
    {
      edges[count].label = t->label;
      edges[count].destination = t->to_state->hash;
      count++;
    }
  }
  return count;
}


/**
 * Compare to state sets by comparing the id's of the states that are contained
 * in each set. Both sets are expected to be sorted by id!
 *
 * @param sset1 first state set
 * @param sset2 second state set
 * @return 0 if the sets are equal, otherwise non-zero
 */
static int
state_set_compare (struct REGEX_INTERNAL_StateSet *sset1,
                   struct REGEX_INTERNAL_StateSet *sset2)
{
  int result;
  unsigned int i;

  if (NULL == sset1 || NULL == sset2)
    return 1;

  result = sset1->off - sset2->off;
  if (result < 0)
    return -1;
  if (result > 0)
    return 1;
  for (i = 0; i < sset1->off; i++)
    if (0 != (result = state_compare (&sset1->states[i], &sset2->states[i])))
      break;
  return result;
}


/**
 * Clears the given StateSet 'set'
 *
 * @param set set to be cleared
 */
static void
state_set_clear (struct REGEX_INTERNAL_StateSet *set)
{
  GNUNET_array_grow (set->states, set->size, 0);
  set->off = 0;
}


/**
 * Clears an automaton fragment. Does not destroy the states inside the
 * automaton.
 *
 * @param a automaton to be cleared
 */
static void
automaton_fragment_clear (struct REGEX_INTERNAL_Automaton *a)
{
  if (NULL == a)
    return;

  a->start = NULL;
  a->end = NULL;
  a->states_head = NULL;
  a->states_tail = NULL;
  a->state_count = 0;
  GNUNET_free (a);
}


/**
 * Frees the memory used by State 's'
 *
 * @param s state that should be destroyed
 */
static void
automaton_destroy_state (struct REGEX_INTERNAL_State *s)
{
  struct REGEX_INTERNAL_Transition *t;
  struct REGEX_INTERNAL_Transition *next_t;

  if (NULL == s)
    return;

  GNUNET_free_non_null (s->name);
  GNUNET_free_non_null (s->proof);
  state_set_clear (&s->nfa_set);
  for (t = s->transitions_head; NULL != t; t = next_t)
  {
    next_t = t->next;
    state_remove_transition (s, t);
  }

  GNUNET_free (s);
}


/**
 * Remove a state from the given automaton 'a'. Always use this function when
 * altering the states of an automaton. Will also remove all transitions leading
 * to this state, before destroying it.
 *
 * @param a automaton
 * @param s state to remove
 */
static void
automaton_remove_state (struct REGEX_INTERNAL_Automaton *a,
                        struct REGEX_INTERNAL_State *s)
{
  struct REGEX_INTERNAL_State *s_check;
  struct REGEX_INTERNAL_Transition *t_check;
  struct REGEX_INTERNAL_Transition *t_check_next;

  if (NULL == a || NULL == s)
    return;

  /* remove all transitions leading to this state */
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check;
         t_check = t_check_next)
    {
      t_check_next = t_check->next;
      if (t_check->to_state == s)
        state_remove_transition (s_check, t_check);
    }
  }

  /* remove state */
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s);
  a->state_count--;

  automaton_destroy_state (s);
}


/**
 * Merge two states into one. Will merge 's1' and 's2' into 's1' and destroy
 * 's2'. 's1' will contain all (non-duplicate) outgoing transitions of 's2'.
 *
 * @param ctx context
 * @param a automaton
 * @param s1 first state
 * @param s2 second state, will be destroyed
 */
static void
automaton_merge_states (struct REGEX_INTERNAL_Context *ctx,
                        struct REGEX_INTERNAL_Automaton *a,
                        struct REGEX_INTERNAL_State *s1,
                        struct REGEX_INTERNAL_State *s2)
{
  struct REGEX_INTERNAL_State *s_check;
  struct REGEX_INTERNAL_Transition *t_check;
  struct REGEX_INTERNAL_Transition *t;
  struct REGEX_INTERNAL_Transition *t_next;
  int is_dup;

  if (s1 == s2)
    return;

  /* 1. Make all transitions pointing to s2 point to s1, unless this transition
   * does not already exists, if it already exists remove transition. */
  for (s_check = a->states_head; NULL != s_check; s_check = s_check->next)
  {
    for (t_check = s_check->transitions_head; NULL != t_check; t_check = t_next)
    {
      t_next = t_check->next;

      if (s2 == t_check->to_state)
      {
        is_dup = GNUNET_NO;
        for (t = t_check->from_state->transitions_head; NULL != t; t = t->next)
        {
          if (t->to_state == s1 && 0 == strcmp (t_check->label, t->label))
            is_dup = GNUNET_YES;
        }
        if (GNUNET_NO == is_dup)
          t_check->to_state = s1;
        else
          state_remove_transition (t_check->from_state, t_check);
      }
    }
  }

  /* 2. Add all transitions from s2 to sX to s1 */
  for (t_check = s2->transitions_head; NULL != t_check; t_check = t_check->next)
  {
    if (t_check->to_state != s1)
      state_add_transition (ctx, s1, t_check->label, t_check->to_state);
  }

  /* 3. Rename s1 to {s1,s2} */
#if REGEX_DEBUG_DFA
  char *new_name;

  new_name = s1->name;
  GNUNET_asprintf (&s1->name, "{%s,%s}", new_name, s2->name);
  GNUNET_free (new_name);
#endif

  /* remove state */
  GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s2);
  a->state_count--;
  automaton_destroy_state (s2);
}


/**
 * Add a state to the automaton 'a', always use this function to alter the
 * states DLL of the automaton.
 *
 * @param a automaton to add the state to
 * @param s state that should be added
 */
static void
automaton_add_state (struct REGEX_INTERNAL_Automaton *a,
                     struct REGEX_INTERNAL_State *s)
{
  GNUNET_CONTAINER_DLL_insert (a->states_head, a->states_tail, s);
  a->state_count++;
}


/**
 * Depth-first traversal (DFS) of all states that are reachable from state
 * 's'. Performs 'action' on each visited state.
 *
 * @param s start state.
 * @param marks an array of size a->state_count to remember which state was
 *        already visited.
 * @param count current count of the state.
 * @param check function that is checked before advancing on each transition
 *              in the DFS.
 * @param check_cls closure for check.
 * @param action action to be performed on each state.
 * @param action_cls closure for action.
 */
static void
automaton_state_traverse (struct REGEX_INTERNAL_State *s, int *marks,
                          unsigned int *count,
                          REGEX_INTERNAL_traverse_check check, void *check_cls,
                          REGEX_INTERNAL_traverse_action action, void *action_cls)
{
  struct REGEX_INTERNAL_Transition *t;

  if (GNUNET_YES == marks[s->traversal_id])
    return;

  marks[s->traversal_id] = GNUNET_YES;

  if (NULL != action)
    action (action_cls, *count, s);

  (*count)++;

  for (t = s->transitions_head; NULL != t; t = t->next)
  {
    if (NULL == check ||
        (NULL != check && GNUNET_YES == check (check_cls, s, t)))
    {
      automaton_state_traverse (t->to_state, marks, count, check, check_cls,
                                action, action_cls);
    }
  }
}


/**
 * Traverses the given automaton using depth-first-search (DFS) from it's start
 * state, visiting all reachable states and calling 'action' on each one of
 * them.
 *
 * @param a automaton to be traversed.
 * @param start start state, pass a->start or NULL to traverse the whole automaton.
 * @param check function that is checked before advancing on each transition
 *              in the DFS.
 * @param check_cls closure for check.
 * @param action action to be performed on each state.
 * @param action_cls closure for action
 */
void
REGEX_INTERNAL_automaton_traverse (const struct REGEX_INTERNAL_Automaton *a,
                                 struct REGEX_INTERNAL_State *start,
                                 REGEX_INTERNAL_traverse_check check,
                                 void *check_cls,
                                 REGEX_INTERNAL_traverse_action action,
                                 void *action_cls)
{
  unsigned int count;
  struct REGEX_INTERNAL_State *s;

  if (NULL == a || 0 == a->state_count)
    return;

  int marks[a->state_count];

  for (count = 0, s = a->states_head; NULL != s && count < a->state_count;
       s = s->next, count++)
  {
    s->traversal_id = count;
    marks[s->traversal_id] = GNUNET_NO;
  }

  count = 0;

  if (NULL == start)
    s = a->start;
  else
    s = start;

  automaton_state_traverse (s, marks, &count, check, check_cls, action,
                            action_cls);
}


/**
 * String container for faster string operations.
 */
struct StringBuffer
{
  /**
   * Buffer holding the string (may start in the middle!);
   * NOT 0-terminated!
   */
  char *sbuf;

  /**
   * Allocated buffer.
   */
  char *abuf;

  /**
   * Length of the string in the buffer.
   */
  size_t slen;

  /**
   * Number of bytes allocated for 'sbuf'
   */
  unsigned int blen;

  /**
   * Buffer currently represents "NULL" (not the empty string!)
   */
  int16_t null_flag;

  /**
   * If this entry is part of the last/current generation array,
   * this flag is GNUNET_YES if the last and current generation are
   * identical (and thus copying is unnecessary if the value didn't
   * change).  This is used in an optimization that improves
   * performance by about 1% --- if we use int16_t here.  With just
   * "int" for both flags, performance drops (on my system) significantly,
   * most likely due to increased cache misses.
   */
  int16_t synced;

};


/**
 * Compare two strings for equality. If either is NULL they are not equal.
 *
 * @param s1 first string for comparison.
 * @param s2 second string for comparison.
 *
 * @return 0 if the strings are the same or both NULL, 1 or -1 if not.
 */
static int
sb_nullstrcmp (const struct StringBuffer *s1,
	       const struct StringBuffer *s2)
{
  if ( (GNUNET_YES == s1->null_flag) &&
       (GNUNET_YES == s2->null_flag) )
    return 0;
  if ( (GNUNET_YES == s1->null_flag) ||
       (GNUNET_YES == s2->null_flag) )
    return -1;
  if (s1->slen != s2->slen)
    return -1;
  return memcmp (s1->sbuf, s2->sbuf, s1->slen);
}
	

/**
 * Compare two strings for equality.
 *
 * @param s1 first string for comparison.
 * @param s2 second string for comparison.
 *
 * @return 0 if the strings are the same, 1 or -1 if not.
 */
static int
sb_strcmp (const struct StringBuffer *s1,
	   const struct StringBuffer *s2)
{
  if (s1->slen != s2->slen)
    return -1;
  return memcmp (s1->sbuf, s2->sbuf, s1->slen);
}
	

/**
 * Reallocate the buffer of 'ret' to fit 'nlen' characters;
 * move the existing string to the beginning of the new buffer.
 *
 * @param ret current buffer, to be updated
 * @param nlen target length for the buffer, must be at least ret->slen
 */
static void
sb_realloc (struct StringBuffer *ret,
	    size_t nlen)
{
  char *old;

  GNUNET_assert (nlen >= ret->slen);
  old = ret->abuf;
  ret->abuf = GNUNET_malloc (nlen);
  ret->blen = nlen;
  memcpy (ret->abuf,
	  ret->sbuf,
	  ret->slen);
  ret->sbuf = ret->abuf;
  GNUNET_free_non_null (old);
}


/**
 * Append a string.
 *
 * @param ret where to write the result
 * @param sarg string to append
 */
static void
sb_append (struct StringBuffer *ret,
	   const struct StringBuffer *sarg)
{
  if (GNUNET_YES == ret->null_flag)
    ret->slen = 0;
  ret->null_flag = GNUNET_NO;
  if (ret->blen < sarg->slen + ret->slen)
    sb_realloc (ret, ret->blen + sarg->slen + 128);
  memcpy (&ret->sbuf[ret->slen],
	  sarg->sbuf,
	  sarg->slen);
  ret->slen += sarg->slen;
}
	

/**
 * Append a C string.
 *
 * @param ret where to write the result
 * @param cstr string to append
 */
static void
sb_append_cstr (struct StringBuffer *ret,
		const char *cstr)
{
  size_t cstr_len = strlen (cstr);

  if (GNUNET_YES == ret->null_flag)
    ret->slen = 0;
  ret->null_flag = GNUNET_NO;
  if (ret->blen < cstr_len + ret->slen)
    sb_realloc (ret, ret->blen + cstr_len + 128);
  memcpy (&ret->sbuf[ret->slen],
	  cstr,
	  cstr_len);
  ret->slen += cstr_len;
}
	

/**
 * Wrap a string buffer, that is, set ret to the format string
 * which contains an "%s" which is to be replaced with the original
 * content of 'ret'.  Note that optimizing this function is not
 * really worth it, it is rarely called.
 *
 * @param ret where to write the result and take the input for %.*s from
 * @param format format string, fprintf-style, with exactly one "%.*s"
 * @param extra_chars how long will the result be, in addition to 'sarg' length
 */
static void
sb_wrap (struct StringBuffer *ret,
	 const char *format,
	 size_t extra_chars)
{
  char *temp;

  if (GNUNET_YES == ret->null_flag)
    ret->slen = 0;
  ret->null_flag = GNUNET_NO;
  temp = GNUNET_malloc (ret->slen + extra_chars + 1);
  GNUNET_snprintf (temp,
		   ret->slen + extra_chars + 1,
		   format,
		   (int) ret->slen,
		   ret->sbuf);
  GNUNET_free_non_null (ret->abuf);
  ret->abuf = temp;
  ret->sbuf = temp;
  ret->blen = ret->slen + extra_chars + 1;
  ret->slen = ret->slen + extra_chars;
}


/**
 * Format a string buffer.    Note that optimizing this function is not
 * really worth it, it is rarely called.
 *
 * @param ret where to write the result
 * @param format format string, fprintf-style, with exactly one "%.*s"
 * @param extra_chars how long will the result be, in addition to 'sarg' length
 * @param sarg string to print into the format
 */
static void
sb_printf1 (struct StringBuffer *ret,
	    const char *format,
	    size_t extra_chars,
	    const struct StringBuffer *sarg)
{
  if (ret->blen < sarg->slen + extra_chars + 1)
    sb_realloc (ret,
		sarg->slen + extra_chars + 1);
  ret->null_flag = GNUNET_NO;
  ret->sbuf = ret->abuf;
  ret->slen = sarg->slen + extra_chars;
  GNUNET_snprintf (ret->sbuf,
		   ret->blen,
		   format,
		   (int) sarg->slen,
		   sarg->sbuf);
}


/**
 * Format a string buffer.
 *
 * @param ret where to write the result
 * @param format format string, fprintf-style, with exactly two "%.*s"
 * @param extra_chars how long will the result be, in addition to 'sarg1/2' length
 * @param sarg1 first string to print into the format
 * @param sarg2 second string to print into the format
 */
static void
sb_printf2 (struct StringBuffer *ret,
	    const char *format,
	    size_t extra_chars,
	    const struct StringBuffer *sarg1,
	    const struct StringBuffer *sarg2)
{
  if (ret->blen < sarg1->slen + sarg2->slen + extra_chars + 1)
    sb_realloc (ret,
		sarg1->slen + sarg2->slen + extra_chars + 1);
  ret->null_flag = GNUNET_NO;
  ret->slen = sarg1->slen + sarg2->slen + extra_chars;
  ret->sbuf = ret->abuf;
  GNUNET_snprintf (ret->sbuf,
		   ret->blen,
		   format,
		   (int) sarg1->slen,
		   sarg1->sbuf,
		   (int) sarg2->slen,
		   sarg2->sbuf);
}


/**
 * Format a string buffer.     Note that optimizing this function is not
 * really worth it, it is rarely called.
 *
 * @param ret where to write the result
 * @param format format string, fprintf-style, with exactly three "%.*s"
 * @param extra_chars how long will the result be, in addition to 'sarg1/2/3' length
 * @param sarg1 first string to print into the format
 * @param sarg2 second string to print into the format
 * @param sarg3 third string to print into the format
 */
static void
sb_printf3 (struct StringBuffer *ret,
	    const char *format,
	    size_t extra_chars,
	    const struct StringBuffer *sarg1,
	    const struct StringBuffer *sarg2,
	    const struct StringBuffer *sarg3)
{
  if (ret->blen < sarg1->slen + sarg2->slen + sarg3->slen + extra_chars + 1)
    sb_realloc (ret,
		sarg1->slen + sarg2->slen + sarg3->slen + extra_chars + 1);
  ret->null_flag = GNUNET_NO;
  ret->slen = sarg1->slen + sarg2->slen + sarg3->slen + extra_chars;
  ret->sbuf = ret->abuf;
  GNUNET_snprintf (ret->sbuf,
		   ret->blen,
		   format,
		   (int) sarg1->slen,
		   sarg1->sbuf,
		   (int) sarg2->slen,
		   sarg2->sbuf,
		   (int) sarg3->slen,
		   sarg3->sbuf);
}


/**
 * Free resources of the given string buffer.
 *
 * @param sb buffer to free (actual pointer is not freed, as they
 *        should not be individually allocated)
 */
static void
sb_free (struct StringBuffer *sb)
{
  GNUNET_array_grow (sb->abuf,
		     sb->blen,
		     0);
  sb->slen = 0;
  sb->sbuf = NULL;
  sb->null_flag= GNUNET_YES;
}


/**
 * Copy the given string buffer from 'in' to 'out'.
 *
 * @param in input string
 * @param out output string
 */
static void
sb_strdup (struct StringBuffer *out,
	   const struct StringBuffer *in)
	
{
  out->null_flag = in->null_flag;
  if (GNUNET_YES == out->null_flag)
    return;
  if (out->blen < in->slen)
  {
    GNUNET_array_grow (out->abuf,
		       out->blen,
		       in->slen);
  }
  out->sbuf = out->abuf;
  out->slen = in->slen;
  memcpy (out->sbuf, in->sbuf, out->slen);
}


/**
 * Copy the given string buffer from 'in' to 'out'.
 *
 * @param cstr input string
 * @param out output string
 */
static void
sb_strdup_cstr (struct StringBuffer *out,
		const char *cstr)
{
  if (NULL == cstr)
  {
    out->null_flag = GNUNET_YES;
    return;
  }
  out->null_flag = GNUNET_NO;
  out->slen = strlen (cstr);
  if (out->blen < out->slen)
  {
    GNUNET_array_grow (out->abuf,
		       out->blen,
		       out->slen);
  }
  out->sbuf = out->abuf;
  memcpy (out->sbuf, cstr, out->slen);
}


/**
 * Check if the given string 'str' needs parentheses around it when
 * using it to generate a regex.
 *
 * @param str string
 *
 * @return GNUNET_YES if parentheses are needed, GNUNET_NO otherwise
 */
static int
needs_parentheses (const struct StringBuffer *str)
{
  size_t slen;
  const char *op;
  const char *cl;
  const char *pos;
  const char *end;
  unsigned int cnt;

  if ((GNUNET_YES == str->null_flag) || ((slen = str->slen) < 2))
    return GNUNET_NO;
  pos = str->sbuf;
  if ('(' != pos[0])
    return GNUNET_YES;
  end = str->sbuf + slen;
  cnt = 1;
  pos++;
  while (cnt > 0)
  {
    cl = memchr (pos, ')', end - pos);
    if (NULL == cl)
    {
      GNUNET_break (0);
      return GNUNET_YES;
    }
    /* while '(' before ')', count opening parens */
    while ( (NULL != (op = memchr (pos, '(', end - pos)))  &&
	    (op < cl) )
    {
      cnt++;
      pos = op + 1;
    }
    /* got ')' first */
    cnt--;
    pos = cl + 1;
  }
  return (*pos == '\0') ? GNUNET_NO : GNUNET_YES;
}


/**
 * Remove parentheses surrounding string 'str'.
 * Example: "(a)" becomes "a", "(a|b)|(a|c)" stays the same.
 * You need to GNUNET_free the returned string.
 *
 * @param str string, modified to contain a
 * @return string without surrounding parentheses, string 'str' if no preceding
 *         epsilon could be found, NULL if 'str' was NULL
 */
static void
remove_parentheses (struct StringBuffer *str)
{
  size_t slen;
  const char *pos;
  const char *end;
  const char *sbuf;
  const char *op;
  const char *cp;
  unsigned int cnt;

  if (0)
    return;
  sbuf = str->sbuf;
  if ( (GNUNET_YES == str->null_flag) ||
       (1 >=  (slen = str->slen)) ||
       ('(' != str->sbuf[0]) ||
       (')' != str->sbuf[slen - 1]) )
    return;
  cnt = 0;
  pos = &sbuf[1];
  end = &sbuf[slen - 1];
  op = memchr (pos, '(', end - pos);
  cp = memchr (pos, ')', end - pos);
  while (NULL != cp)
  {
    while ( (NULL != op) &&
	    (op < cp) )
    {
      cnt++;
      pos = op + 1;
      op = memchr (pos, '(', end - pos);
    }
    while ( (NULL != cp) &&
	    ( (NULL == op) ||
	      (cp < op) ) )
    {
      if (0 == cnt)
	return; /* can't strip parens */
      cnt--;
      pos = cp + 1;
      cp = memchr (pos, ')', end - pos);
    }
  }
  if (0 != cnt)
  {
    GNUNET_break (0);
    return;
  }
  str->sbuf++;
  str->slen -= 2;
}


/**
 * Check if the string 'str' starts with an epsilon (empty string).
 * Example: "(|a)" is starting with an epsilon.
 *
 * @param str string to test
 *
 * @return 0 if str has no epsilon, 1 if str starts with '(|' and ends with ')'
 */
static int
has_epsilon (const struct StringBuffer *str)
{
  return
    (GNUNET_YES != str->null_flag) &&
    (0 < str->slen) &&
    ('(' == str->sbuf[0]) &&
    ('|' == str->sbuf[1]) &&
    (')' == str->sbuf[str->slen - 1]);
}


/**
 * Remove an epsilon from the string str. Where epsilon is an empty string
 * Example: str = "(|a|b|c)", result: "a|b|c"
 * The returned string needs to be freed.
 *
 * @param str original string
 * @param ret where to return string without preceding epsilon, string 'str' if no preceding
 *         epsilon could be found, NULL if 'str' was NULL
 */
static void
remove_epsilon (const struct StringBuffer *str,
		struct StringBuffer *ret)
{
  if (GNUNET_YES == str->null_flag)
  {
    ret->null_flag = GNUNET_YES;
    return;
  }
  if ( (str->slen > 1) &&
       ('(' == str->sbuf[0]) &&
       ('|' == str->sbuf[1]) &&
       (')' == str->sbuf[str->slen - 1]) )
  {
    /* remove epsilon */
    if (ret->blen < str->slen - 3)
    {
      GNUNET_array_grow (ret->abuf,
			 ret->blen,
			 str->slen - 3);
    }
    ret->sbuf = ret->abuf;
    ret->slen = str->slen - 3;
    memcpy (ret->sbuf, &str->sbuf[2], ret->slen);
    return;
  }
  sb_strdup (ret, str);
}


/**
 * Compare n bytes of 'str1' and 'str2'
 *
 * @param str1 first string to compare
 * @param str2 second string for comparison
 * @param n number of bytes to compare
 *
 * @return -1 if any of the strings is NULL, 0 if equal, non 0 otherwise
 */
static int
sb_strncmp (const struct StringBuffer *str1,
	    const struct StringBuffer *str2, size_t n)
{
  size_t max;

  if ( (str1->slen != str2->slen) &&
       ( (str1->slen < n) ||
	 (str2->slen < n) ) )
    return -1;
  max = GNUNET_MAX (str1->slen, str2->slen);
  if (max > n)
    max = n;
  return memcmp (str1->sbuf, str2->sbuf, max);
}


/**
 * Compare n bytes of 'str1' and 'str2'
 *
 * @param str1 first string to compare
 * @param str2 second C string for comparison
 * @param n number of bytes to compare (and length of str2)
 *
 * @return -1 if any of the strings is NULL, 0 if equal, non 0 otherwise
 */
static int
sb_strncmp_cstr (const struct StringBuffer *str1,
		 const char *str2, size_t n)
{
  if (str1->slen < n)
    return -1;
  return memcmp (str1->sbuf, str2, n);
}


/**
 * Initialize string buffer for storing strings of up to n
 * characters.
 *
 * @param sb buffer to initialize
 * @param n desired target length
 */
static void
sb_init (struct StringBuffer *sb,
	 size_t n)
{
  sb->null_flag = GNUNET_NO;
  sb->abuf = sb->sbuf = (0 == n) ? NULL : GNUNET_malloc (n);
  sb->blen = n;
  sb->slen = 0;
}


/**
 * Compare 'str1', starting from position 'k',  with whole 'str2'
 *
 * @param str1 first string to compare, starting from position 'k'
 * @param str2 second string for comparison
 * @param k starting position in 'str1'
 *
 * @return -1 if any of the strings is NULL, 0 if equal, non 0 otherwise
 */
static int
sb_strkcmp (const struct StringBuffer *str1,
	    const struct StringBuffer *str2, size_t k)
{
  if ( (GNUNET_YES == str1->null_flag) ||
       (GNUNET_YES == str2->null_flag) ||
       (k > str1->slen) ||
       (str1->slen - k != str2->slen) )
    return -1;
  return memcmp (&str1->sbuf[k], str2->sbuf, str2->slen);
}


/**
 * Helper function used as 'action' in 'REGEX_INTERNAL_automaton_traverse'
 * function to create the depth-first numbering of the states.
 *
 * @param cls states array.
 * @param count current state counter.
 * @param s current state.
 */
static void
number_states (void *cls, const unsigned int count,
               struct REGEX_INTERNAL_State *s)
{
  struct REGEX_INTERNAL_State **states = cls;

  s->dfs_id = count;
  if (NULL != states)
    states[count] = s;
}



#define PRIS(a) \
  ((GNUNET_YES == a.null_flag) ? 6 : (int) a.slen), \
  ((GNUNET_YES == a.null_flag) ? "(null)" : a.sbuf)


/**
 * Construct the regular expression given the inductive step,
 * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^*
 * R^{(k-1)}_{kj}, and simplify the resulting expression saved in R_cur_ij.
 *
 * @param R_last_ij value of  $R^{(k-1)_{ij}.
 * @param R_last_ik value of  $R^{(k-1)_{ik}.
 * @param R_last_kk value of  $R^{(k-1)_{kk}.
 * @param R_last_kj value of  $R^{(k-1)_{kj}.
 * @param R_cur_ij result for this inductive step is saved in R_cur_ij, R_cur_ij
 *                 is expected to be NULL when called!
 * @param R_cur_l optimization -- kept between iterations to avoid realloc
 * @param R_cur_r optimization -- kept between iterations to avoid realloc
 */
static void
automaton_create_proofs_simplify (const struct StringBuffer *R_last_ij,
				  const struct StringBuffer *R_last_ik,
                                  const struct StringBuffer *R_last_kk,
				  const struct StringBuffer *R_last_kj,
                                  struct StringBuffer *R_cur_ij,
				  struct StringBuffer *R_cur_l,
				  struct StringBuffer *R_cur_r)
{
  struct StringBuffer R_temp_ij;
  struct StringBuffer R_temp_ik;
  struct StringBuffer R_temp_kj;
  struct StringBuffer R_temp_kk;
  int eps_check;
  int ij_ik_cmp;
  int ij_kj_cmp;
  int ik_kk_cmp;
  int kk_kj_cmp;
  int clean_ik_kk_cmp;
  int clean_kk_kj_cmp;
  size_t length;
  size_t length_l;
  size_t length_r;

  /*
   * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
   * R_last == R^{(k-1)}, R_cur == R^{(k)}
   * R_cur_ij = R_cur_l | R_cur_r
   * R_cur_l == R^{(k-1)}_{ij}
   * R_cur_r == R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
   */

  if ( (GNUNET_YES == R_last_ij->null_flag) &&
       ( (GNUNET_YES == R_last_ik->null_flag) ||
	 (GNUNET_YES == R_last_kj->null_flag)))
  {
    /* R^{(k)}_{ij} = N | N */
    R_cur_ij->null_flag = GNUNET_YES;
    R_cur_ij->synced = GNUNET_NO;
    return;
  }

  if ( (GNUNET_YES == R_last_ik->null_flag) ||
       (GNUNET_YES == R_last_kj->null_flag) )
  {
    /*  R^{(k)}_{ij} = R^{(k-1)}_{ij} | N */
    if (GNUNET_YES == R_last_ij->synced)
    {
      R_cur_ij->synced = GNUNET_YES;
      R_cur_ij->null_flag = GNUNET_NO;
      return;
    }
    R_cur_ij->synced = GNUNET_YES;
    sb_strdup (R_cur_ij, R_last_ij);
    return;
  }
  R_cur_ij->synced = GNUNET_NO;

  /* $R^{(k)}_{ij} = N | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj} OR
   * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj} */

  R_cur_r->null_flag = GNUNET_YES;
  R_cur_r->slen = 0;
  R_cur_l->null_flag = GNUNET_YES;
  R_cur_l->slen = 0;

  /* cache results from strcmp, we might need these many times */
  ij_kj_cmp = sb_nullstrcmp (R_last_ij, R_last_kj);
  ij_ik_cmp = sb_nullstrcmp (R_last_ij, R_last_ik);
  ik_kk_cmp = sb_nullstrcmp (R_last_ik, R_last_kk);
  kk_kj_cmp = sb_nullstrcmp (R_last_kk, R_last_kj);

  /* Assign R_temp_(ik|kk|kj) to R_last[][] and remove epsilon as well
   * as parentheses, so we can better compare the contents */

  memset (&R_temp_ij, 0, sizeof (struct StringBuffer));
  memset (&R_temp_ik, 0, sizeof (struct StringBuffer));
  memset (&R_temp_kk, 0, sizeof (struct StringBuffer));
  memset (&R_temp_kj, 0, sizeof (struct StringBuffer));
  remove_epsilon (R_last_ik, &R_temp_ik);
  remove_epsilon (R_last_kk, &R_temp_kk);
  remove_epsilon (R_last_kj, &R_temp_kj);
  remove_parentheses (&R_temp_ik);
  remove_parentheses (&R_temp_kk);
  remove_parentheses (&R_temp_kj);
  clean_ik_kk_cmp = sb_nullstrcmp (R_last_ik, &R_temp_kk);
  clean_kk_kj_cmp = sb_nullstrcmp (&R_temp_kk, R_last_kj);

  /* construct R_cur_l (and, if necessary R_cur_r) */
  if (GNUNET_YES != R_last_ij->null_flag)
  {
    /* Assign R_temp_ij to R_last_ij and remove epsilon as well
     * as parentheses, so we can better compare the contents */
    remove_epsilon (R_last_ij, &R_temp_ij);
    remove_parentheses (&R_temp_ij);

    if ( (0 == sb_strcmp (&R_temp_ij, &R_temp_ik)) &&
	 (0 == sb_strcmp (&R_temp_ik, &R_temp_kk)) &&
	 (0 == sb_strcmp (&R_temp_kk, &R_temp_kj)) )
    {
      if (0 == R_temp_ij.slen)
      {
        R_cur_r->null_flag = GNUNET_NO;
      }
      else if ((0 == sb_strncmp_cstr (R_last_ij, "(|", 2)) ||
               (0 == sb_strncmp_cstr (R_last_ik, "(|", 2) &&
                0 == sb_strncmp_cstr (R_last_kj, "(|", 2)))
      {
        /*
         * a|(e|a)a*(e|a) = a*
         * a|(e|a)(e|a)*(e|a) = a*
         * (e|a)|aa*a = a*
         * (e|a)|aa*(e|a) = a*
         * (e|a)|(e|a)a*a = a*
         * (e|a)|(e|a)a*(e|a) = a*
         * (e|a)|(e|a)(e|a)*(e|a) = a*
         */
        if (GNUNET_YES == needs_parentheses (&R_temp_ij))
          sb_printf1 (R_cur_r, "(%.*s)*", 3, &R_temp_ij);
        else
          sb_printf1 (R_cur_r, "%.*s*", 1, &R_temp_ij);
      }
      else
      {
        /*
         * a|aa*a = a+
         * a|(e|a)a*a = a+
         * a|aa*(e|a) = a+
         * a|(e|a)(e|a)*a = a+
         * a|a(e|a)*(e|a) = a+
         */
        if (GNUNET_YES == needs_parentheses (&R_temp_ij))
          sb_printf1 (R_cur_r, "(%.*s)+", 3, &R_temp_ij);
        else
          sb_printf1 (R_cur_r, "%.*s+", 1, &R_temp_ij);
      }
    }
    else if ( (0 == ij_ik_cmp) && (0 == clean_kk_kj_cmp) && (0 != clean_ik_kk_cmp) )
    {
      /* a|ab*b = ab* */
      if (0 == R_last_kk->slen)
        sb_strdup (R_cur_r, R_last_ij);
      else if (GNUNET_YES == needs_parentheses (&R_temp_kk))
        sb_printf2 (R_cur_r, "%.*s(%.*s)*", 3, R_last_ij, &R_temp_kk);
      else
        sb_printf2 (R_cur_r, "%.*s%.*s*", 1, R_last_ij, R_last_kk);
      R_cur_l->null_flag = GNUNET_YES;
    }
    else if ( (0 == ij_kj_cmp) && (0 == clean_ik_kk_cmp) && (0 != clean_kk_kj_cmp))
    {
      /* a|bb*a = b*a */
      if (R_last_kk->slen < 1)
      {
        sb_strdup (R_cur_r, R_last_kj);
      }
      else if (GNUNET_YES == needs_parentheses (&R_temp_kk))
        sb_printf2 (R_cur_r, "(%.*s)*%.*s", 3, &R_temp_kk, R_last_kj);
      else
        sb_printf2 (R_cur_r, "%.*s*%.*s", 1, &R_temp_kk, R_last_kj);

      R_cur_l->null_flag = GNUNET_YES;
    }
    else if ( (0 == ij_ik_cmp) && (0 == kk_kj_cmp) && (! has_epsilon (R_last_ij)) &&
	      has_epsilon (R_last_kk))
    {
      /* a|a(e|b)*(e|b) = a|ab* = a|a|ab|abb|abbb|... = ab* */
      if (needs_parentheses (&R_temp_kk))
        sb_printf2 (R_cur_r, "%.*s(%.*s)*", 3, R_last_ij, &R_temp_kk);
      else
        sb_printf2 (R_cur_r, "%.*s%.*s*", 1, R_last_ij, &R_temp_kk);
      R_cur_l->null_flag = GNUNET_YES;
    }
    else if ( (0 == ij_kj_cmp) && (0 == ik_kk_cmp) && (! has_epsilon (R_last_ij)) &&
             has_epsilon (R_last_kk))
    {
      /* a|(e|b)(e|b)*a = a|b*a = a|a|ba|bba|bbba|...  = b*a */
      if (needs_parentheses (&R_temp_kk))
        sb_printf2 (R_cur_r, "(%.*s)*%.*s", 3, &R_temp_kk, R_last_ij);
      else
        sb_printf2 (R_cur_r, "%.*s*%.*s", 1, &R_temp_kk, R_last_ij);
      R_cur_l->null_flag = GNUNET_YES;
    }
    else
    {
      sb_strdup (R_cur_l, R_last_ij);
      remove_parentheses (R_cur_l);
    }
  }
  else
  {
    /* we have no left side */
    R_cur_l->null_flag = GNUNET_YES;
  }

  /* construct R_cur_r, if not already constructed */
  if (GNUNET_YES == R_cur_r->null_flag)
  {
    length = R_temp_kk.slen - R_last_ik->slen;

    /* a(ba)*bx = (ab)+x */
    if ( (length > 0) &&
	 (GNUNET_YES != R_last_kk->null_flag) &&
	 (0 < R_last_kk->slen) &&
	 (GNUNET_YES != R_last_kj->null_flag) &&
	 (0 < R_last_kj->slen) &&
	 (GNUNET_YES != R_last_ik->null_flag) &&
	 (0 < R_last_ik->slen) &&
	 (0 == sb_strkcmp (&R_temp_kk, R_last_ik, length)) &&
	 (0 == sb_strncmp (&R_temp_kk, R_last_kj, length)) )
    {
      struct StringBuffer temp_a;
      struct StringBuffer temp_b;

      sb_init (&temp_a, length);
      sb_init (&temp_b, R_last_kj->slen - length);

      length_l = length;
      temp_a.sbuf = temp_a.abuf;
      memcpy (temp_a.sbuf, R_last_kj->sbuf, length_l);
      temp_a.slen = length_l;

      length_r = R_last_kj->slen - length;
      temp_b.sbuf = temp_b.abuf;
      memcpy (temp_b.sbuf, &R_last_kj->sbuf[length], length_r);
      temp_b.slen = length_r;

      /* e|(ab)+ = (ab)* */
      if ( (GNUNET_YES != R_cur_l->null_flag) &&
	   (0 == R_cur_l->slen) &&
	   (0 == temp_b.slen) )
      {
        sb_printf2 (R_cur_r, "(%.*s%.*s)*", 3, R_last_ik, &temp_a);
        sb_free (R_cur_l);
        R_cur_l->null_flag = GNUNET_YES;
      }
      else
      {
        sb_printf3 (R_cur_r, "(%.*s%.*s)+%.*s", 3, R_last_ik, &temp_a, &temp_b);
      }
      sb_free (&temp_a);
      sb_free (&temp_b);
    }
    else if (0 == sb_strcmp (&R_temp_ik, &R_temp_kk) &&
             0 == sb_strcmp (&R_temp_kk, &R_temp_kj))
    {
      /*
       * (e|a)a*(e|a) = a*
       * (e|a)(e|a)*(e|a) = a*
       */
      if (has_epsilon (R_last_ik) && has_epsilon (R_last_kj))
      {
        if (needs_parentheses (&R_temp_kk))
          sb_printf1 (R_cur_r, "(%.*s)*", 3, &R_temp_kk);
        else
          sb_printf1 (R_cur_r, "%.*s*", 1, &R_temp_kk);
      }
      /* aa*a = a+a */
      else if ( (0 == clean_ik_kk_cmp) &&
		(0 == clean_kk_kj_cmp) &&
		(! has_epsilon (R_last_ik)) )
      {
        if (needs_parentheses (&R_temp_kk))
          sb_printf2 (R_cur_r, "(%.*s)+%.*s", 3, &R_temp_kk, &R_temp_kk);
        else
          sb_printf2 (R_cur_r, "%.*s+%.*s", 1, &R_temp_kk, &R_temp_kk);
      }
      /*
       * (e|a)a*a = a+
       * aa*(e|a) = a+
       * a(e|a)*(e|a) = a+
       * (e|a)a*a = a+
       */
      else
      {
        eps_check =
	  (has_epsilon (R_last_ik) + has_epsilon (R_last_kk) +
	   has_epsilon (R_last_kj));

        if (1 == eps_check)
        {
          if (needs_parentheses (&R_temp_kk))
            sb_printf1 (R_cur_r, "(%.*s)+", 3, &R_temp_kk);
          else
            sb_printf1 (R_cur_r, "%.*s+", 1, &R_temp_kk);
        }
      }
    }
    /*
     * aa*b = a+b
     * (e|a)(e|a)*b = a*b
     */
    else if (0 == sb_strcmp (&R_temp_ik, &R_temp_kk))
    {
      if (has_epsilon (R_last_ik))
      {
        if (needs_parentheses (&R_temp_kk))
          sb_printf2 (R_cur_r, "(%.*s)*%.*s", 3, &R_temp_kk, R_last_kj);
        else
          sb_printf2 (R_cur_r, "%.*s*%.*s", 1, &R_temp_kk, R_last_kj);
      }
      else
      {
        if (needs_parentheses (&R_temp_kk))
          sb_printf2 (R_cur_r, "(%.*s)+%.*s", 3, &R_temp_kk, R_last_kj);
        else
          sb_printf2 (R_cur_r, "%.*s+%.*s", 1, &R_temp_kk, R_last_kj);
      }
    }
    /*
     * ba*a = ba+
     * b(e|a)*(e|a) = ba*
     */
    else if (0 == sb_strcmp (&R_temp_kk, &R_temp_kj))
    {
      if (has_epsilon (R_last_kj))
      {
        if (needs_parentheses (&R_temp_kk))
          sb_printf2 (R_cur_r, "%.*s(%.*s)*", 3, R_last_ik, &R_temp_kk);
        else
          sb_printf2 (R_cur_r, "%.*s%.*s*", 1, R_last_ik, &R_temp_kk);
      }
      else
      {
        if (needs_parentheses (&R_temp_kk))
          sb_printf2 (R_cur_r, "(%.*s)+%.*s", 3, R_last_ik, &R_temp_kk);
        else
          sb_printf2 (R_cur_r, "%.*s+%.*s", 1, R_last_ik, &R_temp_kk);
      }
    }
    else
    {
      if (0 < R_temp_kk.slen)
      {
        if (needs_parentheses (&R_temp_kk))
        {
          sb_printf3 (R_cur_r, "%.*s(%.*s)*%.*s", 3, R_last_ik, &R_temp_kk,
		      R_last_kj);
        }
        else
        {
          sb_printf3 (R_cur_r, "%.*s%.*s*%.*s", 1, R_last_ik, &R_temp_kk,
		      R_last_kj);
        }
      }
      else
      {
	sb_printf2 (R_cur_r, "%.*s%.*s", 0, R_last_ik, R_last_kj);
      }
    }
  }
  sb_free (&R_temp_ij);
  sb_free (&R_temp_ik);
  sb_free (&R_temp_kk);
  sb_free (&R_temp_kj);

  if ( (GNUNET_YES == R_cur_l->null_flag) &&
       (GNUNET_YES == R_cur_r->null_flag) )
  {
    R_cur_ij->null_flag = GNUNET_YES;
    return;
  }

  if ( (GNUNET_YES != R_cur_l->null_flag) &&
       (GNUNET_YES == R_cur_r->null_flag) )
  {
    struct StringBuffer tmp;

    tmp = *R_cur_ij;
    *R_cur_ij = *R_cur_l;
    *R_cur_l = tmp;
    return;
  }

  if ( (GNUNET_YES == R_cur_l->null_flag) &&
       (GNUNET_YES != R_cur_r->null_flag) )
  {
    struct StringBuffer tmp;

    tmp = *R_cur_ij;
    *R_cur_ij = *R_cur_r;
    *R_cur_r = tmp;
    return;
  }

  if (0 == sb_nullstrcmp (R_cur_l, R_cur_r))
  {
    struct StringBuffer tmp;

    tmp = *R_cur_ij;
    *R_cur_ij = *R_cur_l;
    *R_cur_l = tmp;
    return;
  }
  sb_printf2 (R_cur_ij, "(%.*s|%.*s)", 3, R_cur_l, R_cur_r);
}


/**
 * Create proofs for all states in the given automaton. Implementation of the
 * algorithm descriped in chapter 3.2.1 of "Automata Theory, Languages, and
 * Computation 3rd Edition" by Hopcroft, Motwani and Ullman.
 *
 * Each state in the automaton gets assigned 'proof' and 'hash' (hash of the
 * proof) fields. The starting state will only have a valid proof/hash if it has
 * any incoming transitions.
 *
 * @param a automaton for which to assign proofs and hashes, must not be NULL
 */
static int
automaton_create_proofs (struct REGEX_INTERNAL_Automaton *a)
{
  unsigned int n = a->state_count;
  struct REGEX_INTERNAL_State *states[n];
  struct StringBuffer *R_last;
  struct StringBuffer *R_cur;
  struct StringBuffer R_cur_r;
  struct StringBuffer R_cur_l;
  struct StringBuffer *R_swap;
  struct REGEX_INTERNAL_Transition *t;
  struct StringBuffer complete_regex;
  unsigned int i;
  unsigned int j;
  unsigned int k;

  R_last = GNUNET_malloc_large (sizeof (struct StringBuffer) * n * n);
  R_cur = GNUNET_malloc_large (sizeof (struct StringBuffer) * n * n);
  if ( (NULL == R_last) ||
       (NULL == R_cur) )
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "malloc");
    GNUNET_free_non_null (R_cur);
    GNUNET_free_non_null (R_last);
    return GNUNET_SYSERR;
  }

  /* create depth-first numbering of the states, initializes 'state' */
  REGEX_INTERNAL_automaton_traverse (a, a->start, NULL, NULL, &number_states,
                                   states);

  for (i = 0; i < n; i++)
    GNUNET_assert (NULL != states[i]);
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++)
      R_last[i *n + j].null_flag = GNUNET_YES;

  /* Compute regular expressions of length "1" between each pair of states */
  for (i = 0; i < n; i++)
  {
    for (t = states[i]->transitions_head; NULL != t; t = t->next)
    {
      j = t->to_state->dfs_id;
      if (GNUNET_YES == R_last[i * n + j].null_flag)
      {
        sb_strdup_cstr (&R_last[i * n + j], t->label);
      }
      else
      {
	sb_append_cstr (&R_last[i * n + j], "|");
	sb_append_cstr (&R_last[i * n + j], t->label);
      }
    }
    /* add self-loop: i is reachable from i via epsilon-transition */
    if (GNUNET_YES == R_last[i * n + i].null_flag)
    {
      R_last[i * n + i].slen = 0;
      R_last[i * n + i].null_flag = GNUNET_NO;
    }
    else
    {
      sb_wrap (&R_last[i * n + i], "(|%.*s)", 3);
    }
  }
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++)
      if (needs_parentheses (&R_last[i * n + j]))
        sb_wrap (&R_last[i * n + j], "(%.*s)", 2);
  /* Compute regular expressions of length "k" between each pair of states per
   * induction */
  memset (&R_cur_l, 0, sizeof (struct StringBuffer));
  memset (&R_cur_r, 0, sizeof (struct StringBuffer));
  for (k = 0; k < n; k++)
  {
    for (i = 0; i < n; i++)
    {
      for (j = 0; j < n; j++)
      {
        /* Basis for the recursion:
         * $R^{(k)}_{ij} = R^{(k-1)}_{ij} | R^{(k-1)}_{ik} ( R^{(k-1)}_{kk} )^* R^{(k-1)}_{kj}
         * R_last == R^{(k-1)}, R_cur == R^{(k)}
         */

        /* Create R_cur[i][j] and simplify the expression */
        automaton_create_proofs_simplify (&R_last[i * n + j], &R_last[i * n + k],
                                          &R_last[k * n + k], &R_last[k * n + j],
                                          &R_cur[i * n + j],
					  &R_cur_l, &R_cur_r);
      }
    }
    /* set R_last = R_cur */
    R_swap = R_last;
    R_last = R_cur;
    R_cur = R_swap;
    /* clear 'R_cur' for next iteration */
    for (i = 0; i < n; i++)
      for (j = 0; j < n; j++)
        R_cur[i * n + j].null_flag = GNUNET_YES;
  }
  sb_free (&R_cur_l);
  sb_free (&R_cur_r);
  /* assign proofs and hashes */
  for (i = 0; i < n; i++)
  {
    if (GNUNET_YES != R_last[a->start->dfs_id * n + i].null_flag)
    {
      states[i]->proof = GNUNET_strndup (R_last[a->start->dfs_id * n + i].sbuf,
					 R_last[a->start->dfs_id * n + i].slen);
      GNUNET_CRYPTO_hash (states[i]->proof, strlen (states[i]->proof),
                          &states[i]->hash);
    }
  }

  /* complete regex for whole DFA: union of all pairs (start state/accepting
   * state(s)). */
  sb_init (&complete_regex, 16 * n);
  for (i = 0; i < n; i++)
  {
    if (states[i]->accepting)
    {
      if ( (0 == complete_regex.slen) &&
	   (0 < R_last[a->start->dfs_id * n + i].slen) )
      {
	sb_append (&complete_regex,
		   &R_last[a->start->dfs_id * n + i]);
      }
      else if ( (GNUNET_YES != R_last[a->start->dfs_id * n + i].null_flag) &&
		(0 < R_last[a->start->dfs_id * n + i].slen) )
      {
	sb_append_cstr (&complete_regex, "|");
	sb_append (&complete_regex,
		   &R_last[a->start->dfs_id * n + i]);
      }
    }
  }
  a->canonical_regex = GNUNET_strndup (complete_regex.sbuf, complete_regex.slen);

  /* cleanup */
  sb_free (&complete_regex);
  for (i = 0; i < n; i++)
    for (j = 0; j < n; j++)
    {
      sb_free (&R_cur[i * n + j]);
      sb_free (&R_last[i * n + j]);
    }
  GNUNET_free (R_cur);
  GNUNET_free (R_last);
  return GNUNET_OK;
}


/**
 * Creates a new DFA state based on a set of NFA states. Needs to be freed using
 * automaton_destroy_state.
 *
 * @param ctx context
 * @param nfa_states set of NFA states on which the DFA should be based on
 *
 * @return new DFA state
 */
static struct REGEX_INTERNAL_State *
dfa_state_create (struct REGEX_INTERNAL_Context *ctx,
                  struct REGEX_INTERNAL_StateSet *nfa_states)
{
  struct REGEX_INTERNAL_State *s;
  char *pos;
  size_t len;
  struct REGEX_INTERNAL_State *cstate;
  struct REGEX_INTERNAL_Transition *ctran;
  unsigned int i;

  s = GNUNET_new (struct REGEX_INTERNAL_State);
  s->id = ctx->state_id++;
  s->index = -1;
  s->lowlink = -1;

  if (NULL == nfa_states)
  {
    GNUNET_asprintf (&s->name, "s%i", s->id);
    return s;
  }

  s->nfa_set = *nfa_states;

  if (nfa_states->off < 1)
    return s;

  /* Create a name based on 'nfa_states' */
  len = nfa_states->off * 14 + 4;
  s->name = GNUNET_malloc (len);
  strcat (s->name, "{");
  pos = s->name + 1;

  for (i = 0; i < nfa_states->off; i++)
  {
    cstate = nfa_states->states[i];
    GNUNET_snprintf (pos, pos - s->name + len,
		     "%i,", cstate->id);
    pos += strlen (pos);

    /* Add a transition for each distinct label to NULL state */
    for (ctran = cstate->transitions_head; NULL != ctran; ctran = ctran->next)
      if (NULL != ctran->label)
        state_add_transition (ctx, s, ctran->label, NULL);

    /* If the nfa_states contain an accepting state, the new dfa state is also
     * accepting. */
    if (cstate->accepting)
      s->accepting = 1;
  }
  pos[-1] = '}';
  s->name = GNUNET_realloc (s->name, strlen (s->name) + 1);

  memset (nfa_states, 0, sizeof (struct REGEX_INTERNAL_StateSet));
  return s;
}


/**
 * Move from the given state 's' to the next state on transition 'str'. Consumes
 * as much of the given 'str' as possible (usefull for strided DFAs). On return
 * 's' will point to the next state, and the length of the substring used for
 * this transition will be returned. If no transition possible 0 is returned and
 * 's' points to NULL.
 *
 * @param s starting state, will point to the next state or NULL (if no
 * transition possible)
 * @param str edge label to follow (will match longest common prefix)
 *
 * @return length of the substring comsumed from 'str'
 */
static unsigned int
dfa_move (struct REGEX_INTERNAL_State **s, const char *str)
{
  struct REGEX_INTERNAL_Transition *t;
  struct REGEX_INTERNAL_State *new_s;
  unsigned int len;
  unsigned int max_len;

  if (NULL == s)
    return 0;

  new_s = NULL;
  max_len = 0;
  for (t = (*s)->transitions_head; NULL != t; t = t->next)
  {
    len = strlen (t->label);

    if (0 == strncmp (t->label, str, len))
    {
      if (len >= max_len)
      {
        max_len = len;
        new_s = t->to_state;
      }
    }
  }

  *s = new_s;
  return max_len;
}


/**
 * Set the given state 'marked' to GNUNET_YES. Used by the
 * 'dfa_remove_unreachable_states' function to detect unreachable states in the
 * automaton.
 *
 * @param cls closure, not used.
 * @param count count, not used.
 * @param s state where the marked attribute will be set to GNUNET_YES.
 */
static void
mark_states (void *cls, const unsigned int count, struct REGEX_INTERNAL_State *s)
{
  s->marked = GNUNET_YES;
}


/**
 * Remove all unreachable states from DFA 'a'. Unreachable states are those
 * states that are not reachable from the starting state.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_unreachable_states (struct REGEX_INTERNAL_Automaton *a)
{
  struct REGEX_INTERNAL_State *s;
  struct REGEX_INTERNAL_State *s_next;

  /* 1. unmark all states */
  for (s = a->states_head; NULL != s; s = s->next)
    s->marked = GNUNET_NO;

  /* 2. traverse dfa from start state and mark all visited states */
  REGEX_INTERNAL_automaton_traverse (a, a->start, NULL, NULL, &mark_states, NULL);

  /* 3. delete all states that were not visited */
  for (s = a->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;
    if (GNUNET_NO == s->marked)
      automaton_remove_state (a, s);
  }
}


/**
 * Remove all dead states from the DFA 'a'. Dead states are those states that do
 * not transition to any other state but themselves.
 *
 * @param a DFA automaton
 */
static void
dfa_remove_dead_states (struct REGEX_INTERNAL_Automaton *a)
{
  struct REGEX_INTERNAL_State *s;
  struct REGEX_INTERNAL_State *s_next;
  struct REGEX_INTERNAL_Transition *t;
  int dead;

  GNUNET_assert (DFA == a->type);

  for (s = a->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;

    if (s->accepting)
      continue;

    dead = 1;
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->to_state && t->to_state != s)
      {
        dead = 0;
        break;
      }
    }

    if (0 == dead)
      continue;

    /* state s is dead, remove it */
    automaton_remove_state (a, s);
  }
}


/**
 * Merge all non distinguishable states in the DFA 'a'
 *
 * @param ctx context
 * @param a DFA automaton
 * @return GNUNET_OK on success
 */
static int
dfa_merge_nondistinguishable_states (struct REGEX_INTERNAL_Context *ctx,
                                     struct REGEX_INTERNAL_Automaton *a)
{
  uint32_t *table;
  struct REGEX_INTERNAL_State *s1;
  struct REGEX_INTERNAL_State *s2;
  struct REGEX_INTERNAL_Transition *t1;
  struct REGEX_INTERNAL_Transition *t2;
  struct REGEX_INTERNAL_State *s1_next;
  struct REGEX_INTERNAL_State *s2_next;
  int change;
  unsigned int num_equal_edges;
  unsigned int i;
  unsigned int state_cnt;
  unsigned long long idx;
  unsigned long long idx1;

  if ( (NULL == a) || (0 == a->state_count) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not merge nondistinguishable states, automaton was NULL.\n");
    return GNUNET_SYSERR;
  }

  state_cnt = a->state_count;
  table = GNUNET_malloc_large ((sizeof (uint32_t) * state_cnt * state_cnt / 32)  + sizeof (uint32_t));
  if (NULL == table)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "malloc");
    return GNUNET_SYSERR;
  }

  for (i = 0, s1 = a->states_head; NULL != s1; s1 = s1->next)
    s1->marked = i++;

  /* Mark all pairs of accepting/!accepting states */
  for (s1 = a->states_head; NULL != s1; s1 = s1->next)
    for (s2 = a->states_head; NULL != s2; s2 = s2->next)
      if ( (s1->accepting && !s2->accepting) ||
	   (!s1->accepting && s2->accepting) )
      {
	idx = s1->marked * state_cnt + s2->marked;
        table[idx / 32] |= (1 << (idx % 32));
      }

  /* Find all equal states */
  change = 1;
  while (0 != change)
  {
    change = 0;
    for (s1 = a->states_head; NULL != s1; s1 = s1->next)
    {
      for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2->next)
      {
	idx = s1->marked * state_cnt + s2->marked;
        if (0 != (table[idx / 32] & (1 << (idx % 32))))
          continue;
        num_equal_edges = 0;
        for (t1 = s1->transitions_head; NULL != t1; t1 = t1->next)
        {
          for (t2 = s2->transitions_head; NULL != t2; t2 = t2->next)
          {
            if (0 == strcmp (t1->label, t2->label))
	    {
	      num_equal_edges++;
	      /* same edge, but targets definitively different, so we're different
		 as well */
	      if (t1->to_state->marked > t2->to_state->marked)
		idx1 = t1->to_state->marked * state_cnt + t2->to_state->marked;
	      else
		idx1 = t2->to_state->marked * state_cnt + t1->to_state->marked;
	      if (0 != (table[idx1 / 32] & (1 << (idx1 % 32))))
	      {
		table[idx / 32] |= (1 << (idx % 32));
		change = 1; /* changed a marker, need to run again */
	      }
	    }
	  }
        }
        if ( (num_equal_edges != s1->transition_count) ||
	     (num_equal_edges != s2->transition_count) )
        {
          /* Make sure ALL edges of possible equal states are the same */
	  table[idx / 32] |= (1 << (idx % 32));
	  change = 1;  /* changed a marker, need to run again */
        }
      }
    }
  }

  /* Merge states that are equal */
  for (s1 = a->states_head; NULL != s1; s1 = s1_next)
  {
    s1_next = s1->next;
    for (s2 = a->states_head; NULL != s2 && s1 != s2; s2 = s2_next)
    {
      s2_next = s2->next;
      idx = s1->marked * state_cnt + s2->marked;
      if (0 == (table[idx / 32] & (1 << (idx % 32))))
        automaton_merge_states (ctx, a, s1, s2);
    }
  }

  GNUNET_free (table);
  return GNUNET_OK;
}


/**
 * Minimize the given DFA 'a' by removing all unreachable states, removing all
 * dead states and merging all non distinguishable states
 *
 * @param ctx context
 * @param a DFA automaton
 * @return GNUNET_OK on success
 */
static int
dfa_minimize (struct REGEX_INTERNAL_Context *ctx,
              struct REGEX_INTERNAL_Automaton *a)
{
  if (NULL == a)
    return GNUNET_SYSERR;

  GNUNET_assert (DFA == a->type);

  /* 1. remove unreachable states */
  dfa_remove_unreachable_states (a);

  /* 2. remove dead states */
  dfa_remove_dead_states (a);

  /* 3. Merge nondistinguishable states */
  if (GNUNET_OK != dfa_merge_nondistinguishable_states (ctx, a))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Context for adding strided transitions to a DFA.
 */
struct REGEX_INTERNAL_Strided_Context
{
  /**
   * Length of the strides.
   */
  const unsigned int stride;

  /**
   * Strided transitions DLL. New strided transitions will be stored in this DLL
   * and afterwards added to the DFA.
   */
  struct REGEX_INTERNAL_Transition *transitions_head;

  /**
   * Strided transitions DLL.
   */
  struct REGEX_INTERNAL_Transition *transitions_tail;
};


/**
 * Recursive helper function to add strides to a DFA.
 *
 * @param cls context, contains stride length and strided transitions DLL.
 * @param depth current depth of the depth-first traversal of the graph.
 * @param label current label, string that contains all labels on the path from
 *        'start' to 's'.
 * @param start start state for the depth-first traversal of the graph.
 * @param s current state in the depth-first traversal
 */
static void
dfa_add_multi_strides_helper (void *cls, const unsigned int depth, char *label,
                              struct REGEX_INTERNAL_State *start,
                              struct REGEX_INTERNAL_State *s)
{
  struct REGEX_INTERNAL_Strided_Context *ctx = cls;
  struct REGEX_INTERNAL_Transition *t;
  char *new_label;

  if (depth == ctx->stride)
  {
    t = GNUNET_new (struct REGEX_INTERNAL_Transition);
    t->label = GNUNET_strdup (label);
    t->to_state = s;
    t->from_state = start;
    GNUNET_CONTAINER_DLL_insert (ctx->transitions_head, ctx->transitions_tail,
                                 t);
  }
  else
  {
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      /* Do not consider self-loops, because it end's up in too many
       * transitions */
      if (t->to_state == t->from_state)
        continue;

      if (NULL != label)
      {
        GNUNET_asprintf (&new_label, "%s%s", label, t->label);
      }
      else
        new_label = GNUNET_strdup (t->label);

      dfa_add_multi_strides_helper (cls, (depth + 1), new_label, start,
                                    t->to_state);
    }
  }
  GNUNET_free_non_null (label);
}


/**
 * Function called for each state in the DFA. Starts a traversal of depth set in
 * context starting from state 's'.
 *
 * @param cls context.
 * @param count not used.
 * @param s current state.
 */
static void
dfa_add_multi_strides (void *cls, const unsigned int count,
                       struct REGEX_INTERNAL_State *s)
{
  dfa_add_multi_strides_helper (cls, 0, NULL, s, s);
}


/**
 * Adds multi-strided transitions to the given 'dfa'.
 *
 * @param regex_ctx regex context needed to add transitions to the automaton.
 * @param dfa DFA to which the multi strided transitions should be added.
 * @param stride_len length of the strides.
 */
void
REGEX_INTERNAL_dfa_add_multi_strides (struct REGEX_INTERNAL_Context *regex_ctx,
                                    struct REGEX_INTERNAL_Automaton *dfa,
                                    const unsigned int stride_len)
{
  struct REGEX_INTERNAL_Strided_Context ctx = { stride_len, NULL, NULL };
  struct REGEX_INTERNAL_Transition *t;
  struct REGEX_INTERNAL_Transition *t_next;

  if (1 > stride_len || GNUNET_YES == dfa->is_multistrided)
    return;

  /* Compute the new transitions of given stride_len */
  REGEX_INTERNAL_automaton_traverse (dfa, dfa->start, NULL, NULL,
                                   &dfa_add_multi_strides, &ctx);

  /* Add all the new transitions to the automaton. */
  for (t = ctx.transitions_head; NULL != t; t = t_next)
  {
    t_next = t->next;
    state_add_transition (regex_ctx, t->from_state, t->label, t->to_state);
    GNUNET_CONTAINER_DLL_remove (ctx.transitions_head, ctx.transitions_tail, t);
    GNUNET_free_non_null (t->label);
    GNUNET_free (t);
  }

  /* Mark this automaton as multistrided */
  dfa->is_multistrided = GNUNET_YES;
}

/**
 * Recursive Helper function for DFA path compression. Does DFS on the DFA graph
 * and adds new transitions to the given transitions DLL and marks states that
 * should be removed by setting state->contained to GNUNET_YES.
 *
 * @param dfa DFA for which the paths should be compressed.
 * @param start starting state for linear path search.
 * @param cur current state in the recursive DFS.
 * @param label current label (string of traversed labels).
 * @param max_len maximal path compression length.
 * @param transitions_head transitions DLL.
 * @param transitions_tail transitions DLL.
 */
void
dfa_compress_paths_helper (struct REGEX_INTERNAL_Automaton *dfa,
                           struct REGEX_INTERNAL_State *start,
                           struct REGEX_INTERNAL_State *cur, char *label,
                           unsigned int max_len,
                           struct REGEX_INTERNAL_Transition **transitions_head,
                           struct REGEX_INTERNAL_Transition **transitions_tail)
{
  struct REGEX_INTERNAL_Transition *t;
  char *new_label;


  if (NULL != label &&
      ((cur->incoming_transition_count > 1 || GNUNET_YES == cur->accepting ||
        GNUNET_YES == cur->marked) || (start != dfa->start && max_len > 0 &&
                                       max_len == strlen (label)) ||
       (start == dfa->start && GNUNET_REGEX_INITIAL_BYTES == strlen (label))))
  {
    t = GNUNET_new (struct REGEX_INTERNAL_Transition);
    t->label = GNUNET_strdup (label);
    t->to_state = cur;
    t->from_state = start;
    GNUNET_CONTAINER_DLL_insert (*transitions_head, *transitions_tail, t);

    if (GNUNET_NO == cur->marked)
    {
      dfa_compress_paths_helper (dfa, cur, cur, NULL, max_len, transitions_head,
                                 transitions_tail);
    }
    return;
  }
  else if (cur != start)
    cur->contained = GNUNET_YES;

  if (GNUNET_YES == cur->marked && cur != start)
    return;

  cur->marked = GNUNET_YES;


  for (t = cur->transitions_head; NULL != t; t = t->next)
  {
    if (NULL != label)
      GNUNET_asprintf (&new_label, "%s%s", label, t->label);
    else
      new_label = GNUNET_strdup (t->label);

    if (t->to_state != cur)
    {
      dfa_compress_paths_helper (dfa, start, t->to_state, new_label, max_len,
                                 transitions_head, transitions_tail);
    }
    GNUNET_free (new_label);
  }
}


/**
 * Compress paths in the given 'dfa'. Linear paths like 0->1->2->3 will be
 * compressed to 0->3 by combining transitions.
 *
 * @param regex_ctx context for adding new transitions.
 * @param dfa DFA representation, will directly modify the given DFA.
 * @param max_len maximal length of the compressed paths.
 */
static void
dfa_compress_paths (struct REGEX_INTERNAL_Context *regex_ctx,
                    struct REGEX_INTERNAL_Automaton *dfa, unsigned int max_len)
{
  struct REGEX_INTERNAL_State *s;
  struct REGEX_INTERNAL_State *s_next;
  struct REGEX_INTERNAL_Transition *t;
  struct REGEX_INTERNAL_Transition *t_next;
  struct REGEX_INTERNAL_Transition *transitions_head = NULL;
  struct REGEX_INTERNAL_Transition *transitions_tail = NULL;

  if (NULL == dfa)
    return;

  /* Count the incoming transitions on each state. */
  for (s = dfa->states_head; NULL != s; s = s->next)
  {
    for (t = s->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != t->to_state)
        t->to_state->incoming_transition_count++;
    }
  }

  /* Unmark all states. */
  for (s = dfa->states_head; NULL != s; s = s->next)
  {
    s->marked = GNUNET_NO;
    s->contained = GNUNET_NO;
  }

  /* Add strides and mark states that can be deleted. */
  dfa_compress_paths_helper (dfa, dfa->start, dfa->start, NULL, max_len,
                             &transitions_head, &transitions_tail);

  /* Add all the new transitions to the automaton. */
  for (t = transitions_head; NULL != t; t = t_next)
  {
    t_next = t->next;
    state_add_transition (regex_ctx, t->from_state, t->label, t->to_state);
    GNUNET_CONTAINER_DLL_remove (transitions_head, transitions_tail, t);
    GNUNET_free_non_null (t->label);
    GNUNET_free (t);
  }

  /* Remove marked states (including their incoming and outgoing transitions). */
  for (s = dfa->states_head; NULL != s; s = s_next)
  {
    s_next = s->next;
    if (GNUNET_YES == s->contained)
      automaton_remove_state (dfa, s);
  }
}


/**
 * Creates a new NFA fragment. Needs to be cleared using
 * automaton_fragment_clear.
 *
 * @param start starting state
 * @param end end state
 *
 * @return new NFA fragment
 */
static struct REGEX_INTERNAL_Automaton *
nfa_fragment_create (struct REGEX_INTERNAL_State *start,
                     struct REGEX_INTERNAL_State *end)
{
  struct REGEX_INTERNAL_Automaton *n;

  n = GNUNET_new (struct REGEX_INTERNAL_Automaton);

  n->type = NFA;
  n->start = NULL;
  n->end = NULL;
  n->state_count = 0;

  if (NULL == start || NULL == end)
    return n;

  automaton_add_state (n, end);
  automaton_add_state (n, start);

  n->state_count = 2;

  n->start = start;
  n->end = end;

  return n;
}


/**
 * Adds a list of states to the given automaton 'n'.
 *
 * @param n automaton to which the states should be added
 * @param states_head head of the DLL of states
 * @param states_tail tail of the DLL of states
 */
static void
nfa_add_states (struct REGEX_INTERNAL_Automaton *n,
                struct REGEX_INTERNAL_State *states_head,
                struct REGEX_INTERNAL_State *states_tail)
{
  struct REGEX_INTERNAL_State *s;

  if (NULL == n || NULL == states_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not add states\n");
    return;
  }

  if (NULL == n->states_head)
  {
    n->states_head = states_head;
    n->states_tail = states_tail;
    return;
  }

  if (NULL != states_head)
  {
    n->states_tail->next = states_head;
    n->states_tail = states_tail;
  }

  for (s = states_head; NULL != s; s = s->next)
    n->state_count++;
}


/**
 * Creates a new NFA state. Needs to be freed using automaton_destroy_state.
 *
 * @param ctx context
 * @param accepting is it an accepting state or not
 *
 * @return new NFA state
 */
static struct REGEX_INTERNAL_State *
nfa_state_create (struct REGEX_INTERNAL_Context *ctx, int accepting)
{
  struct REGEX_INTERNAL_State *s;

  s = GNUNET_new (struct REGEX_INTERNAL_State);
  s->id = ctx->state_id++;
  s->accepting = accepting;
  s->marked = GNUNET_NO;
  s->contained = 0;
  s->index = -1;
  s->lowlink = -1;
  s->scc_id = 0;
  s->name = NULL;
  GNUNET_asprintf (&s->name, "s%i", s->id);

  return s;
}


/**
 * Calculates the closure set for the given set of states.
 *
 * @param ret set to sorted nfa closure on 'label' (epsilon closure if 'label' is NULL)
 * @param nfa the NFA containing 's'
 * @param states list of states on which to base the closure on
 * @param label transitioning label for which to base the closure on,
 *                pass NULL for epsilon transition
 */
static void
nfa_closure_set_create (struct REGEX_INTERNAL_StateSet *ret,
			struct REGEX_INTERNAL_Automaton *nfa,
                        struct REGEX_INTERNAL_StateSet *states, const char *label)
{
  struct REGEX_INTERNAL_State *s;
  unsigned int i;
  struct REGEX_INTERNAL_StateSet_MDLL cls_stack;
  struct REGEX_INTERNAL_State *clsstate;
  struct REGEX_INTERNAL_State *currentstate;
  struct REGEX_INTERNAL_Transition *ctran;

  memset (ret, 0, sizeof (struct REGEX_INTERNAL_StateSet));
  if (NULL == states)
    return;

  for (i = 0; i < states->off; i++)
  {
    s = states->states[i];

    /* Add start state to closure only for epsilon closure */
    if (NULL == label)
      state_set_append (ret, s);

    /* initialize work stack */
    cls_stack.head = NULL;
    cls_stack.tail = NULL;
    GNUNET_CONTAINER_MDLL_insert (ST, cls_stack.head, cls_stack.tail, s);
    cls_stack.len = 1;

    while (NULL != (currentstate = cls_stack.tail))
    {
      GNUNET_CONTAINER_MDLL_remove (ST, cls_stack.head, cls_stack.tail,
				    currentstate);
      cls_stack.len--;
      for (ctran = currentstate->transitions_head; NULL != ctran;
	   ctran = ctran->next)
      {
	if (NULL == (clsstate = ctran->to_state))
	  continue;
	if (0 != clsstate->contained)
	  continue;
	if (0 != nullstrcmp (label, ctran->label))
	  continue;
	state_set_append (ret, clsstate);
	GNUNET_CONTAINER_MDLL_insert_tail (ST, cls_stack.head, cls_stack.tail,
					   clsstate);
	cls_stack.len++;
	clsstate->contained = 1;
      }
    }
  }
  for (i = 0; i < ret->off; i++)
    ret->states[i]->contained = 0;

  if (ret->off > 1)
    qsort (ret->states, ret->off, sizeof (struct REGEX_INTERNAL_State *),
           &state_compare);
}


/**
 * Pops two NFA fragments (a, b) from the stack and concatenates them (ab)
 *
 * @param ctx context
 */
static void
nfa_add_concatenation (struct REGEX_INTERNAL_Context *ctx)
{
  struct REGEX_INTERNAL_Automaton *a;
  struct REGEX_INTERNAL_Automaton *b;
  struct REGEX_INTERNAL_Automaton *new_nfa;

  b = ctx->stack_tail;
  GNUNET_assert (NULL != b);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_assert (NULL != a);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, NULL, b->start);
  a->end->accepting = 0;
  b->end->accepting = 1;

  new_nfa = nfa_fragment_create (NULL, NULL);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  nfa_add_states (new_nfa, b->states_head, b->states_tail);
  new_nfa->start = a->start;
  new_nfa->end = b->end;
  new_nfa->state_count += a->state_count + b->state_count;
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Pops a NFA fragment from the stack (a) and adds a new fragment (a*)
 *
 * @param ctx context
 */
static void
nfa_add_star_op (struct REGEX_INTERNAL_Context *ctx)
{
  struct REGEX_INTERNAL_Automaton *a;
  struct REGEX_INTERNAL_Automaton *new_nfa;
  struct REGEX_INTERNAL_State *start;
  struct REGEX_INTERNAL_State *end;

  a = ctx->stack_tail;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_star_op failed, because there was no element on the stack");
    return;
  }

  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, NULL, a->start);
  state_add_transition (ctx, start, NULL, end);
  state_add_transition (ctx, a->end, NULL, a->start);
  state_add_transition (ctx, a->end, NULL, end);

  a->end->accepting = 0;
  end->accepting = 1;

  new_nfa = nfa_fragment_create (start, end);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  automaton_fragment_clear (a);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Pops an NFA fragment (a) from the stack and adds a new fragment (a+)
 *
 * @param ctx context
 */
static void
nfa_add_plus_op (struct REGEX_INTERNAL_Context *ctx)
{
  struct REGEX_INTERNAL_Automaton *a;

  a = ctx->stack_tail;

  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_plus_op failed, because there was no element on the stack");
    return;
  }

  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  state_add_transition (ctx, a->end, NULL, a->start);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, a);
}


/**
 * Pops an NFA fragment (a) from the stack and adds a new fragment (a?)
 *
 * @param ctx context
 */
static void
nfa_add_question_op (struct REGEX_INTERNAL_Context *ctx)
{
  struct REGEX_INTERNAL_Automaton *a;
  struct REGEX_INTERNAL_Automaton *new_nfa;
  struct REGEX_INTERNAL_State *start;
  struct REGEX_INTERNAL_State *end;

  a = ctx->stack_tail;
  if (NULL == a)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "nfa_add_question_op failed, because there was no element on the stack");
    return;
  }

  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);

  state_add_transition (ctx, start, NULL, a->start);
  state_add_transition (ctx, start, NULL, end);
  state_add_transition (ctx, a->end, NULL, end);

  a->end->accepting = 0;

  new_nfa = nfa_fragment_create (start, end);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
  automaton_fragment_clear (a);
}


/**
 * Pops two NFA fragments (a, b) from the stack and adds a new NFA fragment that
 * alternates between a and b (a|b)
 *
 * @param ctx context
 */
static void
nfa_add_alternation (struct REGEX_INTERNAL_Context *ctx)
{
  struct REGEX_INTERNAL_Automaton *a;
  struct REGEX_INTERNAL_Automaton *b;
  struct REGEX_INTERNAL_Automaton *new_nfa;
  struct REGEX_INTERNAL_State *start;
  struct REGEX_INTERNAL_State *end;

  b = ctx->stack_tail;
  GNUNET_assert (NULL != b);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, b);
  a = ctx->stack_tail;
  GNUNET_assert (NULL != a);
  GNUNET_CONTAINER_DLL_remove (ctx->stack_head, ctx->stack_tail, a);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, NULL, a->start);
  state_add_transition (ctx, start, NULL, b->start);

  state_add_transition (ctx, a->end, NULL, end);
  state_add_transition (ctx, b->end, NULL, end);

  a->end->accepting = 0;
  b->end->accepting = 0;
  end->accepting = 1;

  new_nfa = nfa_fragment_create (start, end);
  nfa_add_states (new_nfa, a->states_head, a->states_tail);
  nfa_add_states (new_nfa, b->states_head, b->states_tail);
  automaton_fragment_clear (a);
  automaton_fragment_clear (b);

  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, new_nfa);
}


/**
 * Adds a new nfa fragment to the stack
 *
 * @param ctx context
 * @param label label for nfa transition
 */
static void
nfa_add_label (struct REGEX_INTERNAL_Context *ctx, const char *label)
{
  struct REGEX_INTERNAL_Automaton *n;
  struct REGEX_INTERNAL_State *start;
  struct REGEX_INTERNAL_State *end;

  GNUNET_assert (NULL != ctx);

  start = nfa_state_create (ctx, 0);
  end = nfa_state_create (ctx, 1);
  state_add_transition (ctx, start, label, end);
  n = nfa_fragment_create (start, end);
  GNUNET_assert (NULL != n);
  GNUNET_CONTAINER_DLL_insert_tail (ctx->stack_head, ctx->stack_tail, n);
}


/**
 * Initialize a new context
 *
 * @param ctx context
 */
static void
REGEX_INTERNAL_context_init (struct REGEX_INTERNAL_Context *ctx)
{
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Context was NULL!");
    return;
  }
  ctx->state_id = 0;
  ctx->transition_id = 0;
  ctx->stack_head = NULL;
  ctx->stack_tail = NULL;
}


/**
 * Construct an NFA by parsing the regex string of length 'len'.
 *
 * @param regex regular expression string
 * @param len length of the string
 *
 * @return NFA, needs to be freed using REGEX_INTERNAL_destroy_automaton
 */
struct REGEX_INTERNAL_Automaton *
REGEX_INTERNAL_construct_nfa (const char *regex, const size_t len)
{
  struct REGEX_INTERNAL_Context ctx;
  struct REGEX_INTERNAL_Automaton *nfa;
  const char *regexp;
  char curlabel[2];
  char *error_msg;
  unsigned int count;
  unsigned int altcount;
  unsigned int atomcount;
  unsigned int poff;
  unsigned int psize;
  struct
  {
    int altcount;
    int atomcount;
  }     *p;

  if (NULL == regex || 0 == strlen (regex) || 0 == len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not parse regex. Empty regex string provided.\n");

    return NULL;
  }
  REGEX_INTERNAL_context_init (&ctx);

  regexp = regex;
  curlabel[1] = '\0';
  p = NULL;
  error_msg = NULL;
  altcount = 0;
  atomcount = 0;
  poff = 0;
  psize = 0;

  for (count = 0; count < len && *regexp; count++, regexp++)
  {
    switch (*regexp)
    {
    case '(':
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      if (poff == psize)
        GNUNET_array_grow (p, psize, psize * 2 + 4); /* FIXME why *2 +4? */
      p[poff].altcount = altcount;
      p[poff].atomcount = atomcount;
      poff++;
      altcount = 0;
      atomcount = 0;
      break;
    case '|':
      if (0 == atomcount)
      {
        error_msg = "Cannot append '|' to nothing";
        goto error;
      }
      while (--atomcount > 0)
        nfa_add_concatenation (&ctx);
      altcount++;
      break;
    case ')':
      if (0 == poff)
      {
        error_msg = "Missing opening '('";
        goto error;
      }
      if (0 == atomcount)
      {
        /* Ignore this: "()" */
        poff--;
        altcount = p[poff].altcount;
        atomcount = p[poff].atomcount;
        break;
      }
      while (--atomcount > 0)
        nfa_add_concatenation (&ctx);
      for (; altcount > 0; altcount--)
        nfa_add_alternation (&ctx);
      poff--;
      altcount = p[poff].altcount;
      atomcount = p[poff].atomcount;
      atomcount++;
      break;
    case '*':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '*' to nothing";
        goto error;
      }
      nfa_add_star_op (&ctx);
      break;
    case '+':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '+' to nothing";
        goto error;
      }
      nfa_add_plus_op (&ctx);
      break;
    case '?':
      if (atomcount == 0)
      {
        error_msg = "Cannot append '?' to nothing";
        goto error;
      }
      nfa_add_question_op (&ctx);
      break;
    default:
      if (atomcount > 1)
      {
        --atomcount;
        nfa_add_concatenation (&ctx);
      }
      curlabel[0] = *regexp;
      nfa_add_label (&ctx, curlabel);
      atomcount++;
      break;
    }
  }
  if (0 != poff)
  {
    error_msg = "Unbalanced parenthesis";
    goto error;
  }
  while (--atomcount > 0)
    nfa_add_concatenation (&ctx);
  for (; altcount > 0; altcount--)
    nfa_add_alternation (&ctx);

  GNUNET_array_grow (p, psize, 0);

  nfa = ctx.stack_tail;
  GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);

  if (NULL != ctx.stack_head)
  {
    error_msg = "Creating the NFA failed. NFA stack was not empty!";
    goto error;
  }

  /* Remember the regex that was used to generate this NFA */
  nfa->regex = GNUNET_strdup (regex);

  /* create depth-first numbering of the states for pretty printing */
  REGEX_INTERNAL_automaton_traverse (nfa, NULL, NULL, NULL, &number_states, NULL);

  /* No multistriding added so far */
  nfa->is_multistrided = GNUNET_NO;

  return nfa;

error:
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not parse regex: `%s'\n", regex);
  if (NULL != error_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", error_msg);

  GNUNET_free_non_null (p);

  while (NULL != (nfa = ctx.stack_head))
  {
    GNUNET_CONTAINER_DLL_remove (ctx.stack_head, ctx.stack_tail, nfa);
    REGEX_INTERNAL_automaton_destroy (nfa);
  }

  return NULL;
}


/**
 * Create DFA states based on given 'nfa' and starting with 'dfa_state'.
 *
 * @param ctx context.
 * @param nfa NFA automaton.
 * @param dfa DFA automaton.
 * @param dfa_state current dfa state, pass epsilon closure of first nfa state
 *                  for starting.
 */
static void
construct_dfa_states (struct REGEX_INTERNAL_Context *ctx,
                      struct REGEX_INTERNAL_Automaton *nfa,
                      struct REGEX_INTERNAL_Automaton *dfa,
                      struct REGEX_INTERNAL_State *dfa_state)
{
  struct REGEX_INTERNAL_Transition *ctran;
  struct REGEX_INTERNAL_State *new_dfa_state;
  struct REGEX_INTERNAL_State *state_contains;
  struct REGEX_INTERNAL_State *state_iter;
  struct REGEX_INTERNAL_StateSet tmp;
  struct REGEX_INTERNAL_StateSet nfa_set;

  for (ctran = dfa_state->transitions_head; NULL != ctran; ctran = ctran->next)
  {
    if (NULL == ctran->label || NULL != ctran->to_state)
      continue;

    nfa_closure_set_create (&tmp, nfa, &dfa_state->nfa_set, ctran->label);
    nfa_closure_set_create (&nfa_set, nfa, &tmp, NULL);
    state_set_clear (&tmp);

    state_contains = NULL;
    for (state_iter = dfa->states_head; NULL != state_iter;
         state_iter = state_iter->next)
    {
      if (0 == state_set_compare (&state_iter->nfa_set, &nfa_set))
      {
        state_contains = state_iter;
	break;
      }
    }
    if (NULL == state_contains)
    {
      new_dfa_state = dfa_state_create (ctx, &nfa_set);
      automaton_add_state (dfa, new_dfa_state);
      ctran->to_state = new_dfa_state;
      construct_dfa_states (ctx, nfa, dfa, new_dfa_state);
    }
    else
    {
      ctran->to_state = state_contains;
      state_set_clear (&nfa_set);
    }
  }
}


/**
 * Construct DFA for the given 'regex' of length 'len'.
 *
 * Path compression means, that for example a DFA o -> a -> b -> c -> o will be
 * compressed to o -> abc -> o. Note that this parameter influences the
 * non-determinism of states of the resulting NFA in the DHT (number of outgoing
 * edges with the same label). For example for an application that stores IPv4
 * addresses as bitstrings it could make sense to limit the path compression to
 * 4 or 8.
 *
 * @param regex regular expression string.
 * @param len length of the regular expression.
 * @param max_path_len limit the path compression length to the
 *        given value. If set to 1, no path compression is applied. Set to 0 for
 *        maximal possible path compression (generally not desireable).
 * @return DFA, needs to be freed using REGEX_INTERNAL_automaton_destroy.
 */
struct REGEX_INTERNAL_Automaton *
REGEX_INTERNAL_construct_dfa (const char *regex, const size_t len,
                              unsigned int max_path_len)
{
  struct REGEX_INTERNAL_Context ctx;
  struct REGEX_INTERNAL_Automaton *dfa;
  struct REGEX_INTERNAL_Automaton *nfa;
  struct REGEX_INTERNAL_StateSet nfa_start_eps_cls;
  struct REGEX_INTERNAL_StateSet singleton_set;

  REGEX_INTERNAL_context_init (&ctx);

  /* Create NFA */
  nfa = REGEX_INTERNAL_construct_nfa (regex, len);

  if (NULL == nfa)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not create DFA, because NFA creation failed\n");
    return NULL;
  }

  dfa = GNUNET_new (struct REGEX_INTERNAL_Automaton);
  dfa->type = DFA;
  dfa->regex = GNUNET_strdup (regex);

  /* Create DFA start state from epsilon closure */
  memset (&singleton_set, 0, sizeof (struct REGEX_INTERNAL_StateSet));
  state_set_append (&singleton_set, nfa->start);
  nfa_closure_set_create (&nfa_start_eps_cls, nfa, &singleton_set, NULL);
  state_set_clear (&singleton_set);
  dfa->start = dfa_state_create (&ctx, &nfa_start_eps_cls);
  automaton_add_state (dfa, dfa->start);

  construct_dfa_states (&ctx, nfa, dfa, dfa->start);
  REGEX_INTERNAL_automaton_destroy (nfa);

  /* Minimize DFA */
  if (GNUNET_OK != dfa_minimize (&ctx, dfa))
  {
    REGEX_INTERNAL_automaton_destroy (dfa);
    return NULL;
  }

  /* Create proofs and hashes for all states */
  if (GNUNET_OK != automaton_create_proofs (dfa))
  {
    REGEX_INTERNAL_automaton_destroy (dfa);
    return NULL;
  }

  /* Compress linear DFA paths */
  if (1 != max_path_len)
    dfa_compress_paths (&ctx, dfa, max_path_len);

  return dfa;
}


/**
 * Free the memory allocated by constructing the REGEX_INTERNAL_Automaton data
 * structure.
 *
 * @param a automaton to be destroyed
 */
void
REGEX_INTERNAL_automaton_destroy (struct REGEX_INTERNAL_Automaton *a)
{
  struct REGEX_INTERNAL_State *s;
  struct REGEX_INTERNAL_State *next_state;

  if (NULL == a)
    return;

  GNUNET_free_non_null (a->regex);
  GNUNET_free_non_null (a->canonical_regex);

  for (s = a->states_head; NULL != s; s = next_state)
  {
    next_state = s->next;
    GNUNET_CONTAINER_DLL_remove (a->states_head, a->states_tail, s);
    automaton_destroy_state (s);
  }

  GNUNET_free (a);
}


/**
 * Evaluates the given string using the given DFA automaton
 *
 * @param a automaton, type must be DFA
 * @param string string that should be evaluated
 *
 * @return 0 if string matches, non 0 otherwise
 */
static int
evaluate_dfa (struct REGEX_INTERNAL_Automaton *a, const char *string)
{
  const char *strp;
  struct REGEX_INTERNAL_State *s;
  unsigned int step_len;

  if (DFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate DFA, but NFA automaton given");
    return -1;
  }

  s = a->start;

  /* If the string is empty but the starting state is accepting, we accept. */
  if ((NULL == string || 0 == strlen (string)) && s->accepting)
    return 0;

  for (strp = string; NULL != strp && *strp; strp += step_len)
  {
    step_len = dfa_move (&s, strp);

    if (NULL == s)
      break;
  }

  if (NULL != s && s->accepting)
    return 0;

  return 1;
}


/**
 * Evaluates the given string using the given NFA automaton
 *
 * @param a automaton, type must be NFA
 * @param string string that should be evaluated
 *
 * @return 0 if string matches, non 0 otherwise
 */
static int
evaluate_nfa (struct REGEX_INTERNAL_Automaton *a, const char *string)
{
  const char *strp;
  char str[2];
  struct REGEX_INTERNAL_State *s;
  struct REGEX_INTERNAL_StateSet sset;
  struct REGEX_INTERNAL_StateSet new_sset;
  struct REGEX_INTERNAL_StateSet singleton_set;
  unsigned int i;
  int result;

  if (NFA != a->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Tried to evaluate NFA, but DFA automaton given");
    return -1;
  }

  /* If the string is empty but the starting state is accepting, we accept. */
  if ((NULL == string || 0 == strlen (string)) && a->start->accepting)
    return 0;

  result = 1;
  memset (&singleton_set, 0, sizeof (struct REGEX_INTERNAL_StateSet));
  state_set_append (&singleton_set, a->start);
  nfa_closure_set_create (&sset, a, &singleton_set, NULL);
  state_set_clear (&singleton_set);

  str[1] = '\0';
  for (strp = string; NULL != strp && *strp; strp++)
  {
    str[0] = *strp;
    nfa_closure_set_create (&new_sset, a, &sset, str);
    state_set_clear (&sset);
    nfa_closure_set_create (&sset, a, &new_sset, 0);
    state_set_clear (&new_sset);
  }

  for (i = 0; i < sset.off; i++)
  {
    s = sset.states[i];
    if ( (NULL != s) && (s->accepting) )
    {
      result = 0;
      break;
    }
  }

  state_set_clear (&sset);
  return result;
}


/**
 * Evaluates the given 'string' against the given compiled regex
 *
 * @param a automaton
 * @param string string to check
 *
 * @return 0 if string matches, non 0 otherwise
 */
int
REGEX_INTERNAL_eval (struct REGEX_INTERNAL_Automaton *a, const char *string)
{
  int result;

  switch (a->type)
  {
  case DFA:
    result = evaluate_dfa (a, string);
    break;
  case NFA:
    result = evaluate_nfa (a, string);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Evaluating regex failed, automaton has no type!\n");
    result = GNUNET_SYSERR;
    break;
  }

  return result;
}


/**
 * Get the canonical regex of the given automaton.
 * When constructing the automaton a proof is computed for each state,
 * consisting of the regular expression leading to this state. A complete
 * regex for the automaton can be computed by combining these proofs.
 * As of now this function is only useful for testing.
 *
 * @param a automaton for which the canonical regex should be returned.
 *
 * @return
 */
const char *
REGEX_INTERNAL_get_canonical_regex (struct REGEX_INTERNAL_Automaton *a)
{
  if (NULL == a)
    return NULL;

  return a->canonical_regex;
}


/**
 * Get the number of transitions that are contained in the given automaton.
 *
 * @param a automaton for which the number of transitions should be returned.
 *
 * @return number of transitions in the given automaton.
 */
unsigned int
REGEX_INTERNAL_get_transition_count (struct REGEX_INTERNAL_Automaton *a)
{
  unsigned int t_count;
  struct REGEX_INTERNAL_State *s;

  if (NULL == a)
    return 0;

  t_count = 0;
  for (s = a->states_head; NULL != s; s = s->next)
    t_count += s->transition_count;

  return t_count;
}


/**
 * Get the first key for the given 'input_string'. This hashes the first x bits
 * of the 'input_string'.
 *
 * @param input_string string.
 * @param string_len length of the 'input_string'.
 * @param key pointer to where to write the hash code.
 *
 * @return number of bits of 'input_string' that have been consumed
 *         to construct the key
 */
size_t
REGEX_INTERNAL_get_first_key (const char *input_string, size_t string_len,
                            struct GNUNET_HashCode * key)
{
  size_t size;

  size = string_len < GNUNET_REGEX_INITIAL_BYTES ? string_len :
                                                   GNUNET_REGEX_INITIAL_BYTES;
  if (NULL == input_string)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Given input string was NULL!\n");
    return 0;
  }
  GNUNET_CRYPTO_hash (input_string, size, key);

  return size;
}


/**
 * Recursive function that calls the iterator for each synthetic start state.
 *
 * @param min_len minimum length of the path in the graph.
 * @param max_len maximum length of the path in the graph.
 * @param consumed_string string consumed by traversing the graph till this state.
 * @param state current state of the automaton.
 * @param iterator iterator function called for each edge.
 * @param iterator_cls closure for the iterator function.
 */
static void
iterate_initial_edge (const unsigned int min_len, const unsigned int max_len,
                      char *consumed_string, struct REGEX_INTERNAL_State *state,
                      REGEX_INTERNAL_KeyIterator iterator, void *iterator_cls)
{
  char *temp;
  struct REGEX_INTERNAL_Transition *t;
  unsigned int num_edges = state->transition_count;
  struct REGEX_BLOCK_Edge edges[num_edges];
  struct REGEX_BLOCK_Edge edge[1];
  struct GNUNET_HashCode hash;
  struct GNUNET_HashCode hash_new;
  unsigned int cur_len;

  if (NULL != consumed_string)
    cur_len = strlen (consumed_string);
  else
    cur_len = 0;

  if ((cur_len >= min_len || GNUNET_YES == state->accepting) && cur_len > 0 &&
      NULL != consumed_string)
  {
    if (cur_len <= max_len)
    {
      if (state->proof != NULL && 0 != strcmp (consumed_string, state->proof))
      {
        (void) state_get_edges (state, edges);
        GNUNET_CRYPTO_hash (consumed_string, strlen (consumed_string), &hash);
        iterator (iterator_cls, &hash, consumed_string, state->accepting,
                  num_edges, edges);
      }

      if (GNUNET_YES == state->accepting && cur_len > 1 &&
          state->transition_count < 1 && cur_len < max_len)
      {
        /* Special case for regex consisting of just a string that is shorter than
         * max_len */
        edge[0].label = &consumed_string[cur_len - 1];
        edge[0].destination = state->hash;
        temp = GNUNET_strdup (consumed_string);
        temp[cur_len - 1] = '\0';
        GNUNET_CRYPTO_hash (temp, cur_len - 1, &hash_new);
        iterator (iterator_cls, &hash_new, temp, GNUNET_NO, 1, edge);
        GNUNET_free (temp);
      }
    }
    else /* cur_len > max_len */
    {
      /* Case where the concatenated labels are longer than max_len, then split. */
      edge[0].label = &consumed_string[max_len];
      edge[0].destination = state->hash;
      temp = GNUNET_strdup (consumed_string);
      temp[max_len] = '\0';
      GNUNET_CRYPTO_hash (temp, max_len, &hash);
      iterator (iterator_cls, &hash, temp, GNUNET_NO, 1, edge);
      GNUNET_free (temp);
    }
  }

  if (cur_len < max_len)
  {
    for (t = state->transitions_head; NULL != t; t = t->next)
    {
      if (NULL != consumed_string)
        GNUNET_asprintf (&temp, "%s%s", consumed_string, t->label);
      else
        GNUNET_asprintf (&temp, "%s", t->label);

      iterate_initial_edge (min_len, max_len, temp, t->to_state, iterator,
                            iterator_cls);
      GNUNET_free (temp);
    }
  }
}


/**
 * Iterate over all edges starting from start state of automaton 'a'. Calling
 * iterator for each edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each edge.
 * @param iterator_cls closure.
 */
void
REGEX_INTERNAL_iterate_all_edges (struct REGEX_INTERNAL_Automaton *a,
                                  REGEX_INTERNAL_KeyIterator iterator,
                                  void *iterator_cls)
{
  struct REGEX_INTERNAL_State *s;

  for (s = a->states_head; NULL != s; s = s->next)
  {
    struct REGEX_BLOCK_Edge edges[s->transition_count];
    unsigned int num_edges;

    num_edges = state_get_edges (s, edges);
    if ( ( (NULL != s->proof) &&
           (0 < strlen (s->proof)) ) || s->accepting)
      iterator (iterator_cls, &s->hash, s->proof,
                s->accepting,
                num_edges, edges);
    s->marked = GNUNET_NO;
  }

  iterate_initial_edge (GNUNET_REGEX_INITIAL_BYTES,
                        GNUNET_REGEX_INITIAL_BYTES,
                        NULL, a->start,
                        iterator, iterator_cls);
}

/**
 * Struct to hold all the relevant state information in the HashMap.
 *
 * Contains the same info as the Regex Iterator parametes except the key,
 * which comes directly from the HashMap iterator.
 */
struct temporal_state_store {
  int reachable;
  char *proof;
  int accepting;
  int num_edges;
  struct REGEX_BLOCK_Edge *edges;
};


/**
 * Store regex iterator and cls in one place to pass to the hashmap iterator.
 */
struct client_iterator {
  REGEX_INTERNAL_KeyIterator iterator;
  void *iterator_cls;
};


/**
 * Iterator over all edges of a dfa. Stores all of them in a HashMap
 * for later reachability marking.
 *
 * @param cls Closure (HashMap)
 * @param key hash for current state.
 * @param proof proof for current state
 * @param accepting GNUNET_YES if this is an accepting state, GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
static void
store_all_states (void *cls,
                  const struct GNUNET_HashCode *key,
                  const char *proof,
                  int accepting,
                  unsigned int num_edges,
                  const struct REGEX_BLOCK_Edge *edges)
{
  struct GNUNET_CONTAINER_MultiHashMap *hm = cls;
  struct temporal_state_store *tmp;
  size_t edges_size;

  tmp = GNUNET_new (struct temporal_state_store);
  tmp->reachable = GNUNET_NO;
  tmp->proof = GNUNET_strdup (proof);
  tmp->accepting = accepting;
  tmp->num_edges = num_edges;
  edges_size = sizeof (struct REGEX_BLOCK_Edge) * num_edges;
  tmp->edges = GNUNET_malloc (edges_size);
  memcpy(tmp->edges, edges, edges_size);
  GNUNET_CONTAINER_multihashmap_put (hm, key, tmp,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
}


/**
 * Mark state as reachable and call recursively on all its edges.
 *
 * If already marked as reachable, do nothing.
 *
 * @param state State to mark as reachable.
 * @param hm HashMap which stores all the states indexed by key.
 */
static void
mark_as_reachable (struct temporal_state_store *state,
                   struct GNUNET_CONTAINER_MultiHashMap *hm)
{
  struct temporal_state_store *child;
  unsigned int i;

  if (GNUNET_YES == state->reachable)
    /* visited */
    return;

  state->reachable = GNUNET_YES;
  for (i = 0; i < state->num_edges; i++)
  {
    child = GNUNET_CONTAINER_multihashmap_get (hm,
                                               &state->edges[i].destination);
    if (NULL == child)
    {
      GNUNET_break (0);
      continue;
    }
    mark_as_reachable (child, hm);
  }
}


/**
 * Iterator over hash map entries to mark the ones that are reachable.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
reachability_iterator (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct GNUNET_CONTAINER_MultiHashMap *hm = cls;
  struct temporal_state_store *state = value;

  if (GNUNET_YES == state->reachable)
    /* already visited and marked */
    return GNUNET_YES;

  if (GNUNET_REGEX_INITIAL_BYTES > strlen (state->proof) &&
      GNUNET_NO == state->accepting)
    /* not directly reachable */
    return GNUNET_YES;

  mark_as_reachable (state, hm);
  return GNUNET_YES;
}


/**
 * Iterator over hash map entries.
 * Calling the callback on the ones marked as reachables.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
iterate_reachables (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct client_iterator *ci = cls;
  struct temporal_state_store *state = value;

  if (GNUNET_YES == state->reachable)
  {
    ci->iterator (ci->iterator_cls, key,
                  state->proof, state->accepting,
                  state->num_edges, state->edges);
  }
  GNUNET_free (state->edges);
  GNUNET_free (state->proof);
  GNUNET_free (state);
  return GNUNET_YES;

}

/**
 * Iterate over all edges of automaton 'a' that are reachable from a state with
 * a proof of at least GNUNET_REGEX_INITIAL_BYTES characters.
 *
 * Call the iterator for each such edge.
 *
 * @param a automaton.
 * @param iterator iterator called for each reachable edge.
 * @param iterator_cls closure.
 */
void
REGEX_INTERNAL_iterate_reachable_edges (struct REGEX_INTERNAL_Automaton *a,
                                        REGEX_INTERNAL_KeyIterator iterator,
                                        void *iterator_cls)
{
  struct GNUNET_CONTAINER_MultiHashMap *hm;
  struct client_iterator ci;

  hm = GNUNET_CONTAINER_multihashmap_create (a->state_count * 2, GNUNET_NO);
  ci.iterator = iterator;
  ci.iterator_cls = iterator_cls;

  REGEX_INTERNAL_iterate_all_edges (a, &store_all_states, hm);
  GNUNET_CONTAINER_multihashmap_iterate (hm, &reachability_iterator, hm);
  GNUNET_CONTAINER_multihashmap_iterate (hm, &iterate_reachables, &ci);

  GNUNET_CONTAINER_multihashmap_destroy (hm);
}


/* end of regex_internal.c */
