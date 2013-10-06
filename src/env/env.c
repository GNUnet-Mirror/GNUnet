/*
 * This file is part of GNUnet.
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file env/env.c
 * @brief Library providing operations for the @e environment of
 *        PSYC and Social messages, and for (de)serializing variable values.
 * @author Gabor X Toth
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"

/**
 * Environment for a message.
 *
 * Contains modifiers.
 */
struct GNUNET_ENV_Environment
{
  struct GNUNET_ENV_Modifier *mod_head;
  struct GNUNET_ENV_Modifier *mod_tail;
  size_t mod_count;
};


/**
 * Create an environment.
 *
 * @return A newly allocated environment.
 */
struct GNUNET_ENV_Environment *
GNUNET_ENV_environment_create ()
{
  return GNUNET_new (struct GNUNET_ENV_Environment);
}


/**
 * Add a modifier to the environment.
 *
 * @param env The environment.
 * @param oper Operation to perform.
 * @param name Name of the variable.
 * @param value Value of the variable.
 * @param value_size Size of @a value.
 */
void
GNUNET_ENV_environment_add_mod (struct GNUNET_ENV_Environment *env,
                                enum GNUNET_ENV_Operator oper, const char *name,
                                const void *value, size_t value_size)
{
  struct GNUNET_ENV_Modifier *mod = GNUNET_malloc (sizeof (*mod));
  mod->oper = oper;
  mod->name = name;
  mod->value = value;
  mod->value_size = value_size;
  GNUNET_CONTAINER_DLL_insert_tail (env->mod_head, env->mod_tail, mod);
  env->mod_count++;
}


/**
 * Iterate through all modifiers in the environment.
 *
 * @param env The environment.
 * @param it Iterator.
 * @param it_cls Closure for iterator.
 */
void
GNUNET_ENV_environment_iterate (const struct GNUNET_ENV_Environment *env,
                                GNUNET_ENV_Iterator it, void *it_cls)
{
  struct GNUNET_ENV_Modifier *mod;
  for (mod = env->mod_head; NULL != mod; mod = mod->next)
    it (it_cls, mod);
}


/**
 * Get the number of modifiers in the environment.
 *
 * @param env The environment.
 *
 * @return Number of modifiers.
 */
size_t
GNUNET_ENV_environment_get_mod_count (const struct GNUNET_ENV_Environment *env)
{
  return env->mod_count;
}


/**
 * Destroy an environment.
 *
 * @param env The environment to destroy.
 */
void
GNUNET_ENV_environment_destroy (struct GNUNET_ENV_Environment *env)
{
  struct GNUNET_ENV_Modifier *mod, *prev = NULL;
  for (mod = env->mod_head; NULL != mod; mod = mod->next)
  {
    if (NULL != prev)
      GNUNET_free (prev);
    prev = mod;
  }
  if (NULL != prev)
    GNUNET_free (prev);

  GNUNET_free (env);
}
