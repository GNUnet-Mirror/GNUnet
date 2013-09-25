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
 * @file env/test_env.c
 * @brief Tests for the environment library.
 * @author Gabor X Toth
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_env_lib.h"

struct GNUNET_ENV_Modifier mods[] = {
  { .oper = GNUNET_ENV_OP_SET,
    .name = "_foo", .value = "foo", .value_size = 3 },

  { .oper = GNUNET_ENV_OP_ASSIGN,
    .name = "_foo_bar", .value = "foo bar", .value_size = 7 },

  { .oper = GNUNET_ENV_OP_AUGMENT,
    .name = "_foo_bar_baz", .value = "foo bar baz", .value_size = 11 }
};

struct ItCls
{
  size_t n;
};

int
iterator (void *cls, struct GNUNET_ENV_Modifier *mod)
{
  struct ItCls *it_cls = cls;
  struct GNUNET_ENV_Modifier *m = &mods[it_cls->n++];

  GNUNET_assert (mod->oper == m->oper);
  GNUNET_assert (mod->value_size == m->value_size);
  GNUNET_assert (0 == memcmp (mod->name, m->name, strlen (m->name)));
  GNUNET_assert (0 == memcmp (mod->value, m->value, m->value_size));

  return GNUNET_YES;
}

int
main (int argc, char *argv[])
{
  GNUNET_log_setup ("test-env", "WARNING", NULL);

  struct GNUNET_ENV_Environment *env = GNUNET_ENV_environment_create ();
  GNUNET_assert (NULL != env);
  int i, len = 3;

  for (i = 0; i < len; i++)
  {
    GNUNET_ENV_environment_add_mod (env, mods[i].oper, mods[i].name,
                                    mods[i].value, mods[i].value_size);
  }

  struct ItCls it_cls = { .n = 0 };
  GNUNET_ENV_environment_iterate (env, iterator, &it_cls);
  GNUNET_assert (len == it_cls.n);

  GNUNET_ENV_environment_destroy (env);

  return 0;
}
