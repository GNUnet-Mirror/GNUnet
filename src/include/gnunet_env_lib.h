/*
 * This file is part of GNUnet.
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file include/gnunet_env_lib.h
 * @brief Library providing operations for the @e environment of
 *        PSYC and Social messages, and for (de)serializing variable values.
 * @author Gabor X Toth
 */


#ifndef GNUNET_ENV_LIB_H
#define GNUNET_ENV_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Possible operations on PSYC state (persistent) and transient variables (per message).
 */
enum GNUNET_ENV_Operator
{
  /**
   * Set value of a transient variable.
   */
  GNUNET_ENV_OP_SET = ':',

  /**
   * Assign value for a persistent state variable.
   *
   * If an assigned value is NULL, the variable is deleted.
   */
  GNUNET_ENV_OP_ASSIGN = '=',

  /**
   * Augment state variable.
   *
   * Used for appending strings, adding numbers, and adding new items to a list or dictionary.
   */
  GNUNET_ENV_OP_AUGMENT = '+',

  /**
   * Diminish state variable.
   *
   * Used for subtracting numbers, and removing items from a list or dictionary.
   */
  GNUNET_ENV_OP_DIMINISH = '-',

  /**
   * Update state variable.
   *
   * Used for modifying a single item of a list or dictionary.
   */
  GNUNET_ENV_OP_UPDATE = '@',
};


/**
 * PSYC variable types.
 */
enum GNUNET_ENV_Type
{
  GNUNET_ENV_TYPE_DATA = 0,
  GNUNET_ENV_TYPE_NUMBER,
  GNUNET_ENV_TYPE_LIST,
  GNUNET_ENV_TYPE_DICT
};


/**
 * PSYC state modifier.
 */
struct GNUNET_ENV_Modifier
{
  /**
   * State operation.
   */
  enum GNUNET_ENV_Operator oper;

  /**
   * Variable name.
   */
  const char *name;

  /**
   * Size of @a value.
   */
  size_t value_size;

  /**
   * Value of variable.
   */
  const void *value;

  /**
   * Next modifier.
   */
  struct GNUNET_ENV_Modifier *next;

  /**
   * Previous modifier.
   */
  struct GNUNET_ENV_Modifier *prev;
};


/**
 * Environment for a message.
 *
 * Contains modifiers.
 */
struct GNUNET_ENV_Environment;


/**
 * Create an environment.
 *
 * @return A newly allocated environment.
 */
struct GNUNET_ENV_Environment *
GNUNET_ENV_environment_create ();


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
GNUNET_ENV_environment_add (struct GNUNET_ENV_Environment *env,
                            enum GNUNET_ENV_Operator oper, const char *name,
                            const void *value, size_t value_size);


/**
 * Get the first modifier of the environment.
 */
struct GNUNET_ENV_Modifier *
GNUNET_ENV_environment_head (const struct GNUNET_ENV_Environment *env);



/**
 * Get the last modifier of the environment.
 */
struct GNUNET_ENV_Modifier *
GNUNET_ENV_environment_tail (const struct GNUNET_ENV_Environment *env);


/**
 * Remove a modifier from the environment.
 */
void
GNUNET_ENV_environment_remove (struct GNUNET_ENV_Environment *env,
                               struct GNUNET_ENV_Modifier *mod);


/**
 * Remove a modifier at the beginning of the environment.
 */
int
GNUNET_ENV_environment_shift (struct GNUNET_ENV_Environment *env,
                              enum GNUNET_ENV_Operator *oper, const char **name,
                              const void **value, size_t *value_size);


/**
 * Iterator for modifiers in the environment.
 *
 * @param cls Closure.
 * @param mod Modifier.
 *
 * @return #GNUNET_YES to continue iterating,
 *         #GNUNET_NO to stop.
 */
typedef int
(*GNUNET_ENV_Iterator) (void *cls, enum GNUNET_ENV_Operator oper,
                        const char *name, const char *value,
                        uint32_t value_size);


/**
 * Iterate through all modifiers in the environment.
 *
 * @param env The environment.
 * @param it Iterator.
 * @param it_cls Closure for iterator.
 */
void
GNUNET_ENV_environment_iterate (const struct GNUNET_ENV_Environment *env,
                                GNUNET_ENV_Iterator it, void *it_cls);


/**
 * Get the number of modifiers in the environment.
 *
 * @param env The environment.
 *
 * @return Number of modifiers.
 */
size_t
GNUNET_ENV_environment_get_count (const struct GNUNET_ENV_Environment *env);


/**
 * Destroy an environment.
 *
 * @param env The environment to destroy.
 */
void
GNUNET_ENV_environment_destroy (struct GNUNET_ENV_Environment *env);


/**
 * Get the type of variable.
 *
 * @param name Name of the variable.
 *
 * @return Variable type.
 */
enum GNUNET_ENV_Type
GNUNET_ENV_var_get_type (char *name);


/**
 * Perform an operation on a variable.
 *
 * @param name Name of variable.
 * @param current_value Current value of variable.
 * @param current_value_size Size of @a current_value.
 * @param oper Operator.
 * @param args Arguments for the operation.
 * @param args_size Size of @a args.
 * @param return_value Return value.
 * @param return_value_size Size of @a return_value.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR
 */
int
GNUNET_ENV_operation (char *name, void *current_value, size_t current_value_size,
                      enum GNUNET_ENV_Operator oper, void *args, size_t args_size,
                      void **return_value, size_t *return_value_size);


/**
 * Get the variable's value as an integer.
 *
 * @param size Size of value.
 * @param value Raw value of variable.
 * @param[out] number Value converted to a 64-bit integer.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if an error occurred (e.g. the value is invalid).
 */
int
GNUNET_ENV_value_to_number (size_t size, const void *value, int64_t *number);


/**
 * Get the variable's value as a dictionary.
 *
 * @param size Size of value.
 * @param value Raw value of variable.
 * @param[out] dict A newly created hashmap holding the elements of the dictionary.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if an error occurred (e.g. the value is invalid).
 */
int
GNUNET_ENV_value_to_dict (size_t size, const void *value, struct GNUNET_CONTAINER_MultiHashMap **dict);


/**
 * Create a PSYC variable value from an integer.
 *
 * @param number The number to convert.
 * @param[out] value_size Size of returned value.
 *
 * @return A newly allocated value or NULL on error.
 */
void *
GNUNET_ENV_value_from_number (int64_t number, size_t *value_size);


/**
 * Create a PSYC variable value from a dictionary.
 *
 * @param dict The dict to convert.
 * @param[out] value_size Size of returned value.
 *
 * @return A newly allocated value or NULL on error.
 */
void *
GNUNET_ENV_value_from_dict (struct GNUNET_CONTAINER_MultiHashMap *dict, size_t *value_size);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_ENV_LIB_H */
#endif
/* end of gnunet_env_lib.h */
