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
 * @file include/gnunet_psyc_lib.h
 * @brief Library for common PSYC functionality:
 *        types, variable (de)serialization.
 * @author Gabor X Toth
 */


/** 
 * Possible operations on PSYC state (persistent) and transient variables (per message).
 */
enum GNUNET_PSYC_Operator
{ 
  /**
   * Set value of a transient variable.
   */
  GNUNET_PSYC_OP_SET = ':',

  /**
   * Assign value for a persistent state variable.
   *
   * If an assigned value is NULL, the variable is deleted.
   */
  GNUNET_PSYC_OP_ASSIGN = '=',

  /**
   * Augment state variable.
   *
   * Used for appending strings, adding numbers, and adding new items to a list or dictionary.
   */
  GNUNET_PSYC_OP_AUGMENT = '+',

  /**
   * Diminish state variable.
   *
   * Used for subtracting numbers, and removing items from a list or dictionary.
   */
  GNUNET_PSYC_OP_DIMINISH = '-',

  /**
   * Update state variable.
   *
   * Used for modifying a single item of a list or dictionary.
   */
  GNUNET_PSYC_OP_UPDATE = '@',
};


/**
 * PSYC variable types.
 */
enum GNUNET_PSYC_Type
{
  GNUNET_PSYC_TYPE_DATA = 0,
  GNUNET_PSYC_TYPE_NUMBER,
  GNUNET_PSYC_TYPE_LIST,
  GNUNET_PSYC_TYPE_DICT
};


/** 
 * Get the type of variable.
 *
 * @param name Name of the variable.
 * 
 * @return Variable type.
 */
enum GNUNET_PSYC_Type
GNUNET_PSYC_var_get_type (char *name);


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
GNUNET_PSYC_value_to_number (size_t size, const void *value, int64_t *number);


/** 
 * Get the variable's value as a list.
 *
 * @param size Size of value.
 * @param value Raw value of variable.
 * @param[out] list A newly created list holding the elements.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if an error occurred (e.g. the value is invalid).
 */
int
GNUNET_PSYC_value_to_list (size_t size, const void *value, GNUNET_CONTAINER_SList **list);


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
GNUNET_PSYC_value_to_dict (size_t size, const void *value, GNUNET_CONTAINER_MultiHashMap **dict);


/** 
 * Create a PSYC variable value from an integer.
 *
 * @param number The number to convert.
 * @param[out] value_size Size of returned value.
 * 
 * @return A newly allocated value or NULL on error.
 */
void *
GNUNET_PSYC_value_from_number (int64_t number, size_t *value_size);


/** 
 * Create a PSYC variable value from a list.
 *
 * @param list The list to convert.
 * @param[out] value_size Size of returned value.
 * 
 * @return A newly allocated value or NULL on error.
 */
void *
GNUNET_PSYC_value_from_list (GNUNET_CONTAINER_SList *list, size_t *value_size);


/** 
 * Create a PSYC variable value from a dictionary.
 *
 * @param dict The dict to convert.
 * @param[out] value_size Size of returned value.
 * 
 * @return A newly allocated value or NULL on error.
 */
void *
GNUNET_PSYC_value_from_dict (GNUNET_CONTAINER_MultiHashMap *dict, size_t *value_size);
