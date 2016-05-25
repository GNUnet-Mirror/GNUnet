 /*
  This file is part of GNUnet
  Copyright (C) 2014, 2015, 2016 GNUnet e.V.
  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.
  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
  You should have received a copy of the GNU General Public License along with
  GNUnet; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/
/**
 * @file my/my_result_helper.c
 * @brief functions to extract result values
 * @author Christophe Genevey
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_my_lib.h"

/**
  * extract data from a Mysql database @a result at row @a row
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in, out] dst_size where to store size of result, may be NULL
  * @param[out] dst where to store the result
  * @return
  *   #GNUNET_OK if all results could be extracted
  *   #GNUNET_SYSERR if a result was invalid
  */
static int
extract_varsize_blob (void *cls,
                      MYSQL_RES * result,
                      int row,
                      const char *fname,
                      size_t *dst_size,
                      void *dst)
{
  const char *res;
  void *idst;
  size_t len;

  MYSQL_ROW rows;
  MYSQL_FIELD *field;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name != fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);

    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  res = rows[row];

  len = strlen(res);

  GNUNET_assert (NULL != res);
  
  *dst_size = len;
  idst = GNUNET_malloc (len);
  *((void **) dst) = idst;
  memcpy (idst,
          res,
          len);

  return GNUNET_OK;
}

/**
  * Variable-size result expected
  *
  * @param[out] dst where to store the result, allocated
  * @param[out] sptr where to store the size of @a dst
  * @return array entru for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_variable_size (void **dst,
                                    size_t *ptr_size)
{
  struct GNUNET_MY_ResultSpec res = {
    &extract_varsize_blob,
    NULL,
    (void *)(dst),
    0,
    ptr_size
  };

  return res;
}

/**
  * Extract data from a Mysql database @a result at row @a row
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in] dst_size desired size, never NULL
  * @param[out] dst where to store the result
  * @return
  *  #GNUNET_OK if all results could be extracted
  *  #GNUNET_SYSERR if a result was invalid(non-existing field or NULL)
  *
  */
static int
extract_fixed_blob (void *cls,
                      MYSQL_RES * result,
                      int row,
                      const char * fname,
                      size_t * dst_size,
                      void *dst)
{
  size_t len;
  const char *res;

  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name != fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);

    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  res = rows[row];

  len = strlen (res);
  if (*dst_size != len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Field '%s' has wrong size (got %u, expected %u)\n",
                fname,
                (unsigned int)len,
                (unsigned int) *dst_size);
    return GNUNET_SYSERR;
  }

  GNUNET_assert (NULL != res);
  
  memcpy (dst,
          res,
          len);

  return GNUNET_OK;
}
/**
 * Fixed-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result
 * @param dst_size number of bytes in @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_fixed_size (void *ptr,
                                  size_t ptr_size)
{
  struct GNUNET_MY_ResultSpec res = { 
    &extract_fixed_blob,
    NULL,
    (void *)(ptr),
    ptr_size,
    NULL 
  };
      
  return res;
}

/**
  * Extract data from a Mysql database @a result at row @a row
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in, out] dst_size where to store size of result, may be NULL
  * @param[out] dst where to store the result
  * @return
  *   #GNUNET_OK if all results could be extracted
  *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
extract_rsa_public_key (void *cls,
                        MYSQL_RES *result,
                        int row,
                        const char *fname,
                        size_t *dst_size,
                        void *dst)
{
  struct GNUNET_CRYPTO_RsaPublicKey **pk = dst;
  size_t len;
  const char *res;

  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  *pk = NULL;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name != fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);
    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  res = rows[row];

  len = strlen (res);
  
  *pk = GNUNET_CRYPTO_rsa_public_key_decode (res, 
                                            len);

  if (NULL == *pk)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Field '%s' contains bogus value (fails to decode\n",
                  fname);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
  * RSA public key expected
  *
  * @param name name of the field in the table
  * @param[out] rsa where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_rsa_public_key (struct GNUNET_CRYPTO_RsaPublicKey **rsa)
{
  struct GNUNET_MY_ResultSpec res = {
    &extract_rsa_public_key,
    NULL,
    (void *) rsa,
    0,
    NULL    
  };

  return res;
}

/**
  * Extract data from a Mysql database @a result at row @a row.
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in,out] dst_size where to store size of result, may be NULL
  * @param[out] dst where to store the result
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
extract_rsa_signature (void *cls,
                      MYSQL_RES * result,
                      int row, const char *fname,
                      size_t * dst_size,
                      void *dst)
{
  struct GNUNET_CRYPTO_RsaSignature **sig = dst;
  size_t len;
  const char *res;

  
  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  *sig = NULL;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name == fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);
    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  res = rows[row];
  len = strlen (res);

  *sig = GNUNET_CRYPTO_rsa_signature_decode (res,
                                            len);

  if (NULL == *sig)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Field '%s' contains bogus value (fails to decode)\n",
                fname);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

/**
  * RSA signature expected.
  *
  * @param[out] sig where to store the result;
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_rsa_signature (struct GNUNET_CRYPTO_RsaSignature **sig)
{
  struct GNUNET_MY_ResultSpec res = 
  {
    &extract_rsa_signature,
    NULL,
    (void *)sig,
    0,
    NULL
  };
  return res;
}

/**
  * Extract data from a Mysql database @a result at row @a row
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in, out] dst_size where to store size of result, may be NULL
  * @param[out] dst where to store the result
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non existing field or NULL)
  */
static int
extract_string (void * cls,
                MYSQL_RES * result,
                int row,
                const char * fname,
                size_t *dst_size,
                void *dst)
{
  char **str = dst;
  size_t len;
  const char *res;

  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  *str = NULL;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name == fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);
    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  res = rows[row];
  len = strlen (res);
 
  *str = GNUNET_strndup (res,
                        len);

  if (NULL == *str)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Field '%s' contains bogus value (fails to decode) \n",
                fname);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}    
/**
  * 0- terminated string exprected.
  *
  * @param[out] dst where to store the result, allocated
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_string (char **dst)
{
  struct GNUNET_MY_ResultSpec res = {
    &extract_string,
    NULL,
    (void *) dst,
    0,
    NULL
  };
  return res;
}

/**
  * Absolute time expected
  *
  * @param name name of the field in the table
  * @param[out] at where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_absolute_time (struct GNUNET_TIME_Absolute *at)
{
  return GNUNET_MY_result_spec_uint64 (&at->abs_value_us);
}

/**
  * Absolute time in network byte order expected
  *
  * @param[out] at where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_absolute_time_nbo (struct GNUNET_TIME_AbsoluteNBO *at)
{
  struct GNUNET_MY_ResultSpec res = 
    GNUNET_MY_result_spec_auto_from_type (&at->abs_value_us__);
    return res;
}

/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param int row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in,out] dst_size where to store size of result, may be NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
 */
static int
extract_uint16 (void *cls,
              MYSQL_RES * result,
              int row,
              const char *fname,
              size_t *dst_size,
              void *dst)
{
    //TO COMPLETE 
  uint16_t *udst = dst;
  uint16_t *res;

  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name == fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);
    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  GNUNET_assert (NULL != dst);

  if (sizeof (uint16_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  res = atoi (rows[row]);
  *udst = ntohs (*res);

  return GNUNET_OK;
}

/**
  * uint16_t expected
  *
  * @param[out] u16 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint16 (uint16_t *u16)
{
  struct GNUNET_MY_ResultSpec res = {
    &extract_uint16,
    NULL,
    (void *) u16,
    sizeof (*u16),
    NULL
  };
  return res;
}

/**
  * Extrac data from a  MYSQL database @a result at row @a row
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in, out] dst_size where to store size of result, may be NULL
  * @param[out] dst where to store the result
  * @return
  *      #GNUNET_OK if all results could be extracted
  *      #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
extract_uint32 (void *cls,
                MYSQL_RES * result,
                int row,
                const char *fname,
                size_t *dst_size,
                void *dst)
{
  uint32_t *udst = dst;
  const uint32_t *res;

  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name == fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);
    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  GNUNET_assert (NULL != dst);

  if (sizeof (uint32_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  res = (uint32_t) rows[row];

  *udst = ntohl (*res);
  return GNUNET_OK;
}

/**
  * uint32_t expected
  *
  * @param[out] u32 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint32 (uint32_t *u32)
{
  struct GNUNET_MY_ResultSpec res = {
    &extract_uint32,
    NULL,
    (void *) u32,
    sizeof (*u32),
    NULL
  };
  return res;
}

/**
  * Extract data from a MYSQL database @a result at row @a row
  *
  * @param cls closure
  * @param result where to extract data from
  * @param int row to extract data from
  * @param fname name (or prefix) of the fields to extract from
  * @param[in, out] dst_size where to store size of result, may be null
  * @param[out] dst where to store the result
  * @return
  *    #GNUNET_OK if all results could be extracted
  *    #GNUNET_SYSERR if a result was invalid (non-existing field or NULL)
  */
static int
extract_uint64 (void *cls,
                MYSQL_RES * result,
                int row, 
                const char *fname,
                size_t *dst_size,
                void *dst)
{
  uint64_t *udst = dst;
  const uint64_t *res;

  MYSQL_ROW rows;
  MYSQL_FIELD * field;

  rows = mysql_fetch_row (result);

  field = mysql_fetch_field (result);

  //If it's the correct field
  if (field->name == fname)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "Field '%s' does not exist in result",
                fname);
    return GNUNET_SYSERR;
  }


  if (rows[row] == NULL)
  {
    return GNUNET_SYSERR;
  }

  GNUNET_assert (NULL != dst);
  if (sizeof (uint64_t) != *dst_size)
  {
      GNUNET_break (0);
      return GNUNET_SYSERR;
  }

  res = (uint64_t) rows[row];
  *udst = GNUNET_ntohll (*res);

  return GNUNET_OK;
}


/**
  * uint64_t expected.
  *
  * @param[out] u64 where to store the result
  * @return array entry for the result specification to use
  */
struct GNUNET_MY_ResultSpec
GNUNET_MY_result_spec_uint64 (uint64_t *u64)
{
  struct GNUNET_MY_ResultSpec res = {
    &extract_uint64,
    NULL,
    (void *) u64,
    sizeof (*u64),
    NULL
  };
  return res;
}

/* end of pq_result_helper.c */