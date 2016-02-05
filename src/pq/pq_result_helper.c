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
 * @file pq/pq_result_helper.c
 * @brief functions to extract result values
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet/gnunet_util_lib.h>
#include "gnunet_pq_lib.h"


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_varsize_blob (void *cls,
		    void *rd)
{
  void **dst = rd;

  if (NULL != *dst)
  {
    GNUNET_free (*dst);
    *dst = NULL;
  }
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
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_varsize_blob (void *cls,
		      PGresult *result,
		      int row,
		      const char *fname,
		      size_t *dst_size,
		      void *dst)
{
  size_t len;
  const char *res;
  void *idst;
  int fnum;
  
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;
  
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
		     row,
		     fnum);
  res = PQgetvalue (result,
		    row,
		    fnum);
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
 * Variable-size result expected.
 *
 * @param name name of the field in the table
 * @param[out] dst where to store the result, allocated
 * @param[out] sptr where to store the size of @a dst
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_variable_size (const char *name,
				     void **dst,
				     size_t *sptr)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_varsize_blob,
      &clean_varsize_blob, NULL, 
      (void *) (dst), 0, name, sptr };
  return res;
}


/**
 * Extract data from a Postgres database @a result at row @a row.
 *
 * @param cls closure
 * @param result where to extract data from
 * @param int row to extract data from
 * @param fname name (or prefix) of the fields to extract from
 * @param[in] dst_size desired size, never NULL
 * @param[out] dst where to store the result
 * @return
 *   #GNUNET_YES if all results could be extracted
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_fixed_blob (void *cls,
		    PGresult *result,
		    int row,
		    const char *fname,
		    size_t *dst_size,
		    void *dst)
{
  size_t len;
  const char *res;
  int fnum;
  
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;
  
  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
		     row,
		     fnum);
  if (*dst_size != len) 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' has wrong size (got %u, expected %u)\n",
		fname,
		(unsigned int) len,
		(unsigned int) *dst_size);
    return GNUNET_SYSERR;
  }
  res = PQgetvalue (result,
		    row,
		    fnum);
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
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_fixed_size (const char *name,
				  void *dst,
				  size_t dst_size)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_fixed_blob,
      NULL, NULL, 
      (dst), dst_size, name, NULL };
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
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_rsa_public_key (void *cls,
			PGresult *result,
			int row,
			const char *fname,
			size_t *dst_size,
			void *dst)
{
  struct GNUNET_CRYPTO_rsa_PublicKey **pk = dst;
  size_t len;
  const char *res;
  int fnum;

  *pk = NULL;
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
		     row,
		     fnum);
  res = PQgetvalue (result,
		    row,
		    fnum);
  *pk = GNUNET_CRYPTO_rsa_public_key_decode (res,
					     len);
  if (NULL == *pk)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' contains bogus value (fails to decode)\n",
		fname);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_rsa_public_key (void *cls,
		      void *rd)
{
  struct GNUNET_CRYPTO_rsa_PublicKey **pk = rd;
  
  if (NULL != *pk)
  {
    GNUNET_CRYPTO_rsa_public_key_free (*pk);
    *pk = NULL;
  }
}


/**
 * RSA public key expected.
 *
 * @param name name of the field in the table
 * @param[out] rsa where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_public_key (const char *name,
				      struct GNUNET_CRYPTO_rsa_PublicKey **rsa)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_rsa_public_key,
      &clean_rsa_public_key,
      NULL,
      (void *) rsa, 0, name, NULL };
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
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_rsa_signature (void *cls,
		       PGresult *result,
		       int row,
		       const char *fname,
		       size_t *dst_size,
		       void *dst)
{
  struct GNUNET_CRYPTO_rsa_Signature **sig = dst;
  size_t len;
  const char *res;
  int fnum;
  
  *sig = NULL;
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;

  /* if a field is null, continue but
   * remember that we now return a different result */
  len = PQgetlength (result,
		     row,
		     fnum);
  res = PQgetvalue (result,
		    row,
		    fnum);
  *sig = GNUNET_CRYPTO_rsa_signature_decode (res,
					     len);
  if (NULL == *sig)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' contains bogus value (fails to decode)\n",
		fname);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to clean up memory allocated
 * by a #GNUNET_PQ_ResultConverter.
 *
 * @param cls closure
 * @param rd result data to clean up
 */
static void
clean_rsa_signature (void *cls,
		     void *rd)
{
  struct GNUNET_CRYPTO_rsa_Signature **sig = rd;

  if (NULL != *sig)
  {
    GNUNET_CRYPTO_rsa_signature_free (*sig);
    *sig = NULL;
  }
}


/**
 * RSA signature expected.
 *
 * @param name name of the field in the table
 * @param[out] sig where to store the result;
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_rsa_signature (const char *name,
				    struct GNUNET_CRYPTO_rsa_Signature **sig)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_rsa_signature,
      &clean_rsa_signature,
      NULL,
      (void *) sig, 0, (name), NULL };
  return res;
}


/**
 * Absolute time expected.
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time (const char *name,
				     struct GNUNET_TIME_Absolute *at)
{
  return GNUNET_PQ_result_spec_uint64 (name,
				       &at->abs_value_us);
}


/**
 * Absolute time in network byte order expected.
 *
 * @param name name of the field in the table
 * @param[out] at where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_absolute_time_nbo (const char *name,
					 struct GNUNET_TIME_AbsoluteNBO *at)
{
  struct GNUNET_PQ_ResultSpec res =
    GNUNET_PQ_result_spec_auto_from_type(name, &at->abs_value_us__);
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
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_uint16 (void *cls,
		PGresult *result,
		int row,
		const char *fname,
		size_t *dst_size,
		void *dst)
{
  uint16_t *udst = dst;
  const uint16_t *res;
  int fnum;
  
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof (uint16_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (uint16_t *) PQgetvalue (result,
				 row,
				 fnum);
  *udst = ntohs (*res);
  return GNUNET_OK;
}


/**
 * uint16_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u16 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint16 (const char *name,
			      uint16_t *u16)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_uint16,
      NULL,
      NULL,
      (void *) u16, sizeof (*u16), (name), NULL };
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
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_uint32 (void *cls,
		PGresult *result,
		int row,
		const char *fname,
		size_t *dst_size,
		void *dst)
{
  uint32_t *udst = dst;
  const uint32_t *res;
  int fnum;
  
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof (uint32_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (uint32_t *) PQgetvalue (result,
				 row,
				 fnum);
  *udst = ntohl (*res);
  return GNUNET_OK;
}


/**
 * uint32_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u32 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint32 (const char *name,
			      uint32_t *u32)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_uint32, 
      NULL,
      NULL,
      (void *) u32, sizeof (*u32), (name), NULL };
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
 *   #GNUNET_NO if at least one result was NULL
 *   #GNUNET_SYSERR if a result was invalid (non-existing field)
 */ 
static int
extract_uint64 (void *cls,
		PGresult *result,
		int row,
		const char *fname,
		size_t *dst_size,
		void *dst)
{
  uint64_t *udst = dst;
  const uint64_t *res;
  int fnum;
  
  fnum = PQfnumber (result,
		    fname);
  if (fnum < 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Field `%s' does not exist in result\n",
		fname);
    return GNUNET_SYSERR;
  }
  if (PQgetisnull (result,
		   row,
		   fnum))
    return GNUNET_NO;
  GNUNET_assert (NULL != dst);
  if (sizeof (uint64_t) != *dst_size)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  res = (uint64_t *) PQgetvalue (result,
				 row,
				 fnum);
  *udst = GNUNET_ntohll (*res);
  return GNUNET_OK;
}


/**
 * uint64_t expected.
 *
 * @param name name of the field in the table
 * @param[out] u64 where to store the result
 * @return array entry for the result specification to use
 */
struct GNUNET_PQ_ResultSpec
GNUNET_PQ_result_spec_uint64 (const char *name,
			      uint64_t *u64)
{
  struct GNUNET_PQ_ResultSpec res =
    { &extract_uint64,
      NULL,
      NULL,
      (void *) u64, sizeof (*u64), (name), NULL };
  return res;
}


/* end of pq_result_helper.c */
