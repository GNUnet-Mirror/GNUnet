/*
     This file is part of GNUnet
     Copyright (C) 2016 GNUnet e.V.

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
 * @file my/my_query_helper.c
 * @brief library to help with access to a MySQL database
 * @author Christian Grothoff
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_my_lib.h"


/**
 * Function called to convert input argument into SQL parameters.
 *
 * @param cls closure
 * @param pq data about the query
 * @param qbind array of parameters to initialize
 * @return -1 on error
 */
static int
my_conv_fixed_size (void *cls,
                    const struct GNUNET_MY_QueryParam *qp,
                    MYSQL_BIND *qbind)
{
  GNUNET_assert (1 == qp->num_params);
  qbind->buffer = (void *) qp->data;
  qbind->buffer_length = qp->data_len;
  qbind->length = (unsigned long *) &qp->data_len;
  qbind->buffer_type = 1;
  return 0;
}


/**
 * Generate query parameter for a buffer @a ptr of
 * @a ptr_size bytes.
 *
 * @param ptr pointer to the query parameter to pass
 * @param ptr_size number of bytes in @a ptr
 */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_fixed_size (const void *ptr,
				  size_t ptr_size)
{
  struct GNUNET_MY_QueryParam qp = {
    &my_conv_fixed_size,
    NULL,
    1,
    ptr,
    (unsigned long) ptr_size
  };
  return qp;
}


/**
  * Generate query parameter for a string
  *
  *@param ptr pointer to the string query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_string (const char *ptr)
{
  return GNUNET_MY_query_param_fixed_size(ptr,
                                         strlen(ptr));
}

/**
  * Function called to convert input argument into SQL parameters
  *
  *@param cls closure
  *@param pq data about the query
 * @param qbind array of parameters to initialize
  *@return -1 on error 
  */
static int
my_conv_uint16 (void *cls,
                const struct GNUNET_MY_QueryParam * qp,
                MYSQL_BIND *qbind)
{
  const uint16_t *u_hbo = qp->data;
  uint16_t *u_nbo;

  GNUNET_assert (1 == qp->num_params);

  u_nbo = GNUNET_new (uint16_t);
  *u_nbo = htons (*u_hbo);
  qbind->buffer = (void *) u_nbo;
  qbind->buffer_length = sizeof(uint16_t);
  qbind->buffer_type = 1;

  return 1;
}

/**
  * Generate query parameter for an uint16_t in host byte order.
  *
  * @param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_uint16 (const uint16_t *x)
{
  struct GNUNET_MY_QueryParam res = { 
      &my_conv_uint16,
      NULL,
      1,
      x,
      sizeof (*x)
    };

  return res;
}

/**
  * Function called to convert input argument into SQL parameters
  *
  *@param cls closure
  *@param pq data about the query
 * @param qbind array of parameters to initialize
  *@return -1 on error 
  */
static int 
my_conv_uint32 (void *cls,
                const struct GNUNET_MY_QueryParam *qp,
                MYSQL_BIND *qbind)
{
  const uint32_t *u_hbo = qp->data;
  uint32_t * u_nbo;

  GNUNET_assert (1 == qp->num_params);

  u_nbo = GNUNET_new (uint32_t);
  *u_nbo = htonl (*u_hbo);

  qbind->buffer = (void *) u_nbo;
  qbind->buffer_length = sizeof(uint32_t);
  qbind->buffer_type = 1;

  return 1;
}

/**
  * Generate query parameter for an uint32_t in host byte order
  *
  *@param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_uint32 (const uint32_t *x)
{
  struct GNUNET_MY_QueryParam res = {
    &my_conv_uint32,
    NULL,
    1,
    x, 
    sizeof (*x)
  };
  
  return res;
}

/**
  * Function called to convert input argument into SQL parameters
  *
  *@param cls closure
  *@param pq data about the query
 * @param qbind array of parameters to initialize
  *@return -1 on error 
  */
static int
my_conv_uint64 (void *cls,
              const struct GNUNET_MY_QueryParam *qp,
              MYSQL_BIND * qbind)
{
  const uint64_t * u_hbo = qp->data;
  uint64_t *u_nbo;

  GNUNET_assert (1 == qp->num_params);

  u_nbo = GNUNET_new(uint64_t);
  *u_nbo = GNUNET_htonll (*u_hbo);

  qbind->buffer = (void *) u_nbo;
  qbind->buffer_length = sizeof (uint64_t);
  qbind->buffer_type = 1;

  return 1;  
}

/**
  * Generate query parameter for an uint64_t in host byte order
  *
  *@param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_uint64 (const uint64_t *x)
{
  struct GNUNET_MY_QueryParam res = {
    &my_conv_uint64,
    NULL,
    1,
    x,
    sizeof(*x)
  };

  return res;
}

/**
  * Function called to convert input argument into SQL parameters
  *
  *@param cls closure
  *@param pq data about the query
 * @param qbind array of parameters to initialize
  *@return -1 on error 
  */
static int
my_conv_rsa_public_key (void *cls,
                        const struct GNUNET_MY_QueryParam *qp,
                        MYSQL_BIND * qbind)
  {
    const struct GNUNET_CRYPTO_RsaPublicKey *rsa = qp->data;
    char *buf;
    size_t buf_size;

    GNUNET_assert(1 == qp->num_params);

    buf_size = GNUNET_CRYPTO_rsa_public_key_encode (rsa, &buf);

    qbind->buffer = (void *)buf;
    qbind->buffer_length = buf_size - 1;
    qbind->buffer_type = 1;

    return 1;
  }

  /**
    * Generate query parameter for an RSA public key. The
    * database must contain a BLOB type in the respective position.
    *
    * @param x the query parameter to pass
    * @return array entry for the query parameters to use
    */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *x)
{
  struct GNUNET_MY_QueryParam res = {
    &my_conv_rsa_public_key,
    NULL,
    1,
    x,
    0
  };

  return res;
}

/**
  * Function called to convert input argument into SQL parameters
  *
  *@param cls closure
  *@param pq data about the query
 * @param qbind array of parameters to initialize
  *@return -1 on error 
  */
static int 
my_conv_rsa_signature (void *cls,
                      const struct GNUNET_MY_QueryParam *qp,
                      MYSQL_BIND * qbind)
{
  const struct GNUNET_CRYPTO_RsaSignature *sig = qp->data;
  char *buf;
  size_t buf_size;

  GNUNET_assert(1 == qp->num_params);

  buf_size = GNUNET_CRYPTO_rsa_signature_encode(sig,
                                                &buf);

  qbind->buffer = (void *)buf;
  qbind->buffer_length = buf_size - 1;
  qbind->buffer_type = 1;

  return 1;
}

/**
  * Generate query parameter for an RSA signature. The
  * database must contain a BLOB type in the respective position
  *
  *@param x the query parameter to pass
  *@return array entry for the query parameters to use
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *x)
{
  struct GNUNET_MY_QueryParam res = {
    &my_conv_rsa_signature,
    NULL,
    1,
    (x),
    0
  };
  return res;
}

/**
  * Generate query parameter for an absolute time value.
  * The database must store a 64-bit integer.
  *
  *@param x pointer to the query parameter to pass
  *@return array entry for the query parameters to use
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_absolute_time (const struct GNUNET_TIME_Absolute *x)
{
  return GNUNET_MY_query_param_uint64 (&x->abs_value_us);
}

/**
  * Generate query parameter for an absolute time value.
  * The database must store a 64-bit integer.
  *
  *@param x pointer to the query parameter to pass
  */
struct GNUNET_MY_QueryParam
GNUNET_MY_query_param_absolute_time_nbo (const struct GNUNET_TIME_AbsoluteNBO *x)
{
  return GNUNET_MY_query_param_auto_from_type (&x->abs_value_us__);
}

/* end of my_query_helper.c */