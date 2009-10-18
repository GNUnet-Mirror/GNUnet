/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/test_bio.c
 * @brief testcase for the buffered IO module
 * @author JiLu
 */


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_disk_lib.h"
#include "gnunet_bio_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_time_lib.h"
#include <extractor.h>
#include <zlib.h>

const char readWhatMeta[200],readWhatString[200],readWhatInt64[200];
char readResultString[200];
size_t readMaxLen;
int64_t numberOne = 100000L;
char *msg;

int
main (int argc, char *argv[])
{
	    char* fileName = GNUNET_DISK_mktemp ("gnunet_bio");
		struct GNUNET_BIO_ReadHandle *fileR;
		struct GNUNET_BIO_WriteHandle *fileW;
		struct GNUNET_CONTAINER_MetaData *metaDataW;
		struct GNUNET_CONTAINER_MetaData *metaDataR;
		metaDataR = GNUNET_CONTAINER_meta_data_create();
		metaDataW = GNUNET_CONTAINER_meta_data_create();
		GNUNET_CONTAINER_meta_data_add_publication_date(metaDataW);
		fileW = GNUNET_BIO_write_open(fileName);
		const char writeString[]="helloJilu";
		GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_string(fileW,writeString));
		GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_meta_data(fileW,metaDataW));
		GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_int64(fileW,numberOne));
		GNUNET_assert(GNUNET_OK == GNUNET_BIO_write_close(fileW));
		fileR = GNUNET_BIO_read_open (fileName);
		GNUNET_BIO_read_meta_data(fileR,readWhatMeta,&metaDataR);
		readMaxLen = sizeof(readResultString);
        //GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_string(fileR,readWhatString,&readResultString,readMaxLen));
		//GNUNET_assert(GNUNET_OK == GNUNET_BIO_read_int64__(fileR,readWhatInt64,&numberOne));
        GNUNET_BIO_read_close(fileR,&msg);
		GNUNET_CONTAINER_meta_data_destroy(metaDataW);
		GNUNET_CONTAINER_meta_data_destroy(metaDataR);

		return 0;

}                               /* end of main */
